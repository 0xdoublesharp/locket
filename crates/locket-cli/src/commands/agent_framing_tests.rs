//! Real-socket regression fixtures for CLI response readers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::redundant_pub_crate)]

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::sync::mpsc;
use std::time::Duration;

use locket_agent::{DEFAULT_MAX_MESSAGE_SIZE, PROTOCOL_VERSION, SuccessEnvelope, encode_frame};
use serde_json::{Value, json};

pub(crate) const CANARY: &str = "framing-plaintext-canary-do-not-echo";

pub(crate) fn invalid_frame(kind: &str) -> Vec<u8> {
    match kind {
        "oversized" => u32::try_from(DEFAULT_MAX_MESSAGE_SIZE + 1).unwrap().to_le_bytes().to_vec(),
        "malformed" => {
            // A type error can include the offending plaintext string in its diagnostic.
            let body = format!(r#"{{"v":"{CANARY}","id":"test","type":"success","payload":{{}}}}"#);
            let mut frame = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
            frame.extend_from_slice(body.as_bytes());
            frame
        }
        "version" => {
            let mut response = SuccessEnvelope::new("test", json!({"private": CANARY}));
            response.v = PROTOCOL_VERSION + 1;
            encode_frame(&response, DEFAULT_MAX_MESSAGE_SIZE).unwrap()
        }
        _ => panic!("unknown fixture"),
    }
}

pub(crate) fn fragmented_success() -> Vec<Vec<u8>> {
    let frame =
        encode_frame(&SuccessEnvelope::new("test", json!({"ok": true})), DEFAULT_MAX_MESSAGE_SIZE)
            .unwrap();
    vec![frame[..2].to_vec(), frame[2..9].to_vec(), frame[9..].to_vec()]
}

/// Returns only if the real reader finishes while its peer is still open.
pub(crate) fn with_open_peer<T: Send + 'static>(
    chunks: Vec<Vec<u8>>,
    reader: impl FnOnce(&crate::RuntimeContext) -> T + Send + 'static,
) -> T {
    let directory = tempfile::tempdir().unwrap();
    let context = crate::tests::test_context(&directory);
    let listener = UnixListener::bind(crate::agent_socket_path(&context)).unwrap();
    let (sent_tx, sent_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix).unwrap();
        let length = u32::from_le_bytes(prefix) as usize;
        assert!(length <= DEFAULT_MAX_MESSAGE_SIZE);
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).unwrap();
        for chunk in chunks {
            stream.write_all(&chunk).unwrap();
            stream.flush().unwrap();
            std::thread::sleep(Duration::from_millis(10));
        }
        sent_tx.send(()).unwrap();
        // The owner releases the socket even on a regression, so no reader thread leaks.
        let _ = release_rx.recv_timeout(Duration::from_secs(3));
    });
    let (result_tx, result_rx) = mpsc::channel();
    let client = std::thread::spawn(move || {
        result_tx.send(reader(&context)).unwrap();
    });
    sent_rx.recv_timeout(Duration::from_secs(3)).expect("peer sent the complete fixture");
    let result = result_rx.recv_timeout(Duration::from_millis(750));
    release_tx.send(()).unwrap();
    server.join().unwrap();
    client.join().unwrap();
    result.expect("reader must finish on a complete frame while the socket remains open")
}

fn rejects_frame(kind: &str) {
    let result = with_open_peer(vec![invalid_frame(kind)], |context| {
        super::request_status_snapshot(&crate::agent_socket_path(context))
    });
    let error = result.expect_err("permanent frame error");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(!error.to_string().contains(CANARY));
}

#[test]
fn agent_reader_rejects_oversized_frame_while_peer_stays_open() {
    rejects_frame("oversized");
}

#[test]
fn agent_reader_rejects_malformed_frame_while_peer_stays_open() {
    rejects_frame("malformed");
}

#[test]
fn agent_reader_rejects_version_frame_while_peer_stays_open() {
    rejects_frame("version");
}

#[test]
fn agent_reader_accepts_fragmented_frame_while_peer_stays_open() {
    let result = with_open_peer(fragmented_success(), |context| {
        super::request_status_snapshot(&crate::agent_socket_path(context))
    });
    assert_eq!(result.unwrap(), json!({"ok": true}));
}

#[test]
fn agent_reader_rejects_incomplete_frames_at_eof() -> Result<(), Box<dyn std::error::Error>> {
    let frame = encode_frame(&SuccessEnvelope::new("test", Value::Null), DEFAULT_MAX_MESSAGE_SIZE)?;
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let mut scratch = zeroize::Zeroizing::new([0_u8; 16 * 1024]);
    for end in 0..frame.len() {
        let error = runtime
            .block_on(super::read_agent_response(&mut &frame[..end], &mut scratch[..]))
            .expect_err("incomplete frame must fail at EOF");
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }
    Ok(())
}
