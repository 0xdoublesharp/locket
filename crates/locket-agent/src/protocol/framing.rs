//! Length-prefix framing for the v1 agent wire protocol.

use serde::Serialize;
use zeroize::Zeroizing;

use crate::PROTOCOL_VERSION;
use crate::envelope::{RequestEnvelope, ResponseEnvelope};
use crate::error::ProtocolError;

/// Serializes an envelope payload into a length-prefixed v1 frame.
///
/// The first four bytes are the little-endian payload length. The length
/// excludes the prefix itself and the payload is UTF-8 JSON.
///
/// # Errors
///
/// Returns [`ProtocolError::Json`] when serialization fails, and
/// [`ProtocolError::MessageTooLarge`] or [`ProtocolError::LengthPrefixOverflow`]
/// when the JSON payload is too large for the configured v1 frame.
pub fn encode_frame<T: Serialize>(
    envelope: &T,
    maximum_size: usize,
) -> Result<Vec<u8>, ProtocolError> {
    let mut payload = Zeroizing::new(Vec::with_capacity(128));
    serde_json::to_writer(&mut *payload, envelope)?;
    if payload.len() > maximum_size {
        return Err(ProtocolError::MessageTooLarge {
            length: payload.len(),
            maximum: maximum_size,
        });
    }
    let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::LengthPrefixOverflow)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decodes one v1 request frame from `bytes`.
///
/// # Errors
///
/// Returns [`ProtocolError::IncompleteFrame`] when fewer than one complete
/// frame is available, [`ProtocolError::MessageTooLarge`] when the frame
/// declares an oversized payload, [`ProtocolError::Json`] for malformed JSON,
/// and [`ProtocolError::UnsupportedVersion`] for non-v1 requests. Unknown
/// `kind` values decode successfully — the dispatcher answers them with a
/// `ProtocolError` envelope so the connection can keep serving subsequent
/// frames instead of stalling on a transport-level decode error.
pub fn decode_request_frame(
    bytes: &[u8],
    maximum_size: usize,
) -> Result<(RequestEnvelope, usize), ProtocolError> {
    let (payload, consumed) = frame_payload(bytes, maximum_size)?;
    let envelope: RequestEnvelope = serde_json::from_slice(payload)?;
    if envelope.v != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion { version: envelope.v });
    }
    Ok((envelope, consumed))
}

/// Decodes one v1 response frame from `bytes`.
///
/// # Errors
///
/// Returns [`ProtocolError::IncompleteFrame`] when fewer than one complete
/// frame is available, [`ProtocolError::MessageTooLarge`] when the frame
/// declares an oversized payload, [`ProtocolError::Json`] for malformed JSON,
/// and [`ProtocolError::UnsupportedVersion`] for non-v1 responses.
pub fn decode_response_frame(
    bytes: &[u8],
    maximum_size: usize,
) -> Result<(ResponseEnvelope, usize), ProtocolError> {
    let (payload, consumed) = frame_payload(bytes, maximum_size)?;
    let envelope: ResponseEnvelope = serde_json::from_slice(payload)?;
    let version = match &envelope {
        ResponseEnvelope::Success(success) => success.v,
        ResponseEnvelope::Error(error) => error.v,
    };
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion { version });
    }
    Ok((envelope, consumed))
}

fn frame_payload(bytes: &[u8], maximum_size: usize) -> Result<(&[u8], usize), ProtocolError> {
    if bytes.len() < 4 {
        return Err(ProtocolError::IncompleteFrame);
    }
    let length_bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let length = u32::from_le_bytes(length_bytes) as usize;
    if length > maximum_size {
        return Err(ProtocolError::MessageTooLarge { length, maximum: maximum_size });
    }
    let consumed = 4 + length;
    if bytes.len() < consumed {
        return Err(ProtocolError::IncompleteFrame);
    }
    Ok((&bytes[4..consumed], consumed))
}
