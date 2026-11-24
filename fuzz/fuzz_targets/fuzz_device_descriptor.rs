#![no_main]

use data_encoding::BASE64URL_NOPAD;
use libfuzzer_sys::fuzz_target;
use locket_core::DeviceId;
use serde::Deserialize;

fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let descriptor = if let Some(encoded) = input.strip_prefix("lkdev2_") {
        let Ok(bytes) = BASE64URL_NOPAD.decode(encoded.as_bytes()) else {
            return;
        };
        serde_json::from_slice::<DeviceDescriptorV1>(&bytes)
    } else {
        serde_json::from_str::<DeviceDescriptorV1>(input)
    };
    let Ok(descriptor) = descriptor else {
        return;
    };
    if descriptor.v == 2 {
        if DeviceId::new(descriptor.device_id).is_err()
            || decode_key_len(&descriptor.signing_public_key_ed25519) != Some(32)
            || decode_key_len(&descriptor.sealing_public_key_x25519) != Some(32)
        {
            return;
        }
        if descriptor.label.chars().any(char::is_control)
            || descriptor.fingerprint_sha256.contains('\0')
            || descriptor.safety_words.iter().any(|word| word.chars().any(char::is_control))
        {
            return;
        }
        assert!(!descriptor.label.chars().any(char::is_control));
        assert!(!descriptor.fingerprint_sha256.contains('\0'));
        for word in descriptor.safety_words {
            assert!(!word.chars().any(char::is_control));
        }
    }
});

fn decode_key_len(value: &str) -> Option<usize> {
    BASE64URL_NOPAD.decode(value.as_bytes()).ok().map(|bytes| bytes.len())
}

#[derive(Debug, Deserialize)]
struct DeviceDescriptorV1 {
    v: u16,
    device_id: String,
    label: String,
    signing_public_key_ed25519: String,
    sealing_public_key_x25519: String,
    fingerprint_sha256: String,
    safety_words: Vec<String>,
}
