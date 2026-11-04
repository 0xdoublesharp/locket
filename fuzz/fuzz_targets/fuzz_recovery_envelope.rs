#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_platform::RecoveryEnvelope;

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 {
        return;
    }
    // Exercise both persisted formats and drive mutations past the modern magic.
    let _ = locket_platform::decode_recovery_state(data);
    let mut modern = b"LOCKET-RECOVERY-STATE-V1\0".to_vec();
    modern.extend_from_slice(data);
    let _ = locket_platform::decode_recovery_state(&modern);
    let Ok(envelope) = RecoveryEnvelope::deserialize(data) else {
        return;
    };
    let encoded = envelope.serialize().expect("deserialized envelope should serialize");
    let decoded =
        RecoveryEnvelope::deserialize(&encoded).expect("serialized envelope should decode");
    assert_eq!(decoded.kdf_profile_id, envelope.kdf_profile_id);
    assert_eq!(decoded.created_at_unix_nanos, envelope.created_at_unix_nanos);
    assert_eq!(decoded.entries.len(), envelope.entries.len());
    for (left, right) in decoded.entries.iter().zip(envelope.entries.iter()) {
        assert_eq!(left.entry_kind, right.entry_kind);
        assert_eq!(left.entry_id, right.entry_id);
        assert_eq!(left.nonce, right.nonce);
        assert_eq!(left.ciphertext, right.ciphertext);
    }
});
