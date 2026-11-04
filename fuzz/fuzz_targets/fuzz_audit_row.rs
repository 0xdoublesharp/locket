#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_core::{
    AUDIT_CHECKPOINT_MAX_BYTES, AuditCheckpoint, AuditHmacInput, Timestamp,
    audit_checkpoint_v1_bytes, audit_hmac_v1_bytes, canonical_json, canonical_json_string,
};
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    if data.len() <= AUDIT_CHECKPOINT_MAX_BYTES
        && let Ok(checkpoint) = serde_json::from_slice::<AuditCheckpoint>(data)
    {
        let encoded = serde_json::to_vec(&checkpoint).expect("checkpoint should serialize");
        let decoded: AuditCheckpoint =
            serde_json::from_slice(&encoded).expect("checkpoint should reparse");
        assert_eq!(checkpoint, decoded);
        let _ = audit_checkpoint_v1_bytes(&checkpoint);
    }
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let metadata = serde_json::from_str::<Value>(input).ok();
    if let Some(value) = metadata.as_ref() {
        let canonical = canonical_json(value);
        let _ = serde_json::from_str::<Value>(&canonical).expect("canonical JSON should parse");
    }

    let fields = split_fields(input);
    let audit = AuditHmacInput {
        schema_version: 1,
        sequence: u64::try_from(data.len()).unwrap_or(u64::MAX),
        timestamp: Timestamp::from_unix_nanos(i64::try_from(data.len()).unwrap_or(i64::MAX)),
        project_id: fields.first().copied(),
        profile_id: fields.get(1).copied(),
        action: fields.get(2).copied().unwrap_or("FUZZ"),
        status: fields.get(3).copied().unwrap_or("SUCCESS"),
        metadata_json: metadata.as_ref(),
        previous_hmac: Some(&[0_u8; 32]),
    };
    let _ = audit_hmac_v1_bytes(&audit);
    let _ = canonical_json_string(metadata.as_ref());
});

fn split_fields(input: &str) -> Vec<&str> {
    input.split('\n').take(4).map(|field| field.trim()).collect()
}
