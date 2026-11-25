use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Output};

use super::*;

#[test]
fn macos_process_start_requires_success_and_exact_ps_format() -> Result<(), PlatformError> {
    let token = "Wed Dec  2 23:59:60 2026";
    let output = |code, stdout: &[u8]| Output {
        status: ExitStatus::from_raw(code),
        stdout: stdout.to_vec(),
        stderr: Vec::new(),
    };
    let padded = format!("  {token}\n");
    assert_eq!(parse_macos_ps_output(output(0, padded.as_bytes()))?, token);
    assert!(matches!(
        parse_macos_ps_output(output(1 << 8, padded.as_bytes())),
        Err(PlatformError::ProcessStartTimeUnavailable)
    ));

    for invalid in [
        b"\xff".as_slice(),
        b"  \n",
        b"Wed Dec",
        b"Wed Dec 2 23:59 2026",
        b"Wed Dec 2 24:00:00 2026",
        b"Wed Dec 2 23:59:00 1969",
        b"Wed Dec 32 23:59:00 2026",
        b"Wed Invalid 2 23:59:00 2026",
    ] {
        assert!(matches!(
            parse_macos_ps_output(output(0, invalid)),
            Err(PlatformError::ProcessStartTimeUnavailable)
        ));
    }
    Ok(())
}
