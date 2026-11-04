//! Recovery envelope cold-unlock performance gate.

#![allow(unused_crate_dependencies)]

use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use locket_crypto::{
    KeyBytes, RECOVERY_CODE_BYTES, RECOVERY_SALT_LEN, RecoveryKdfParams, derive_recovery_key_v1,
    open_recovery_entry_v1, seal_recovery_entry_v1,
};

const DEFAULT_SAMPLES: usize = 50;
const DEFAULT_WARMUPS: usize = 5;
const DEFAULT_BUDGET_MS: f64 = 2_000.0;
const DEFAULT_REPORT: &str = "target/quality/perf-recovery-envelope-unlock.md";
const KDF_PROFILE_ID: &str = "lk_kdf_perf_recovery_v1";
const ENTRY_KIND: &str = "master_key";
const ENTRY_ID: &str = "lk_key_perf_recovery_v1";
const PAYLOAD: KeyBytes = [0x42; 32];

#[derive(Debug)]
struct Config {
    samples: usize,
    warmups: usize,
    budget_ms: f64,
    report_path: PathBuf,
    build_profile: String,
    cargo_jobs: String,
    offline: String,
}

#[derive(Debug)]
struct Fixture {
    code_bytes: [u8; RECOVERY_CODE_BYTES],
    salt: [u8; RECOVERY_SALT_LEN],
    nonce: [u8; locket_crypto::NONCE_LEN],
    ciphertext: Vec<u8>,
}

fn main() {
    if let Err(error) = run() {
        let _ = writeln!(io::stderr(), "perf-recovery-envelope-unlock: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let config = parse_config(env::args().skip(1))?;
    let fixture = build_fixture()?;

    for _ in 0..config.warmups {
        sample_once(&fixture)?;
    }

    let mut samples = Vec::with_capacity(config.samples);
    for _ in 0..config.samples {
        let started = Instant::now();
        sample_once(&fixture)?;
        samples.push(started.elapsed().as_secs_f64() * 1_000.0);
    }

    let p95_ms = percentile_95(samples.clone());
    write_report(&config, &samples, p95_ms)?;

    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "perf-recovery-envelope-unlock: p95_ms={p95_ms:.3} budget_ms={:.3} samples={} report={}",
        config.budget_ms,
        samples.len(),
        config.report_path.display()
    )?;

    if p95_ms > config.budget_ms {
        return Err(format!("p95 {p95_ms:.3} ms exceeds budget {:.3} ms", config.budget_ms).into());
    }

    Ok(())
}

fn parse_config(args: impl Iterator<Item = String>) -> Result<Config, Box<dyn Error>> {
    let mut config = Config {
        samples: DEFAULT_SAMPLES,
        warmups: DEFAULT_WARMUPS,
        budget_ms: DEFAULT_BUDGET_MS,
        report_path: PathBuf::from(DEFAULT_REPORT),
        build_profile: "release".to_owned(),
        cargo_jobs: "12".to_owned(),
        offline: "1".to_owned(),
    };
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--samples" => {
                config.samples = parse_next(&mut args, "--samples")?;
            }
            "--warmups" => {
                config.warmups = parse_next(&mut args, "--warmups")?;
            }
            "--budget-ms" => {
                config.budget_ms = parse_next(&mut args, "--budget-ms")?;
            }
            "--report" => {
                config.report_path = PathBuf::from(next_value(&mut args, "--report")?);
            }
            "--build-profile" => {
                config.build_profile = next_value(&mut args, "--build-profile")?;
            }
            "--cargo-jobs" => {
                config.cargo_jobs = next_value(&mut args, "--cargo-jobs")?;
            }
            "--offline" => {
                config.offline = next_value(&mut args, "--offline")?;
            }
            "--help" | "-h" => {
                write_help(io::stdout().lock())?;
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    if config.samples == 0 {
        return Err("--samples must be greater than zero".into());
    }
    if config.budget_ms <= 0.0 {
        return Err("--budget-ms must be greater than zero".into());
    }

    Ok(config)
}

fn next_value(
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    args.next().ok_or_else(|| format!("missing value for {flag}").into())
}

fn parse_next<T>(
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    flag: &str,
) -> Result<T, Box<dyn Error>>
where
    T: std::str::FromStr,
    T::Err: Error + 'static,
{
    Ok(next_value(args, flag)?.parse()?)
}

fn write_help(mut output: impl Write) -> Result<(), Box<dyn Error>> {
    writeln!(
        output,
        "usage: perf_recovery_envelope_unlock [--samples N] [--warmups N] [--budget-ms MS] [--report PATH]"
    )?;
    Ok(())
}

fn build_fixture() -> Result<Fixture, Box<dyn Error>> {
    let code_bytes = [0x31; RECOVERY_CODE_BYTES];
    let salt = [0x52; RECOVERY_SALT_LEN];
    let root = derive_recovery_key_v1(&code_bytes, &salt, RecoveryKdfParams::recovery_v1())?;
    let (nonce, ciphertext) =
        seal_recovery_entry_v1(&root, KDF_PROFILE_ID, ENTRY_KIND, ENTRY_ID, &PAYLOAD)?;

    Ok(Fixture { code_bytes, salt, nonce, ciphertext })
}

fn sample_once(fixture: &Fixture) -> Result<(), Box<dyn Error>> {
    let root = derive_recovery_key_v1(
        &fixture.code_bytes,
        &fixture.salt,
        RecoveryKdfParams::recovery_v1(),
    )?;
    let plaintext = open_recovery_entry_v1(
        &root,
        KDF_PROFILE_ID,
        ENTRY_KIND,
        ENTRY_ID,
        &fixture.nonce,
        &fixture.ciphertext,
    )?;
    if plaintext.as_slice() != PAYLOAD {
        return Err("recovery envelope payload mismatch".into());
    }
    Ok(())
}

fn percentile_95(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(f64::total_cmp);
    let one_based_index = samples.len().saturating_mul(95).div_ceil(100).max(1);
    samples[one_based_index - 1]
}

fn write_report(config: &Config, samples: &[f64], p95_ms: f64) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = config.report_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut report = File::create(&config.report_path)?;
    #[cfg(unix)]
    set_user_only_permissions(&report)?;

    writeln!(report, "# Recovery Envelope Unlock Performance")?;
    writeln!(report)?;
    writeln!(report, "- benchmark: perf-recovery-envelope-unlock")?;
    writeln!(report, "- reference_runner: local-smoke")?;
    writeln!(
        report,
        "- cpu_model: {}",
        first_line(&command_output("sysctl", ["-n", "machdep.cpu.brand_string"]))
    )?;
    writeln!(
        report,
        "- core_count: {}",
        first_line(&command_output("getconf", ["_NPROCESSORS_ONLN"]))
    )?;
    writeln!(
        report,
        "- memory_bytes: {}",
        first_line(&command_output("sysctl", ["-n", "hw.memsize"]))
    )?;
    writeln!(report, "- os: {}", first_line(&command_output("uname", ["-srmo"])))?;
    writeln!(report, "- filesystem_type: {}", filesystem_type())?;
    writeln!(report, "- power_mode: {}", first_line(&command_output("pmset", ["-g", "batt"])))?;
    writeln!(
        report,
        "- commit_sha: {}",
        first_line(&command_output("git", ["rev-parse", "HEAD"]))
    )?;
    writeln!(report, "- build_profile: {}", config.build_profile)?;
    writeln!(report, "- rust_version: {}", first_line(&command_output("rustc", ["-V"])))?;
    writeln!(report, "- agent_running_unlocked: no")?;
    writeln!(report, "- cargo_jobs: {}", config.cargo_jobs)?;
    writeln!(report, "- offline: {}", config.offline)?;
    writeln!(report, "- warmup_iterations: {}", config.warmups)?;
    writeln!(report, "- samples: {}", samples.len())?;
    writeln!(report, "- budget_ms: {:.3}", config.budget_ms)?;
    writeln!(report, "- p95_ms: {p95_ms:.3}")?;
    writeln!(report, "- max_ms: {:.3}", samples.iter().copied().fold(0.0, f64::max))?;
    writeln!(
        report,
        "- p95_index_formula: ceil(0.95 * n) - 1 zero-based / report index {} one-based",
        samples.len().saturating_mul(95).div_ceil(100).max(1)
    )?;
    writeln!(report)?;
    writeln!(
        report,
        "Each measured sample derives the recovery unwrap root with the default v1 Argon2id recovery parameters and opens one v1 recovery envelope entry."
    )?;

    Ok(())
}

#[cfg(unix)]
fn set_user_only_permissions(file: &File) -> io::Result<()> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(0o600);
    file.set_permissions(permissions)
}

fn command_output<const N: usize>(command: &str, args: [&str; N]) -> String {
    Command::new(command)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map_or_else(
            || "unknown".to_owned(),
            |output| String::from_utf8_lossy(&output.stdout).into_owned(),
        )
}

fn first_line(value: &str) -> String {
    value.lines().next().unwrap_or("unknown").trim().to_owned()
}

fn filesystem_type() -> String {
    if let Ok(output) = Command::new("stat").args(["-f", "%T", "."]).output()
        && output.status.success()
    {
        return first_line(&String::from_utf8_lossy(&output.stdout));
    }
    if let Ok(output) = Command::new("df").args(["-T", "."]).output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(kind) = stdout.lines().nth(1).and_then(|line| line.split_whitespace().nth(1)) {
            return kind.to_owned();
        }
    }
    "unknown".to_owned()
}
