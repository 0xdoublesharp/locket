#![allow(unused_crate_dependencies)]
//! Measures the default passphrase fallback Argon2id cold-unlock budget.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;

use locket_crypto::{PassphraseKdfParams, derive_passphrase_fallback_key_v1};

const DEFAULT_BUDGET_MS: f64 = 300.0;
const DEFAULT_SAMPLES: usize = 50;
const DEFAULT_WARMUPS: usize = 5;
const FIXTURE_PASSPHRASE: &[u8] = b"locket passphrase performance fixture";
const FIXTURE_SALT: &[u8; 32] = b"locket-passphrase-perf-salt-v1!!";

fn main() {
    if let Err(error) = run() {
        let mut stderr = io::stderr().lock();
        let _ignored = writeln!(stderr, "{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse(env::args().skip(1))?;
    let params = PassphraseKdfParams::fallback_v1();
    for _ in 0..args.warmups {
        derive_passphrase_fallback_key_v1(FIXTURE_PASSPHRASE, FIXTURE_SALT, params)
            .map_err(|error| error.to_string())?;
    }

    let mut samples = Vec::with_capacity(args.samples);
    for _ in 0..args.samples {
        let start = Instant::now();
        derive_passphrase_fallback_key_v1(FIXTURE_PASSPHRASE, FIXTURE_SALT, params)
            .map_err(|error| error.to_string())?;
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    samples.sort_by(f64::total_cmp);
    let p95 = percentile_95(&samples)?;
    write_report(&args.report, args.samples, args.warmups, args.budget_ms, p95)?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "passphrase_unlock_p95_ms={p95:.3}").map_err(|error| error.to_string())?;
    writeln!(stdout, "passphrase_unlock_budget_ms={:.3}", args.budget_ms)
        .map_err(|error| error.to_string())?;
    writeln!(stdout, "report={}", args.report.display()).map_err(|error| error.to_string())?;

    if p95 > args.budget_ms {
        return Err(format!(
            "passphrase unlock p95 {p95:.3} ms exceeds budget {:.3} ms",
            args.budget_ms
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct Args {
    samples: usize,
    warmups: usize,
    budget_ms: f64,
    report: PathBuf,
}

impl Args {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut parsed = Self {
            samples: DEFAULT_SAMPLES,
            warmups: DEFAULT_WARMUPS,
            budget_ms: DEFAULT_BUDGET_MS,
            report: PathBuf::from("target/quality/perf-passphrase-unlock.md"),
        };
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--samples" => {
                    parsed.samples =
                        parse_usize("--samples", &args.next().ok_or("missing --samples value")?)?;
                }
                "--warmups" => {
                    parsed.warmups =
                        parse_usize("--warmups", &args.next().ok_or("missing --warmups value")?)?;
                }
                "--budget-ms" => {
                    parsed.budget_ms =
                        parse_f64("--budget-ms", &args.next().ok_or("missing --budget-ms value")?)?;
                }
                "--report" => {
                    parsed.report = PathBuf::from(args.next().ok_or("missing --report value")?);
                }
                "--help" => {
                    print_usage_and_exit();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        if parsed.samples == 0 {
            return Err("--samples must be greater than zero".to_owned());
        }
        if parsed.budget_ms <= 0.0 {
            return Err("--budget-ms must be greater than zero".to_owned());
        }
        Ok(parsed)
    }
}

fn parse_usize(flag: &str, value: &str) -> Result<usize, String> {
    value.parse::<usize>().map_err(|_| format!("{flag} must be a positive integer"))
}

fn parse_f64(flag: &str, value: &str) -> Result<f64, String> {
    value.parse::<f64>().map_err(|_| format!("{flag} must be a positive number"))
}

fn print_usage_and_exit() {
    let mut stdout = io::stdout().lock();
    let _ignored = writeln!(
        stdout,
        "usage: perf_passphrase_unlock [--samples N] [--warmups N] [--budget-ms MS] [--report PATH]"
    );
}

fn percentile_95(samples: &[f64]) -> Result<f64, String> {
    if samples.is_empty() {
        return Err("no samples recorded".to_owned());
    }
    let index = (samples.len() * 95).div_ceil(100).saturating_sub(1).min(samples.len() - 1);
    Ok(samples[index])
}

fn write_report(
    path: &PathBuf,
    samples: usize,
    warmups: usize,
    budget_ms: f64,
    p95_ms: f64,
) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let result = if p95_ms <= budget_ms { "passed" } else { "failed" };
    let report = format!(
        "# Passphrase Unlock Performance\n\n- warmup_iterations: {warmups}\n- samples: {samples}\n- p95_ms: {p95_ms:.3}\n- budget_ms: {budget_ms:.3}\n- result: {result}\n"
    );
    fs::write(path, report).map_err(|error| error.to_string())?;
    set_user_only_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_user_only_permissions(path: &PathBuf) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path).map_err(|error| error.to_string())?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions).map_err(|error| error.to_string())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // Retain the shared fallible interface for this public fixture.
const fn set_user_only_permissions(_path: &PathBuf) -> Result<(), String> {
    Ok(())
}
