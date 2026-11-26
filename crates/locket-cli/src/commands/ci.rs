//! Vault-free device enrollment and signed team snapshot reads for CI.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{ArgGroup, Args, Subcommand};
use data_encoding::BASE64URL_NOPAD;
use locket_agent::team_sync::{
    CredentialMode, TransportConfig, WebDavAuthKind, list_and_read_join_packages_for_recipient,
};
use locket_core::team_package::{DeviceIdentity, SignedStatement, VerifiedStatement};
use locket_core::{
    DeviceId, ProfileName, ProjectId, SecretName, safety_words_from_fingerprint_hex,
};
use locket_crypto::{
    EncryptedSecretValue, KeyBytes, KeyWrapAad, KeyWrapPurpose, SecretBlobAad,
    decrypt_secret_value_v1, key_wrap_aad_v1, random_bytes, secret_blob_aad_v1,
};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::team::{device::DeviceDescriptorV1, remote::WebDavAuthArg};
use crate::{
    CliError, access_denied_error, bundle_verification_error, metadata_invalid_error,
    now_unix_nanos, resolve_project, secret_not_found_error, set_user_only_file_permissions,
};

const DEFAULT_IDENTITY_ENV: &str = "LOCKET_CI_IDENTITY";
const IDENTITY_PREFIX: &str = "lkci1_";
const DESCRIPTOR_PREFIX: &str = "lkdev2_";
const TRANSPORT_CREDENTIAL_ENV: &[&str] = &[
    "LOCKET_S3_ACCESS_KEY_ID",
    "LOCKET_S3_SECRET_ACCESS_KEY",
    "LOCKET_S3_SESSION_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "LOCKET_WEBDAV_USERNAME",
    "LOCKET_WEBDAV_SECRET",
    "LOCKET_WEBDAV_TOKEN",
];

#[derive(Debug, Subcommand)]
pub enum CiCommand {
    /// Generate a CI identity and its public enrollment descriptor.
    InitDevice(InitDeviceArgs),
    /// Verify and decrypt a published profile in memory; print metadata only.
    Verify(CiReadArgs),
    /// Run a command with secrets from a verified team profile.
    Exec(CiExecArgs),
}

#[derive(Args)]
#[command(group(
    ArgGroup::new("private_output")
        .required(true)
        .args(["output_key_file", "print_private_identity"])
))]
pub struct InitDeviceArgs {
    /// Label in the public device descriptor.
    #[arg(long, default_value = "ci-runner")]
    label: String,
    /// Save the private identity to a new file instead of printing it.
    #[arg(long, value_name = "PATH")]
    output_key_file: Option<PathBuf>,
    /// Explicitly print the private CI identity token to stdout.
    #[arg(long)]
    print_private_identity: bool,
}

#[derive(Args)]
#[command(
    group(ArgGroup::new("delivery").required(true).args(["folder", "s3_bucket", "webdav_url"])),
    group(ArgGroup::new("s3_options").multiple(true)
        .args(["s3_region", "s3_prefix", "s3_endpoint", "s3_path_style"])
        .conflicts_with_all(["folder", "webdav_url"]))
)]
pub struct CiReadArgs {
    /// Independently obtained owner fingerprint.
    #[arg(long, value_name = "64-HEX", value_parser = owner_pin)]
    owner: String,
    /// Project ID, defaulting to the project in locket.toml.
    #[arg(long)]
    project: Option<ProjectId>,
    /// Published profile name.
    #[arg(long)]
    profile: ProfileName,
    /// Read the private machine identity from this environment variable.
    #[arg(long, default_value = DEFAULT_IDENTITY_ENV, value_parser = identity_env_name)]
    identity_env: String,
    /// Read packages from an existing shared folder.
    #[arg(long)]
    folder: Option<PathBuf>,
    /// Read packages from this S3-compatible bucket.
    #[arg(long)]
    s3_bucket: Option<String>,
    /// S3 signing region.
    #[arg(long, requires = "s3_bucket", default_value = "us-east-1")]
    s3_region: String,
    /// Object prefix containing the team's packages.
    #[arg(long, requires = "s3_bucket", default_value = "")]
    s3_prefix: String,
    /// Custom S3 endpoint, which implies path-style addressing.
    #[arg(long, requires = "s3_bucket")]
    s3_endpoint: Option<String>,
    /// Use path-style bucket addressing.
    #[arg(long, requires = "s3_bucket")]
    s3_path_style: bool,
    /// Read packages from this `WebDAV` collection.
    #[arg(long)]
    webdav_url: Option<String>,
    /// Authentication method for the `WebDAV` collection.
    #[arg(long, requires = "webdav_url", conflicts_with_all = ["folder", "s3_bucket"], value_enum, default_value = "none")]
    webdav_auth: WebDavAuthArg,
    /// Allow a profile the owner marked dangerous.
    #[arg(long)]
    allow_dangerous: bool,
    /// Reject verified snapshots older than this minimum team epoch.
    #[arg(long, value_name = "EPOCH")]
    min_epoch: Option<u64>,
    /// Reject verified snapshots issued more than this many seconds ago.
    #[arg(long, value_name = "SECONDS")]
    max_age_seconds: Option<u64>,
}

#[derive(Args)]
#[command(group(ArgGroup::new("secret_selection").required(true).args(["secrets", "all_profile_secrets"])))]
pub struct CiExecArgs {
    #[command(flatten)]
    read: CiReadArgs,
    /// Inject this team-managed secret. May be repeated.
    #[arg(long = "secret", value_name = "NAME")]
    secrets: Vec<SecretName>,
    /// Inject every active team-managed secret from the profile.
    #[arg(long)]
    all_profile_secrets: bool,
    /// Command and arguments, following --.
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<OsString>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityToken<'a> {
    v: u8,
    id: &'a str,
    label: Cow<'a, str>,
    signing_seed_b64: &'a str,
    sealing_key_b64: &'a str,
}

macro_rules! redacted_debug {
    ($($type:ty),+ $(,)?) => {
        $(impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_struct(stringify!($type)).finish_non_exhaustive()
            }
        })+
    };
}

redacted_debug!(InitDeviceArgs, CiReadArgs, CiExecArgs, IdentityToken<'_>);

fn owner_pin(value: &str) -> Result<String, &'static str> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(value.to_ascii_lowercase())
    } else {
        Err("owner fingerprint must be exactly 64 hexadecimal characters")
    }
}

fn identity_env_name(value: &str) -> Result<String, &'static str> {
    if value.is_empty() || value.contains(['=', '\0']) {
        Err("invalid CI identity environment variable name")
    } else {
        Ok(value.to_owned())
    }
}

pub fn run(cwd: &Path, output: &mut impl Write, command: CiCommand) -> Result<u8, CliError> {
    match command {
        CiCommand::InitDevice(args) => init_device(output, &args)?,
        CiCommand::Verify(args) => {
            let profile = read_profile(cwd, &args)?;
            let result = serde_json::json!({
                "verified": true,
                "project_id": profile.project_id,
                "profile": args.profile,
                "epoch": profile.epoch,
                "owner_fingerprint": args.owner,
                "device_id": profile.device_id,
                "secret_names": profile.values.keys().map(SecretName::as_str).collect::<Vec<_>>(),
            });
            drop(profile);
            serde_json::to_writer(&mut *output, &result)?;
            writeln!(output)?;
        }
        CiCommand::Exec(args) => return exec(cwd, &args),
    }
    Ok(0)
}

fn device_identity(id: String, signing: &KeyBytes, sealing: &KeyBytes) -> DeviceIdentity {
    let signing_public = ed25519_dalek::SigningKey::from_bytes(signing).verifying_key().to_bytes();
    let sealing_public = PublicKey::from(&StaticSecret::from(*sealing)).to_bytes();
    DeviceIdentity::new(id, signing_public, sealing_public)
}

fn init_device(output: &mut impl Write, args: &InitDeviceArgs) -> Result<(), CliError> {
    if args.label.trim().is_empty()
        || args.label.len() > 80
        || args.label.chars().any(char::is_control)
    {
        return Err(metadata_invalid_error("invalid CI device label"));
    }
    let id = DeviceId::generate()
        .map_err(|_| metadata_invalid_error("CI device ID generation failed"))?;
    let signing = Zeroizing::new(random_bytes::<32>()?);
    let sealing = Zeroizing::new(random_bytes::<32>()?);
    let device = device_identity(id.into_string(), &signing, &sealing);
    let descriptor = DeviceDescriptorV1 {
        v: 2,
        device_id: device.id.clone(),
        label: args.label.clone(),
        signing_public_key_ed25519: BASE64URL_NOPAD.encode(&device.signing_key),
        sealing_public_key_x25519: BASE64URL_NOPAD.encode(&device.sealing_key),
        safety_words: safety_words_from_fingerprint_hex(&device.fingerprint)
            .into_iter()
            .map(str::to_owned)
            .collect(),
        fingerprint_sha256: device.fingerprint.clone(),
    };
    let descriptor =
        format!("{DESCRIPTOR_PREFIX}{}", BASE64URL_NOPAD.encode(&serde_json::to_vec(&descriptor)?));
    let token = encode_identity(&device.id, &args.label, &signing, &sealing)?;
    drop((signing, sealing));

    let owner_add_command = format!(
        "locket team add ci-bot --device {descriptor} --confirm-device-fingerprint {} --profile PROFILE --role read-only",
        device.fingerprint,
    );
    let metadata = serde_json::json!({
        "device_id": device.id,
        "label": args.label,
        "fingerprint": device.fingerprint,
        "descriptor": descriptor,
        "owner_add_command": owner_add_command,
    });
    if let Some(path) = &args.output_key_file {
        write_key_file(path, &token)?;
        serde_json::to_writer(&mut *output, &metadata)?;
    } else if args.print_private_identity {
        // Stream the private field directly from its zeroizing buffer.
        #[derive(Serialize)]
        struct Output<'a> {
            #[serde(flatten)]
            metadata: serde_json::Value,
            ci_identity: &'a str,
            warning: &'static str,
        }
        serde_json::to_writer(
            &mut *output,
            &Output {
                metadata,
                ci_identity: &token,
                warning: "Store ci_identity in CI Secrets as LOCKET_CI_IDENTITY. Never commit it.",
            },
        )?;
    } else {
        return Err(metadata_invalid_error(
            "pass --output-key-file PATH or explicitly pass --print-private-identity",
        ));
    }
    writeln!(output)?;
    Ok(())
}

fn encode_identity(
    id: &str,
    label: &str,
    signing: &KeyBytes,
    sealing: &KeyBytes,
) -> Result<Zeroizing<String>, CliError> {
    let signing_seed_b64 = Zeroizing::new(BASE64URL_NOPAD.encode(signing));
    let sealing_key_b64 = Zeroizing::new(BASE64URL_NOPAD.encode(sealing));
    let payload = IdentityToken {
        v: 1,
        id,
        label: Cow::Borrowed(label),
        signing_seed_b64: &signing_seed_b64,
        sealing_key_b64: &sealing_key_b64,
    };
    let mut json = Zeroizing::new(Vec::with_capacity(512));
    serde_json::to_writer(&mut *json, &payload)?;
    let mut token = Zeroizing::new(String::with_capacity(
        IDENTITY_PREFIX.len() + BASE64URL_NOPAD.encode_len(json.len()),
    ));
    token.push_str(IDENTITY_PREFIX);
    BASE64URL_NOPAD.encode_append(&json, &mut token);
    Ok(token)
}

fn write_key_file(path: &Path, token: &str) -> Result<(), CliError> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    set_user_only_file_permissions(temporary.path())?;
    temporary.write_all(token.as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
}

fn read_identity(env: &str) -> Result<(DeviceIdentity, Zeroizing<KeyBytes>), CliError> {
    let invalid = || metadata_invalid_error("invalid CI identity token");
    let token = Zeroizing::new(std::env::var(env).map_err(|_| {
        metadata_invalid_error("CI identity environment variable is missing or invalid")
    })?);
    let encoded = token.strip_prefix(IDENTITY_PREFIX).ok_or_else(invalid)?;
    let size = BASE64URL_NOPAD.decode_len(encoded.len()).map_err(|_| invalid())?;
    if size > 1024 {
        return Err(invalid());
    }
    let mut json = Zeroizing::new(vec![0; size]);
    BASE64URL_NOPAD.decode_mut(encoded.as_bytes(), &mut json).map_err(|_| invalid())?;
    let payload: IdentityToken<'_> = serde_json::from_slice(&json).map_err(|_| invalid())?;
    if payload.v != 1 {
        return Err(invalid());
    }
    let id = DeviceId::new(payload.id).map_err(|_| invalid())?;
    let decode_key = |encoded: &str| {
        let mut key = Zeroizing::new([0; 32]);
        if BASE64URL_NOPAD.decode_len(encoded.len()).ok() != Some(key.len()) {
            return Err(invalid());
        }
        BASE64URL_NOPAD.decode_mut(encoded.as_bytes(), &mut *key).map_err(|_| invalid())?;
        Ok(key)
    };
    let signing = decode_key(payload.signing_seed_b64)?;
    let sealing = decode_key(payload.sealing_key_b64)?;
    Ok((device_identity(id.into_string(), &signing, &sealing), sealing))
}

impl CiReadArgs {
    fn transport(&self, cwd: &Path) -> Result<TransportConfig, CliError> {
        if let Some(path) = &self.folder {
            return Ok(TransportConfig::Folder {
                path: cwd
                    .join(path)
                    .into_os_string()
                    .into_string()
                    .map_err(|_| metadata_invalid_error("shared folder path must be UTF-8"))?,
            });
        }
        if let Some(bucket) = &self.s3_bucket {
            return Ok(TransportConfig::S3 {
                bucket: bucket.clone(),
                region: self.s3_region.clone(),
                prefix: self.s3_prefix.clone(),
                endpoint: self.s3_endpoint.clone(),
                path_style: self.s3_path_style || self.s3_endpoint.is_some(),
                credential_mode: CredentialMode::Env,
            });
        }
        let url = self
            .webdav_url
            .clone()
            .ok_or_else(|| metadata_invalid_error("CI delivery backend is required"))?;
        let auth_kind = self.webdav_auth.into();
        let credential_mode = if auth_kind == WebDavAuthKind::None {
            CredentialMode::None
        } else {
            CredentialMode::Env
        };
        Ok(TransportConfig::WebDav { url, auth_kind, username: None, credential_mode })
    }
}

fn latest_snapshot(
    config: &TransportConfig,
    sealing: &KeyBytes,
    device: &DeviceIdentity,
    project: &ProjectId,
    owner: &str,
) -> Result<VerifiedStatement, CliError> {
    let delivery_error =
        |error: locket_agent::team_sync::SyncError| metadata_invalid_error(error.to_string());
    let candidates = list_and_read_join_packages_for_recipient(config, None, &device.fingerprint)
        .map_err(delivery_error)?;
    let now = now_unix_nanos()? / 1_000_000_000;
    let mut latest: Option<VerifiedStatement> = None;
    let mut fork = false;
    for candidate in candidates {
        let (_, bytes) = candidate.map_err(delivery_error)?;
        let Ok(signed) = SignedStatement::open(&bytes, sealing) else { continue };
        let Ok(verified) = signed.verify_update(owner, project.as_str(), device, now) else {
            continue;
        };
        match latest.as_ref() {
            Some(head) if head.statement.epoch > verified.statement.epoch => {}
            Some(head) if head.statement.epoch == verified.statement.epoch => {
                fork |= head.digest != verified.digest;
            }
            _ => {
                latest = Some(verified);
                fork = false;
            }
        }
    }
    if fork {
        return Err(bundle_verification_error("conflicting CI packages at the highest epoch"));
    }
    let latest = latest.ok_or_else(|| {
        bundle_verification_error("no CI package verified against the owner pin and project")
    })?;
    // The stateful update verifier deliberately permits expired updates.
    // A standalone reader has no saved checkpoint and requires a live head.
    let verified_now = now_unix_nanos()? / 1_000_000_000;
    if verified_now >= latest.statement.expires_at {
        return Err(bundle_verification_error("latest CI package has expired"));
    }
    Ok(latest)
}

struct VerifiedProfile {
    project_id: ProjectId,
    device_id: String,
    epoch: u64,
    values: BTreeMap<SecretName, Zeroizing<String>>,
}

fn read_profile(cwd: &Path, args: &CiReadArgs) -> Result<VerifiedProfile, CliError> {
    let project_id = match &args.project {
        Some(project) => project.clone(),
        None => resolve_project(cwd)?
            .map(|resolved| resolved.config.project_id)
            .ok_or_else(|| metadata_invalid_error("--project is required without locket.toml"))?,
    };
    let (device, sealing) = read_identity(&args.identity_env)?;
    let snapshot =
        latest_snapshot(&args.transport(cwd)?, &sealing, &device, &project_id, &args.owner)?;
    drop(sealing);
    let statement = snapshot.statement;
    if let Some(min_epoch) = args.min_epoch
        && statement.epoch < min_epoch
    {
        return Err(bundle_verification_error(format!(
            "CI package epoch {} is older than required --min-epoch {min_epoch}",
            statement.epoch
        )));
    }
    if let Some(max_age) = args.max_age_seconds {
        let now_secs = now_unix_nanos()? / 1_000_000_000;
        let max_age = i64::try_from(max_age).unwrap_or(i64::MAX);
        if now_secs.saturating_sub(statement.issued_at) > max_age {
            return Err(bundle_verification_error(
                "latest CI package exceeds --max-age-seconds limit",
            ));
        }
    }
    let member = statement
        .members
        .iter()
        .find(|member| !member.removed && member.device == device)
        .ok_or_else(|| access_denied_error("CI device is not an active team member"))?;
    let profile = statement
        .profiles
        .iter()
        .find(|profile| {
            profile.name == args.profile.as_str() && member.profiles.contains(&profile.id)
        })
        .ok_or_else(|| {
            access_denied_error("CI device is not authorized for the requested profile")
        })?;
    if profile.dangerous && !args.allow_dangerous {
        return Err(access_denied_error("dangerous CI profile requires --allow-dangerous"));
    }

    // Recipient encryption encloses the profile keys. TeamProfile zeroizes them on drop.
    let mut values = BTreeMap::new();
    for secret in &profile.secrets {
        let Some(blob) = &secret.blob else { continue };
        let name = SecretName::new(secret.name.as_str())
            .map_err(|_| bundle_verification_error("invalid secret name in CI package"))?;
        let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
            project_id.as_str(),
            &profile.id,
            &secret.id,
            name.as_str(),
            secret.version,
        ))?;
        let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
            project_id.as_str(),
            &secret.id,
            Some(&profile.id),
            secret.version,
            KeyWrapPurpose::SecretDek,
        ))?;
        let encrypted = EncryptedSecretValue {
            encrypted_dek: blob.encrypted_dek.clone(),
            ciphertext: blob.ciphertext.clone(),
            value_nonce: blob.value_nonce,
            aad_schema_version: blob.aad_schema_version,
        };
        let value = decrypt_secret_value_v1(&profile.secret_key, &encrypted, &value_aad, &wrap_aad)
            .map_err(|_| bundle_verification_error("unable to decrypt a CI profile secret"))?;
        values.insert(name, value);
    }
    Ok(VerifiedProfile { project_id, device_id: device.id, epoch: statement.epoch, values })
}

fn exec(cwd: &Path, args: &CiExecArgs) -> Result<u8, CliError> {
    let profile = read_profile(cwd, &args.read)?;
    let (program, command_args) = args
        .command
        .split_first()
        .ok_or_else(|| metadata_invalid_error("CI command is required"))?;
    let mut command = Command::new(program);
    command.args(command_args).current_dir(cwd);
    for env in TRANSPORT_CREDENTIAL_ENV
        .iter()
        .copied()
        .chain([DEFAULT_IDENTITY_ENV, args.read.identity_env.as_str()])
    {
        command.env_remove(env);
    }
    let selected = if args.all_profile_secrets {
        profile.values.keys().collect()
    } else {
        args.secrets.iter().collect::<Vec<_>>()
    };
    for name in selected {
        if locket_exec::is_child_runtime_control(name.as_str()) {
            return Err(crate::runtime::error::invalid_policy_error(format!(
                "CI secret cannot set a child startup variable: {name}"
            )));
        }
        let value = profile.values.get(name).ok_or_else(|| {
            secret_not_found_error(format!("requested CI secret {name} is missing"))
        })?;
        let identity_env = |env: &str| {
            if cfg!(windows) {
                name.as_str().eq_ignore_ascii_case(env)
            } else {
                name.as_str() == env
            }
        };
        if identity_env(DEFAULT_IDENTITY_ENV) || identity_env(&args.read.identity_env) {
            return Err(access_denied_error(
                "CI secret name conflicts with the identity environment variable",
            ));
        }
        command.env(name.as_str(), value.as_str());
    }
    drop(profile);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        // Replace the locket process image in-place so the child cannot inspect
        // a live parent process's original environment or heap memory.
        Err(command.exec().into())
    }
    #[cfg(not(unix))]
    {
        let child = command.spawn();
        drop(command);
        let status = child?.wait()?;
        Ok(crate::runtime::error::child_exit_error(status).exit_code())
    }
}
