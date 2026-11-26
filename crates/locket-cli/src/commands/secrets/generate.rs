//! Generate secret values directly into the encrypted vault.

use std::io::Write;

use clap::{Args, ValueEnum};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use zeroize::Zeroizing;

use super::set::{
    WriteRequest, WriteTargetArgs, cli_target, validate_write_metadata, write_value,
    write_write_result,
};
use crate::{
    CliError, RuntimeContext, SecretMetadataFlags, SourceArg, metadata_invalid_error,
    now_unix_nanos, open_store,
};

#[derive(Args, Debug)]
pub struct GenerateArgs {
    /// Secret key name.
    key: String,
    /// Number of random bytes. UUID format uses exactly 16 random bytes.
    #[arg(long)]
    bytes: Option<u16>,
    /// Output encoding stored in the vault.
    #[arg(long, value_enum, default_value = "base64url")]
    format: GenerateFormat,
    #[command(flatten)]
    target: WriteTargetArgs,
    #[command(flatten)]
    source: SourceArg,
    #[command(flatten)]
    metadata: SecretMetadataFlags,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GenerateFormat {
    #[default]
    #[value(name = "base64url")]
    Base64Url,
    Hex,
    Alphanumeric,
    Uuid,
}

pub fn generate_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &GenerateArgs,
) -> Result<u8, CliError> {
    let result = (|| {
        let mut store = open_store(context)?;
        let target = cli_target(context, &store, &args.target)?;
        let request =
            WriteRequest::new(&args.key, args.source.source, args.target.upsert, &args.metadata)?;
        validate_write_metadata(&args.metadata, None)?;
        let value = generate_value(args.bytes, args.format)?;
        let result = write_value(
            context,
            &mut store,
            &target,
            &request,
            &value,
            "generated",
            now_unix_nanos()?,
        )?;
        if args.target.project.is_none() {
            crate::refresh_example_for_project_if_enabled(context);
        }
        Ok(result)
    })();
    write_write_result(output, args.target.json, result)
}

pub fn generate_value(
    bytes: Option<u16>,
    format: GenerateFormat,
) -> Result<Zeroizing<String>, CliError> {
    let uuid = matches!(format, GenerateFormat::Uuid);
    let bytes = usize::from(bytes.unwrap_or(if uuid { 16 } else { 32 }));
    if !(16..=256).contains(&bytes) || (uuid && bytes != 16) {
        return Err(metadata_invalid_error(
            "generation requires 16–256 bytes, or exactly 16 for UUID format",
        ));
    }
    if matches!(format, GenerateFormat::Alphanumeric) {
        return alphanumeric(bytes);
    }
    let mut random = Zeroizing::new(vec![0; bytes]);
    for chunk in random.chunks_mut(locket_crypto::KEY_LEN) {
        let block = locket_crypto::generate_key()?;
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
    Ok(match format {
        GenerateFormat::Base64Url => Zeroizing::new(BASE64URL_NOPAD.encode(&random)),
        GenerateFormat::Hex => Zeroizing::new(HEXLOWER.encode(&random)),
        GenerateFormat::Uuid => uuid_v4(&mut random),
        GenerateFormat::Alphanumeric => alphanumeric(bytes)?,
    })
}

fn alphanumeric(bytes: usize) -> Result<Zeroizing<String>, CliError> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    // Emit two unbiased base-62 characters per requested byte, preserving at least eight bits
    // of entropy per byte. Discard the portion of the byte range that would bias the modulus.
    let length = bytes * 2;
    let mut value = Zeroizing::new(String::with_capacity(length));
    while value.len() < length {
        let block = locket_crypto::generate_key()?;
        for &byte in block.iter() {
            if byte < 248 {
                value.push(char::from(ALPHABET[usize::from(byte) % ALPHABET.len()]));
                if value.len() == length {
                    break;
                }
            }
        }
    }
    Ok(value)
}

fn uuid_v4(bytes: &mut [u8]) -> Zeroizing<String> {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = Zeroizing::new(HEXLOWER.encode(bytes));
    let mut value = Zeroizing::new(String::with_capacity(36));
    for (index, part) in
        [&hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..]].iter().enumerate()
    {
        if index != 0 {
            value.push('-');
        }
        value.push_str(part);
    }
    value
}
