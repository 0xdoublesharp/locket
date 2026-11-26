use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use clap::Parser;
use locket_crypto::KeyBytes;
use locket_platform::{MasterKeyStore, PlatformError};
use zeroize::Zeroizing;

use super::*;
use crate::{
    Cli, CliError, LOCKET_TOML, RuntimeContext, invalid_reference_error, run_with_context,
};

#[derive(Default)]
struct SharedMemoryKeys(Mutex<BTreeMap<String, Zeroizing<KeyBytes>>>);

impl MasterKeyStore for SharedMemoryKeys {
    fn store_master_key(&self, id: &str, key: &KeyBytes) -> Result<(), PlatformError> {
        self.0
            .lock()
            .map_err(|_| PlatformError::MemoryPoisoned)?
            .insert(id.to_owned(), Zeroizing::new(*key));
        Ok(())
    }

    fn load_master_key(&self, id: &str) -> Result<Zeroizing<KeyBytes>, PlatformError> {
        self.0
            .lock()
            .map_err(|_| PlatformError::MemoryPoisoned)?
            .get(id)
            .cloned()
            .ok_or(PlatformError::MasterKeyNotFound)
    }

    fn delete_master_key(&self, id: &str) -> Result<(), PlatformError> {
        self.0.lock().map_err(|_| PlatformError::MemoryPoisoned)?.remove(id);
        Ok(())
    }
}

fn run_cli_args(context: &RuntimeContext, args: &[&str]) -> Result<String, CliError> {
    let mut output = Vec::new();
    let mut full = vec!["locket"];
    full.extend_from_slice(args);
    let cli = Cli::try_parse_from(full).map_err(|err| invalid_reference_error(err.to_string()))?;
    run_with_context(cli, context, &mut output)?;
    Ok(String::from_utf8_lossy(&output).into_owned())
}

fn add_echo_policy(root: &Path, var_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let toml_path = root.join(LOCKET_TOML);
    let mut content = fs::read_to_string(&toml_path)?;
    #[cfg(unix)]
    let cmd = format!(
        "\n[commands.check]\nshell = \"printf '%s' \\\"${var_name}\\\"\"\nrequired_secrets = [\"{var_name}\"]\n"
    );
    #[cfg(windows)]
    let cmd = format!(
        "\n[commands.check]\nshell = \"echo %{var_name}%\"\nrequired_secrets = [\"{var_name}\"]\n"
    );
    content.push_str(&cmd);
    fs::write(toml_path, content)?;
    Ok(())
}

#[test]
fn rpc_url_multi_repo_dedup_promote_rotate_import_link_and_unlink_delete()
-> Result<(), Box<dyn std::error::Error>> {
    let workspace = tempfile::tempdir()?;
    let store_path = workspace.path().join("store.db");
    let config_path = workspace.path().join("config.toml");
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> = Arc::new(SharedMemoryKeys::default());
    let repo_a = workspace.path().join("foundry");
    let repo_b = workspace.path().join("frontend");
    let repo_c = workspace.path().join("indexer");
    fs::create_dir_all(&repo_a)?;
    fs::create_dir_all(&repo_b)?;
    fs::create_dir_all(&repo_c)?;

    let make_ctx = |cwd: &Path, secret_value: &str| RuntimeContext {
        cwd: cwd.to_path_buf(),
        store_path: store_path.clone(),
        config_path: config_path.clone(),
        key_store: Arc::clone(&key_store),
        secret_value_reader: Arc::new(StaticSecretValueReader::new(secret_value)),
        confirmation_reader: Arc::new(StaticConfirmationReader::new("n")),
        ..test_context(&workspace)
    };

    let rpc_v1 = "https://eth-mainnet.example.invalid/v2/rpc-v1-key";
    let rpc_v2 = "https://eth-mainnet.example.invalid/v2/rpc-v2-rotated";

    let ctx_a = make_ctx(&repo_a, rpc_v2);
    let ctx_b = make_ctx(&repo_b, rpc_v2);
    let ctx_c = make_ctx(&repo_c, rpc_v2);

    run_cli_args(&ctx_a, &["shared", "init"])?;
    run_cli_args(&ctx_a, &["init", "--name", "foundry"])?;
    run_cli_args(&ctx_b, &["init", "--name", "frontend"])?;
    run_cli_args(&ctx_c, &["init", "--name", "indexer"])?;
    add_echo_policy(&repo_a, "RPC_URL")?;
    add_echo_policy(&repo_b, "MAINNET_RPC_URL")?;
    add_echo_policy(&repo_c, "ETH_RPC_URL")?;

    // 1. Import identical RPC URL under different env var names in Repo A and Repo B.
    fs::write(repo_a.join(".env"), format!("RPC_URL={rpc_v1}\n"))?;
    fs::write(repo_b.join(".env"), format!("MAINNET_RPC_URL={rpc_v1}\n"))?;
    run_cli_args(&ctx_a, &["import", ".env", "--keep"])?;
    run_cli_args(&ctx_b, &["import", ".env", "--keep"])?;

    // 2. `locket duplicates --json` detects the cross-project repeat across different names.
    let dup_json: serde_json::Value =
        serde_json::from_str(&run_cli_args(&ctx_a, &["duplicates", "--json"])?)?;
    assert_eq!(dup_json["group_count"], 1);
    assert_eq!(dup_json["groups"][0]["count"], 2);

    // 3. Promote RPC_URL -> @shared/ALCHEMY_MAINNET_RPC and consolidate duplicates.
    let promoted_json: serde_json::Value = serde_json::from_str(&run_cli_args(
        &ctx_a,
        &[
            "promote",
            "RPC_URL",
            "--as",
            "ALCHEMY_MAINNET_RPC",
            "--consolidate-duplicates",
            "--json",
        ],
    )?)?;
    assert_eq!(promoted_json["target_secret_name"], "ALCHEMY_MAINNET_RPC");
    assert_eq!(promoted_json["linked"], true);
    assert_eq!(promoted_json["consolidated_count"], 1);

    // Zero duplicate copies remain after consolidation.
    let dup_after: serde_json::Value =
        serde_json::from_str(&run_cli_args(&ctx_a, &["duplicates", "--json"])?)?;
    assert_eq!(dup_after["group_count"], 0);

    // 4. Both Repo A (RPC_URL) and Repo B (MAINNET_RPC_URL) receive rpc_v1 via `locket get --reveal`.
    assert_eq!(run_cli_args(&ctx_a, &["get", "RPC_URL", "--reveal", "--force"])?.trim(), rpc_v1);
    assert_eq!(
        run_cli_args(&ctx_b, &["get", "MAINNET_RPC_URL", "--reveal", "--force"])?.trim(),
        rpc_v1
    );

    // 5. Rotate ONCE in @shared -> immediately reflected in BOTH Repo A and Repo B!
    run_cli_args(&ctx_a, &["shared", "rotate", "ALCHEMY_MAINNET_RPC"])?;
    assert_eq!(run_cli_args(&ctx_a, &["get", "RPC_URL", "--reveal", "--force"])?.trim(), rpc_v2);
    assert_eq!(
        run_cli_args(&ctx_b, &["get", "MAINNET_RPC_URL", "--reveal", "--force"])?.trim(),
        rpc_v2
    );

    // 6. Import same URL into Repo C under ETH_RPC_URL with --link-shared -> links directly!
    fs::write(repo_c.join(".env"), format!("ETH_RPC_URL={rpc_v2}\n"))?;
    let import_c: serde_json::Value = serde_json::from_str(&run_cli_args(
        &ctx_c,
        &["import", ".env", "--keep", "--link-shared", "--json"],
    )?)?;
    assert_eq!(import_c["linked"], 1);
    assert_eq!(import_c["imported"], 0);
    assert_eq!(
        run_cli_args(&ctx_c, &["get", "ETH_RPC_URL", "--reveal", "--force"])?.trim(),
        rpc_v2
    );

    // 7. `locket shared usages` shows all 3 linked projects and their local var names.
    let usages: serde_json::Value = serde_json::from_str(&run_cli_args(
        &ctx_a,
        &["shared", "usages", "ALCHEMY_MAINNET_RPC", "--json"],
    )?)?;
    assert_eq!(usages["usage_count"], 3);

    // 8. `locket shared rm` warns and fails without --unlink-all.
    let Err(err) = run_cli_args(&ctx_a, &["shared", "rm", "ALCHEMY_MAINNET_RPC"]) else {
        return Err("rm without --unlink-all must warn and fail".into());
    };
    let msg = err.to_string();
    assert!(msg.contains("linked by 3 project(s)"), "{msg}");
    assert!(msg.contains("--unlink-all"), "{msg}");

    // 9. `locket shared rm --unlink-all` removes @shared entry and unlinks all 3 projects at once!
    let removed = run_cli_args(&ctx_a, &["shared", "rm", "ALCHEMY_MAINNET_RPC", "--unlink-all"])?;
    assert!(removed.contains("unlinked 3 project link(s)"), "{removed}");
    assert!(run_cli_args(&ctx_a, &["get", "RPC_URL", "--reveal", "--force"]).is_err());
    assert!(run_cli_args(&ctx_b, &["get", "MAINNET_RPC_URL", "--reveal", "--force"]).is_err());
    assert!(run_cli_args(&ctx_c, &["get", "ETH_RPC_URL", "--reveal", "--force"]).is_err());
    Ok(())
}
