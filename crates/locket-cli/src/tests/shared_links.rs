use std::fs;
use std::path::Path;
use std::sync::Arc;

use clap::Parser;
use locket_platform::MasterKeyStore;

use super::{cross_project::ProjectKeys, *};
use crate::{
    Cli, CliError, LOCKET_TOML, RuntimeContext, invalid_reference_error, run_with_context,
};

fn run_cli_args(context: &RuntimeContext, args: &[&str]) -> Result<String, CliError> {
    let mut output = Vec::new();
    let mut full = vec!["locket"];
    full.extend_from_slice(args);
    let cli = Cli::try_parse_from(full).map_err(|err| invalid_reference_error(err.to_string()))?;
    run_with_context(cli, context, &mut output)?;
    Ok(String::from_utf8_lossy(&output).into_owned())
}

fn add_check_policy(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let path = root.join(LOCKET_TOML);
    let policy = fs::read_to_string(&path)?;
    let argv = toml::Value::try_from(vec![
        test_shell(),
        "-c",
        r#"printf '%s' "$RPC_URL" > received-rpc"#,
    ])?;
    fs::write(
        path,
        format!("{policy}\n[commands.check]\nargv={argv}\nrequired_secrets=['RPC_URL']\n"),
    )?;
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the cross-project sequence in one fixture.
fn rpc_url_multi_repo_dedup_promote_rotate_import_link_and_unlink_delete()
-> Result<(), Box<dyn std::error::Error>> {
    let workspace = tempfile::tempdir()?;
    let store_path = workspace.path().join("store.db");
    let config_path = workspace.path().join("config.toml");
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> = Arc::new(ProjectKeys::default());
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
    add_check_policy(&repo_a)?;
    approve_test_policy(&ctx_a, "check")?;
    let policy = fs::read(repo_a.join(LOCKET_TOML))?;

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

    let resolved = crate::require_project(&ctx_a)?;
    let effective = crate::load_effective_command_policy(&resolved, "check", &ctx_a.cwd)?;
    let (_, _, docker_env) = crate::commands::exec::docker::resolve_policy_locket_env(
        &ctx_a,
        &crate::open_store(&ctx_a)?,
        &resolved,
        &effective,
        &effective.policy,
    )?;
    assert_eq!(docker_env.get("RPC_URL").map(|value| value.as_str()), Some(rpc_v1));
    assert!(!docker_env.contains_key("ALCHEMY_MAINNET_RPC"));

    // 4. Both Repo A (RPC_URL) and Repo B (MAINNET_RPC_URL) receive rpc_v1 via `locket get --reveal`.
    assert_eq!(run_cli_args(&ctx_a, &["get", "RPC_URL", "--reveal", "--force"])?.trim(), rpc_v1);
    assert_eq!(
        run_cli_args(&ctx_b, &["get", "MAINNET_RPC_URL", "--reveal", "--force"])?.trim(),
        rpc_v1
    );

    let received = repo_a.join("received-rpc");
    run_cli_args(&ctx_a, &["run", "check"])?;
    assert_eq!(fs::read_to_string(&received)?, rpc_v1);
    fs::remove_file(&received)?;

    // The same approved policy picks up the current Global Vault version.
    run_cli_args(&ctx_a, &["shared", "rotate", "ALCHEMY_MAINNET_RPC"])?;
    run_cli_args(&ctx_a, &["run", "check"])?;
    assert_eq!(fs::read_to_string(&received)?, rpc_v2);
    assert_eq!(fs::read(repo_a.join(LOCKET_TOML))?, policy);
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
    let store = crate::open_store(&ctx_a)?;
    for (ctx, alias) in [(&ctx_a, "RPC_URL"), (&ctx_b, "MAINNET_RPC_URL"), (&ctx_c, "ETH_RPC_URL")]
    {
        let project = crate::require_project(ctx)?.config.project_id.into_string();
        let key = crate::load_project_key(ctx, &store, &project, locket_crypto::KeyPurpose::Audit)?;
        assert!(store.verify_audit_chain_read_only(&project, key.as_ref())?.hmac_ok);
        let audits: Vec<_> = store
            .list_exportable_audit_rows(&project)?
            .into_iter()
            .filter(|row| row.action == "SECRET_UNLINK")
            .collect();
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].secret_name.as_deref(), Some(alias));
    }
    assert!(run_cli_args(&ctx_a, &["get", "RPC_URL", "--reveal", "--force"]).is_err());
    assert!(run_cli_args(&ctx_b, &["get", "MAINNET_RPC_URL", "--reveal", "--force"]).is_err());
    assert!(run_cli_args(&ctx_c, &["get", "ETH_RPC_URL", "--reveal", "--force"]).is_err());
    Ok(())
}

#[test]
fn rotate_warns_about_other_projects_with_the_previous_value()
-> Result<(), Box<dyn std::error::Error>> {
    let workspace = tempfile::tempdir()?;
    let source = workspace.path().join("source");
    let peer = workspace.path().join("peer");
    fs::create_dir(&source)?;
    fs::create_dir(&peer)?;
    let prior = "rotation-previous-value-canary";
    let replacement = "rotation-replacement-value-canary";
    let context = RuntimeContext {
        cwd: source,
        key_store: Arc::new(ProjectKeys::default()),
        secret_value_reader: Arc::new(StaticSecretValueReader::new(prior)),
        ..test_context(&workspace)
    };
    let peer_context = RuntimeContext { cwd: peer, ..context.clone() };

    run_cli_args(&context, &["shared", "init"])?;
    run_cli_args(&context, &["init", "--name", "rotation-source"])?;
    run_cli_args(&peer_context, &["init", "--name", "rotation-peer"])?;
    run_cli_args(&context, &["set", "TOKEN"])?;
    run_cli_args(&peer_context, &["set", "OTHER_TOKEN"])?;

    let replacement_context = RuntimeContext {
        secret_value_reader: Arc::new(StaticSecretValueReader::new(replacement)),
        ..context
    };
    let output = run_cli_args(&replacement_context, &["rotate", "TOKEN"])?;
    assert!(!output.contains(prior));
    assert!(!output.contains(replacement));
    assert!(output.contains("rotated TOKEN"));
    assert!(output.contains("warning:"));
    assert!(output.contains("rotation-peer (dev) -> OTHER_TOKEN"));
    assert!(output.contains("locket promote TOKEN --consolidate-duplicates"));
    let second_rotation = run_cli_args(&replacement_context, &["rotate", "TOKEN"])?;
    assert!(!second_rotation.contains("warning:"));
    assert_eq!(
        run_cli_args(&peer_context, &["get", "OTHER_TOKEN", "--reveal", "--force"])?.trim(),
        prior,
    );
    Ok(())
}

#[test]
fn mcp_shared_links_use_metadata_only_and_import_modes() -> Result<(), Box<dyn std::error::Error>> {
    use serde_json::json;

    let workspace = tempfile::tempdir()?;
    let source = workspace.path().join("source");
    let peer = workspace.path().join("peer");
    fs::create_dir(&source)?;
    fs::create_dir(&peer)?;
    let shared_value = "mcp-global-vault-canary";
    let repeat_value = "mcp-repeat-value-canary";
    let context = RuntimeContext {
        cwd: source,
        key_store: Arc::new(ProjectKeys::default()),
        secret_value_reader: Arc::new(StaticSecretValueReader::new(shared_value)),
        ..test_context(&workspace)
    };
    let peer_context = RuntimeContext { cwd: peer, ..context.clone() };
    run_cli_args(&context, &["shared", "init"])?;
    run_cli_args(&context, &["shared", "set", "GLOBAL_RPC"])?;
    run_cli_args(&context, &["init", "--name", "mcp-source"])?;
    run_cli_args(&peer_context, &["init", "--name", "mcp-peer"])?;
    fs::write(context.cwd.join(".env"), format!("DUPLICATE={repeat_value}\n"))?;
    fs::write(
        peer_context.cwd.join(".env"),
        format!("RPC_URL={shared_value}\nPEER_DUPLICATE={repeat_value}\n"),
    )?;

    let call = |tool, args: serde_json::Value| -> Result<_, Box<dyn std::error::Error>> {
        let payload = super::cross_project::mcp_call(&peer_context, tool, &args, None)?;
        let serialized = payload.to_string();
        assert!(!serialized.contains(shared_value));
        assert!(!serialized.contains(repeat_value));
        assert!(payload.get("dedup_tag").is_none());
        assert_eq!(payload["metadata_only"], true);
        Ok(payload)
    };
    run_cli_args(&context, &["import", ".env", "--keep"])?;
    run_cli_args(&peer_context, &["import", ".env", "--keep", "--only", "PEER_DUPLICATE"])?;
    let duplicates = call("locket_find_duplicates", json!({}))?;
    assert_eq!(duplicates["group_count"], 1);
    assert_eq!(duplicates["groups"][0]["count"], 2);
    assert!(!duplicates.to_string().contains("dedup_tag"));

    let linked = call(
        "locket_link_secret",
        json!({"project":"mcp-peer", "local_name":"MANUAL_RPC", "target_secret_name":"@shared/GLOBAL_RPC"}),
    )?;
    let usages = || call("locket_list_shared_usages", json!({"name":"GLOBAL_RPC"}));
    assert_eq!(usages()?["usages"][0]["link_id"], linked["link_id"]);
    assert_eq!(usages()?["usages"][0]["local_name"], "MANUAL_RPC");
    let removed =
        call("locket_unlink_secret", json!({"project":"mcp-peer", "local_name":"MANUAL_RPC"}))?;
    assert_eq!(removed["unlinked"], true);
    assert_eq!(usages()?["usage_count"], 0);

    let imported = call(
        "locket_import_env",
        json!({"project":"mcp-peer", "path":".env", "only":["RPC_URL"], "link_shared":true}),
    )?;
    assert_eq!(imported["linked"], 1);
    assert_eq!(imported["imported"], 0);
    assert_eq!(usages()?["usages"][0]["local_name"], "RPC_URL");

    fs::write(peer_context.cwd.join("promote.env"), format!("PROMOTED={repeat_value}\n"))?;
    let promoted = call(
        "locket_import_env",
        json!({"project":"mcp-peer", "path":"promote.env", "promote_duplicates":true}),
    )?;
    assert_eq!(promoted["promoted"], 1);
    assert_eq!(promoted["imported"], 0);
    let usages = call("locket_list_shared_usages", json!({"name":"PROMOTED"}))?;
    assert_eq!(usages["usages"][0]["local_name"], "PROMOTED");
    Ok(())
}

#[cfg(unix)]
#[test]
fn linked_cli_value_access_checks_the_live_agent_even_with_both_keys_available()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    let workspace = tempfile::tempdir()?;
    let socket_dir = tempfile::tempdir()?;
    fs::set_permissions(socket_dir.path(), fs::Permissions::from_mode(0o700))?;
    let context = RuntimeContext {
        key_store: Arc::new(ProjectKeys::default()),
        ..test_context_with_secret_value(&workspace, "linked-fixture-value")
    };
    run_cli_args(&context, &["init", "--name", "linked-consumer"])?;
    run_cli_args(&context, &["shared", "init"])?;
    run_cli_args(&context, &["shared", "set", "ALCHEMY_MAINNET_RPC"])?;
    run_cli_args(&context, &["link", "RPC_URL", "ALCHEMY_MAINNET_RPC"])?;
    add_check_policy(&context.cwd)?;
    approve_test_policy(&context, "check")?;

    let resolved = crate::require_project(&context)?;
    let store = crate::open_store(&context)?;
    let shared =
        crate::commands::discovery::global_vault_project(&store)?.ok_or("missing Global Vault")?;
    // A fixture key store supplies the same CLI key access interface as the OS keychain.
    let shared_key = context.key_store.load_master_key(&shared.id)?;
    let consumer = resolved.config.project_id.to_string();
    let consumer_key = context.key_store.load_master_key(&consumer)?;
    let context = RuntimeContext { agent_data_dir: Some(socket_dir.path().into()), ..context };
    let listener = UnixListener::bind(crate::agent_socket_path(&context))?;
    listener.set_nonblocking(true)?;
    let now = i128::from(crate::now_unix_nanos()?);
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async {
            let listener = tokio::net::UnixListener::from_std(listener)?;
            let state = locket_agent::AgentSocketState::locked("test");
            state.unlock_cache.lock().await.insert(
                consumer.clone(),
                locket_agent::UnlockEntry::new(
                    consumer_key.to_vec(),
                    now,
                    Duration::from_secs(60),
                    locket_agent::UnlockMethod::OsKeychain,
                ),
            );
            for request in 0..6 {
                if request == 4 {
                    let mut cache = state.unlock_cache.lock().await;
                    cache.evict(&consumer);
                    cache.insert(
                        shared.id.clone(),
                        locket_agent::UnlockEntry::new(
                            shared_key.to_vec(),
                            now,
                            Duration::from_secs(60),
                            locket_agent::UnlockMethod::OsKeychain,
                        ),
                    );
                }
                let (stream, _) =
                    tokio::time::timeout(Duration::from_secs(3), listener.accept()).await??;
                let _ = locket_agent::handle_connection(stream, state.clone()).await;
            }
            Ok(())
        })
    });

    let get = run_cli_args(&context, &["get", "RPC_URL", "--reveal", "--force"]);
    let explicit = run_cli_args(
        &context,
        &["get", "RPC_URL", "--project", "linked-consumer", "--reveal", "--force"],
    );
    let run = run_cli_args(&context, &["run", "check"]);
    let effective = crate::load_effective_command_policy(&resolved, "check", &context.cwd)?;
    let docker = crate::commands::exec::docker::resolve_policy_locket_env(
        &context,
        &store,
        &resolved,
        &effective,
        &effective.policy,
    );
    let consumer_locked = run_cli_args(&context, &["get", "RPC_URL", "--reveal", "--force"]);
    server.join().map_err(|_| "agent socket fixture panicked")??;
    for error in [get.err(), explicit.err(), run.err(), docker.err()] {
        assert!(matches!(
            error,
            Some(CliError::Typed { kind: locket_core::LocketError::UnlockRequired, message })
                if message.contains("Global Vault"),
        ));
    }
    assert!(matches!(
        consumer_locked,
        Err(CliError::Typed { kind: locket_core::LocketError::UnlockRequired, message })
            if message.contains("consuming project"),
    ));
    Ok(())
}

#[test]
fn cli_promote_audits_created_reused_and_rotated_targets_in_both_projects()
-> Result<(), Box<dyn std::error::Error>> {
    let workspace = tempfile::tempdir()?;
    let context =
        RuntimeContext { key_store: Arc::new(ProjectKeys::default()), ..test_context(&workspace) };
    run_cli_args(&context, &["init", "--name", "promotion-source"])?;
    run_cli_args(&context, &["shared", "init"])?;
    for (name, value, operation, version) in [
        ("FIRST", "first", "create", 1),
        ("SECOND", "first", "reuse", 1),
        ("THIRD", "changed", "rotate", 2),
    ] {
        let writer = RuntimeContext {
            secret_value_reader: Arc::new(StaticSecretValueReader::new(value)),
            ..context.clone()
        };
        run_cli_args(&writer, &["set", name])?;
        let mut args = vec!["promote", name, "--as", "GLOBAL_TOKEN", "--json"];
        if operation == "rotate" {
            args.push("--overwrite");
        }
        let result: serde_json::Value = serde_json::from_str(&run_cli_args(&context, &args)?)?;
        assert_eq!(result["action"], operation);
        assert_eq!(result["version"], version);
    }
    let store = crate::open_store(&context)?;
    let resolved = crate::require_project(&context)?;
    let source = crate::default_profile(&store, &resolved.config)?;
    let shared =
        crate::commands::discovery::global_vault_project(&store)?.ok_or("missing Global Vault")?;
    let target = store.get_profile_by_name(&shared.id, "default")?.ok_or("missing profile")?;
    for profile in [&source, &target] {
        let key = crate::load_project_key(
            &context,
            &store,
            &profile.project_id,
            locket_crypto::KeyPurpose::Audit,
        )?;
        assert!(store.verify_audit_chain_read_only(&profile.project_id, key.as_ref())?.hmac_ok);
        let rows: Vec<_> = store
            .list_exportable_audit_rows(&profile.project_id)?
            .into_iter()
            .filter(|row| row.action == "SECRET_PROMOTE")
            .collect();
        assert_eq!(rows.len(), 3);
        for (row, (operation, version)) in
            rows.iter().zip([("create", 1), ("reuse", 1), ("rotate", 2)])
        {
            assert_eq!(row.profile_id.as_deref(), Some(profile.id.as_str()));
            let metadata: serde_json::Value = serde_json::from_str(&row.metadata_json)?;
            assert_eq!(metadata["operation"], operation);
            assert_eq!(metadata["secret_name"], "GLOBAL_TOKEN");
            assert_eq!(metadata["target_version"], version);
            assert_eq!(metadata["from_project_id"], source.project_id);
            assert_eq!(metadata["from_profile_id"], source.id);
            assert_eq!(metadata["to_project_id"], target.project_id);
            assert_eq!(metadata["to_profile_id"], target.id);
        }
    }
    Ok(())
}
