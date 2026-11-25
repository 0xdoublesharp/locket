//! Verify socket isolation, live vault access, and post-lock plaintext retention.
#![allow(unused_crate_dependencies, clippy::multiple_crate_versions)]

#[cfg(unix)]
mod unix {
    use std::error::Error;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use locket_agent::{
        AgentSocketConfig, AgentSocketState, ConnectionOutcome, SocketServerError,
        bind_socket_listener, current_process_uid, handle_connection, socket_permission_mode,
    };
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn socket_bind_enforces_permissions_and_keeps_existing_paths_untouched()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let private = directory.path().join("private");
        let socket = private.join("s");
        let _listener = bind_socket_listener(&AgentSocketConfig::new(socket.clone(), "test"))?;
        assert_eq!(socket_permission_mode(&socket), Some(0o600));
        assert_eq!(fs::metadata(&private)?.permissions().mode() & 0o777, 0o700);

        let public = directory.path().join("public");
        fs::create_dir(&public)?;
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755))?;
        let alias = directory.path().join("alias");
        symlink(&public, &alias)?;
        assert!(matches!(
            bind_socket_listener(&AgentSocketConfig::new(public.join("s"), "test")),
            Err(SocketServerError::SocketPathTooWide { .. })
        ));
        assert_symlink_rejected(alias.join("s"));
        assert_eq!(fs::read_dir(public)?.count(), 0);

        let link = private.join("link");
        symlink(&socket, &link)?;
        assert_symlink_rejected(link.clone());
        assert_eq!(fs::read_link(link)?, socket);
        assert_eq!(socket_permission_mode(&socket), Some(0o600));
        Ok(())
    }

    #[tokio::test]
    async fn socket_bind_rejects_symlinks_to_private_directories() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let private = root.join("private");
        fs::create_dir(&private)?;
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700))?;
        let alias = root.join("alias");
        symlink(&private, &alias)?;

        for path in [alias.join("s"), alias.join("nested/s")] {
            assert_symlink_rejected(path);
        }
        assert_eq!(fs::read_dir(private)?.count(), 0);
        Ok(())
    }

    fn assert_symlink_rejected(path: std::path::PathBuf) {
        assert!(matches!(
            bind_socket_listener(&AgentSocketConfig::new(path, "test")),
            Err(SocketServerError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput
        ));
    }

    #[tokio::test]
    async fn kernel_peer_credentials_reject_a_mismatched_daemon_uid() -> Result<(), Box<dyn Error>>
    {
        let (mut client, server) = UnixStream::pair()?;
        let local_uid = current_process_uid();
        let expected_uid = local_uid ^ 1;
        let state = AgentSocketState::with_daemon_uid("test", expected_uid);
        let outcome = handle_connection(server, state).await;
        assert!(matches!(
            outcome,
            ConnectionOutcome::Rejected {
                reason: SocketServerError::PeerCredentialDenied { peer_uid, daemon_uid }
            } if peer_uid == local_uid && daemon_uid == expected_uid
        ));
        assert_eq!(client.read(&mut [0]).await?, 0);
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    mod vault {
        use std::error::Error;
        use std::os::unix::fs::symlink;
        use std::path::Path;
        use std::sync::Arc;
        use std::time::Duration;

        use data_encoding::BASE64URL_NOPAD;
        use locket_agent::{
            AgentMethod, AgentSocketState, ConnectionOutcome, DEFAULT_MAX_MESSAGE_SIZE,
            GrantBinding, RequestEnvelope, ResponseEnvelope, current_process_uid,
            decode_response_frame, encode_frame, handle_connection,
        };
        use locket_crypto::{
            HkdfWrapInfo, KeyBytes, KeyPurpose, KeyWrapAad, KeyWrapPurpose, SecretBlobAad,
            derive_wrapping_key_v1, encrypt_secret_value_v1, generate_key, key_wrap_aad_v1,
            secret_blob_aad_v1, secret_fingerprint_v1, wrap_key_material_v1,
        };
        use locket_platform::{
            MasterKeyStore, MemoryMasterKeyStore, PassphraseFallbackMasterKeyStore,
        };
        use locket_store::{
            KeyRecord, SecretBlobRecord, SecretFingerprintRecord, SecretRecord,
            SecretVersionRecord, Store,
        };
        use serde_json::{Value, json};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;
        use zeroize::Zeroizing;

        const PROJECT: &str = "lk_proj_ipc_fixture";
        const PROFILE: &str = "lk_profile_ipc_fixture";
        const OTHER_PROJECT: &str = "lk_proj_other_fixture";
        const OTHER_PROFILE: &str = "lk_profile_other_fixture";
        const SECRET: &str = "lk_secret_ipc_fixture";

        async fn rpc(
            client: &mut UnixStream,
            method: AgentMethod,
            payload: Value,
        ) -> Result<ResponseEnvelope, Box<dyn Error>> {
            let request = RequestEnvelope::new("security-fixture", method, payload);
            let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
            let response = tokio::time::timeout(Duration::from_secs(5), async {
                client.write_all(&frame).await?;
                let size = client.read_u32_le().await? as usize;
                if size > DEFAULT_MAX_MESSAGE_SIZE {
                    return Err(std::io::Error::other("response too large"));
                }
                let mut bytes = vec![0; 4 + size];
                bytes[..4].copy_from_slice(
                    &u32::try_from(size).map_err(std::io::Error::other)?.to_le_bytes(),
                );
                client.read_exact(&mut bytes[4..]).await?;
                Ok(bytes)
            })
            .await??;
            Ok(decode_response_frame(&response, DEFAULT_MAX_MESSAGE_SIZE)?.0)
        }

        fn success(response: ResponseEnvelope) -> Result<Value, Box<dyn Error>> {
            match response {
                ResponseEnvelope::Success(response) => Ok(response.payload),
                ResponseEnvelope::Error(error) => {
                    Err(format!("{}: {}", error.error, error.message).into())
                }
            }
        }

        fn assert_denied(response: ResponseEnvelope, expected: &str) {
            assert!(
                matches!(response, ResponseEnvelope::Error(error) if error.error == expected),
                "expected {expected}"
            );
        }

        fn insert_wrapped_key(
            store: &Store,
            profile: Option<&str>,
            purpose: KeyPurpose,
            master: &KeyBytes,
            key: &KeyBytes,
        ) -> Result<(), Box<dyn Error>> {
            let id = format!("lk_key_{}", purpose.as_str());
            let wrapping =
                derive_wrapping_key_v1(master, &HkdfWrapInfo::new(PROJECT, profile, purpose))?;
            let aad = key_wrap_aad_v1(&KeyWrapAad::new(
                PROJECT,
                &id,
                profile,
                0,
                KeyWrapPurpose::from(purpose),
            ))?;
            let wrapped = wrap_key_material_v1(&wrapping, key, &aad)?;
            store.insert_key(&KeyRecord {
                id,
                project_id: PROJECT.into(),
                profile_id: profile.map(str::to_owned),
                purpose: purpose.as_str().into(),
                wrapped_material: wrapped.ciphertext,
                nonce: wrapped.nonce,
                created_at: 1,
            })?;
            Ok(())
        }

        fn seed_vault(
            path: &Path,
            key_store: &MemoryMasterKeyStore,
            canary: &str,
        ) -> Result<(), Box<dyn Error>> {
            let master = generate_key()?;
            let audit_key = generate_key()?;
            let secret_key = generate_key()?;
            let fingerprint_key = generate_key()?;
            let mut store = Store::open(path)?;
            store.initialize_schema()?;
            store.insert_project_if_absent(PROJECT, "ipc-fixture", 1)?;
            store.insert_project_if_absent(OTHER_PROJECT, "other-fixture", 1)?;
            store.insert_profile_if_absent(PROFILE, PROJECT, "default", false, 1)?;
            store.insert_profile_if_absent(OTHER_PROFILE, OTHER_PROJECT, "default", false, 1)?;
            insert_wrapped_key(&store, None, KeyPurpose::Audit, &master, &audit_key)?;
            insert_wrapped_key(
                &store,
                Some(PROFILE),
                KeyPurpose::ProfileSecret,
                &master,
                &secret_key,
            )?;

            let name = "CANARY_TOKEN";
            let value_aad =
                secret_blob_aad_v1(&SecretBlobAad::new(PROJECT, PROFILE, SECRET, name, 1))?;
            let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
                PROJECT,
                SECRET,
                Some(PROFILE),
                1,
                KeyWrapPurpose::SecretDek,
            ))?;
            let encrypted = encrypt_secret_value_v1(&secret_key, canary, &value_aad, &wrap_aad)?;
            let fingerprint = secret_fingerprint_v1(&fingerprint_key, canary)?;
            store.create_active_secret(
                &SecretRecord {
                    id: SECRET.into(),
                    project_id: PROJECT.into(),
                    profile_id: PROFILE.into(),
                    name: name.into(),
                    source: "user-local".into(),
                    origin: "manual".into(),
                    current_version: 1,
                    state: "active".into(),
                    created_at: 1,
                    updated_at: 1,
                    last_rotated_at: None,
                    deleted_at: None,
                },
                &SecretVersionRecord {
                    secret_id: SECRET.into(),
                    version: 1,
                    source: "user-local".into(),
                    origin: "manual".into(),
                    state: "current".into(),
                    created_at: 1,
                    deprecated_at: None,
                    grace_until: None,
                    purged_at: None,
                },
                &SecretBlobRecord {
                    secret_id: SECRET.into(),
                    version: 1,
                    encrypted_dek: encrypted.encrypted_dek,
                    ciphertext: encrypted.ciphertext,
                    value_nonce: encrypted.value_nonce,
                    aad_schema_version: 1,
                    created_at: 1,
                },
                &SecretFingerprintRecord {
                    secret_id: SECRET.into(),
                    version: 1,
                    fingerprint: fingerprint.to_vec(),
                    created_at: 1,
                },
            )?;
            key_store.store_master_key(PROJECT, &master)?;
            Ok(())
        }

        #[tokio::test]
        async fn lock_evicts_live_vault_access_and_rejects_cross_scope_ipc()
        -> Result<(), Box<dyn Error>> {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("vault.db");
            let keys = Arc::new(MemoryMasterKeyStore::default());
            {
                let random = generate_key()?;
                let canary = Zeroizing::new(BASE64URL_NOPAD.encode(random.as_ref()));
                seed_vault(&path, &keys, &canary)?;
            }
            let alias = directory.path().join("vault-link.db");
            symlink(&path, &alias)?;
            assert!(Store::open(&alias).is_err());
            assert!(Store::open_read_only(&alias).is_err());
            let state = AgentSocketState::with_stores(
                "fixture",
                current_process_uid(),
                keys.clone(),
                Arc::new(PassphraseFallbackMasterKeyStore::new(directory.path().join("fallback"))),
            )
            .with_canonical_store_path(path.clone());
            let (mut client, server) = UnixStream::pair()?;
            let server = tokio::spawn(handle_connection(server, state));
            let unlock = json!({"project_id": PROJECT, "ttl_seconds": 60});

            let alias_unlock =
                json!({"project_id": PROJECT, "ttl_seconds": 60, "store_path": alias});
            assert_denied(
                rpc(&mut client, AgentMethod::Unlock, alias_unlock).await?,
                "AccessDenied",
            );
            success(rpc(&mut client, AgentMethod::Unlock, unlock.clone()).await?)?;
            // An unlock entry is now the only source of the master key.
            keys.delete_master_key(PROJECT)?;

            let process = locket_platform::current_process_binding()?;
            let binding = GrantBinding::new(process.pid, process.process_start_time);
            let grant = json!({
                "project_id": PROJECT, "profile_id": PROFILE, "action": "ScanKnownValues",
                "ttl_seconds": 30, "binding": binding,
            });
            let grant_id =
                success(rpc(&mut client, AgentMethod::RequestGrant, grant.clone()).await?)?;
            let grant_id = grant_id["grant_id"].as_str().ok_or("missing grant id")?;
            let request = |project, profile| {
                json!({
                    "project_id": project, "profile_id": profile, "store_path": path,
                    "grant_id": grant_id, "binding": binding, "require_known": true,
                })
            };
            for (project, profile) in [(OTHER_PROJECT, OTHER_PROFILE), (PROJECT, OTHER_PROFILE)] {
                assert_denied(
                    rpc(&mut client, AgentMethod::ScanKnownValues, request(project, profile))
                        .await?,
                    "GrantRequired",
                );
            }
            let scan = request(PROJECT, PROFILE);
            // The scan decrypts the eligible blob before matching inputs, even for an empty list.
            let result =
                success(rpc(&mut client, AgentMethod::ScanKnownValues, scan.clone()).await?)?;
            assert_eq!(result, json!({"findings": [], "locked": false}));
            let status = json!({"project_id": PROJECT});
            let before = success(rpc(&mut client, AgentMethod::Status, status.clone()).await?)?;
            assert_eq!(before["lock_state"], "unlocked");
            assert_eq!(before["live_grant_count"], 1);

            success(rpc(&mut client, AgentMethod::Lock, status.clone()).await?)?;
            // SQLite removes these files once the last connection closes.
            assert!(!path.with_extension("db-wal").try_exists()?);
            assert!(!path.with_extension("db-shm").try_exists()?);
            let after = success(rpc(&mut client, AgentMethod::Status, status).await?)?;
            assert_eq!(after["lock_state"], "locked");
            assert_eq!(after["live_grant_count"], 0);
            assert_denied(
                rpc(&mut client, AgentMethod::ScanKnownValues, scan).await?,
                "GrantRequired",
            );
            assert_denied(
                rpc(&mut client, AgentMethod::RequestGrant, grant).await?,
                "UnlockRequired",
            );
            let mut cached = unlock;
            cached["reuse_cached"] = json!(true);
            assert_denied(rpc(&mut client, AgentMethod::Unlock, cached).await?, "UnlockRequired");

            drop(client);
            assert_eq!(server.await?, ConnectionOutcome::PeerClosed);
            Ok(())
        }

        #[cfg(target_os = "linux")]
        mod heap {
            use super::{
                AgentMethod, AgentSocketState, Arc, ConnectionOutcome, Error, GrantBinding,
                MasterKeyStore, MemoryMasterKeyStore, PROFILE, PROJECT,
                PassphraseFallbackMasterKeyStore, UnixStream, Zeroizing, current_process_uid,
                handle_connection, json, rpc, seed_vault, success,
            };
            use std::fs::File;
            use std::hint::black_box;
            use std::io::{Read, Write};
            use std::os::unix::fs::FileExt;
            use std::process::Command;

            const CHILD: &str = "LOCKET_TEST_POST_LOCK_HEAP_CHILD";
            const CHILD_PASSED: &str = "completed post-lock heap scan and positive control";
            const CANARY_LEN: usize = 48;
            const CANARY_XOR: u8 = 0xa7;
            static MASKED_CANARY: [u8; CANARY_LEN] = [
                0xd6, 0xe1, 0xe4, 0xf8, 0xf5, 0xe6, 0xe9, 0xc6, 0xf3, 0xd3, 0x9e, 0xd0, 0xe2, 0xd2,
                0xd2, 0xf7, 0xc4, 0xf6, 0x92, 0xc4, 0xf2, 0xf8, 0xe2, 0xf8, 0xdf, 0xc5, 0xe0, 0xfe,
                0xf7, 0xd7, 0xc4, 0x95, 0xc4, 0x9f, 0xf2, 0xf0, 0xe1, 0xf4, 0xf6, 0xf1, 0xf3, 0xc6,
                0xeb, 0xdd, 0xfd, 0xe0, 0xed, 0xf3,
            ];

            fn canary() -> Zeroizing<Vec<u8>> {
                let mut bytes = Zeroizing::new(vec![0; CANARY_LEN]);
                // Keep the plaintext out of compiler-generated constants and stack arrays.
                for (byte, masked) in bytes.iter_mut().zip(black_box(&MASKED_CANARY)) {
                    *byte = masked ^ CANARY_XOR;
                }
                bytes
            }

            #[test]
            fn lock_leaves_no_plaintext_canary_in_heap() -> Result<(), Box<dyn Error>> {
                if std::env::var_os(CHILD).is_none() {
                    let (_, module) =
                        module_path!().split_once("::").ok_or("missing test module")?;
                    let test = format!("{module}::lock_leaves_no_plaintext_canary_in_heap");
                    let output = Command::new(std::env::current_exe()?)
                        .env(CHILD, "1")
                        .args(["--exact", &test, "--nocapture", "--test-threads=1"])
                        .output()?;
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    assert!(
                        output.status.success() && stdout.contains(CHILD_PASSED),
                        "heap scan child exited with {}\n{stdout}\n{}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr)
                    );
                    return Ok(());
                }

                // Allocate scanner storage before decrypting so it cannot recycle a freed
                // plaintext allocation when the scan begins.
                let mut maps = String::with_capacity(64 * 1024);
                let mut buffer = Zeroizing::new(vec![0; 64 * 1024]);
                let directory = tempfile::tempdir()?;
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(exercise_vault(directory.path()))?;
                assert!(
                    !contains_canary(&mut maps, &mut buffer)?,
                    "plaintext canary survived vault lock in private anonymous memory"
                );

                // Check detector sensitivity after the real scan to avoid contaminating it.
                let live = canary();
                assert!(
                    contains_canary(&mut maps, &mut buffer)?,
                    "heap scanner missed a live plaintext allocation"
                );
                black_box(&live);
                writeln!(std::io::stdout().lock(), "{CHILD_PASSED}")?;
                Ok(())
            }

            async fn exercise_vault(directory: &std::path::Path) -> Result<(), Box<dyn Error>> {
                let path = directory.join("vault.db");
                let keys = Arc::new(MemoryMasterKeyStore::default());
                seed_vault(&path, &keys, std::str::from_utf8(&canary())?)?;
                let state = AgentSocketState::with_stores(
                    "heap-fixture",
                    current_process_uid(),
                    keys.clone(),
                    Arc::new(PassphraseFallbackMasterKeyStore::new(directory.join("fallback"))),
                )
                .with_canonical_store_path(path.clone());
                let (mut client, server) = UnixStream::pair()?;
                let server = tokio::spawn(handle_connection(server, state));
                success(
                    rpc(
                        &mut client,
                        AgentMethod::Unlock,
                        json!({"project_id": PROJECT, "ttl_seconds": 60}),
                    )
                    .await?,
                )?;
                keys.delete_master_key(PROJECT)?;

                let process = locket_platform::current_process_binding()?;
                let binding = GrantBinding::new(process.pid, process.process_start_time);
                let grant = success(
                    rpc(
                        &mut client,
                        AgentMethod::RequestGrant,
                        json!({
                            "project_id": PROJECT, "profile_id": PROFILE,
                            "action": "ScanKnownValues", "ttl_seconds": 30, "binding": binding,
                        }),
                    )
                    .await?,
                )?;
                // Read the stored plaintext through the agent's known-value decryption path
                // without embedding it in IPC buffers or returning it to the caller.
                let scan = success(
                    rpc(
                        &mut client,
                        AgentMethod::ScanKnownValues,
                        json!({
                            "project_id": PROJECT, "profile_id": PROFILE, "store_path": path,
                            "grant_id": grant["grant_id"], "binding": binding, "require_known": true,
                        }),
                    )
                    .await?,
                )?;
                assert_eq!(scan, json!({"findings": [], "locked": false}));
                let project = json!({"project_id": PROJECT});
                success(rpc(&mut client, AgentMethod::Lock, project.clone()).await?)?;
                let status = success(rpc(&mut client, AgentMethod::Status, project).await?)?;
                assert_eq!(status["lock_state"], "locked");
                assert_eq!(status["live_grant_count"], 0);
                drop(client);
                assert_eq!(server.await?, ConnectionOutcome::PeerClosed);
                Ok(())
            }

            fn contains_canary(
                maps: &mut String,
                buffer: &mut [u8],
            ) -> Result<bool, Box<dyn Error>> {
                maps.clear();
                File::open("/proc/self/maps")?.read_to_string(maps)?;
                let memory = File::open("/proc/self/mem")?;
                let mask = black_box(&MASKED_CANARY);
                let capacity = u64::try_from(buffer.len())?;
                let overlap = u64::try_from(CANARY_LEN - 1)?;
                for line in maps.lines() {
                    let mut fields = line.split_ascii_whitespace();
                    let range = fields.next().ok_or("missing process memory range")?;
                    if fields.next() != Some("rw-p") {
                        continue;
                    }
                    // Skip offset, device, and inode to read the optional mapping name.
                    if let Some(name) = fields.nth(3)
                        && name != "[heap]"
                        && !name.starts_with("[anon:")
                    {
                        continue;
                    }
                    let (start, end) = range.split_once('-').ok_or("invalid memory range")?;
                    let mut offset = u64::from_str_radix(start, 16)?;
                    let end = u64::from_str_radix(end, 16)?;
                    while end - offset > overlap {
                        let size = capacity.min(end - offset);
                        let bytes = &mut buffer[..usize::try_from(size)?];
                        memory.read_exact_at(bytes, offset)?;
                        if bytes.windows(CANARY_LEN).any(|candidate| {
                            candidate
                                .iter()
                                .zip(mask)
                                .all(|(byte, masked)| byte ^ CANARY_XOR == *masked)
                        }) {
                            return Ok(true);
                        }
                        // Check windows that cross a read boundary in the same mapping.
                        offset += size - overlap;
                    }
                }
                Ok(false)
            }
        }
    }
}
