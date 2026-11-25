//! CLI conformance for `DotenvMetadataNonInterference.lean` and store/backup crypto boundaries.
#![allow(unused_crate_dependencies, clippy::multiple_crate_versions)]

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix_conformance {
    use std::error::Error;
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use data_encoding::BASE64URL_NOPAD;
    use locket_core::{
        BundleContainer, LocketError, ProfileId, ProfileName, ProjectConfig, ProjectId,
        bundle::decrypt_bundle_payload_with_x25519_secret_zeroizing,
        invite::{device_fingerprint_v1, fingerprint_hex},
    };
    use locket_crypto::{
        HkdfWrapInfo, KeyPurpose, KeyWrapAad, derive_wrapping_key_v1, key_wrap_aad_v1,
        wrap_key_material_v1,
    };
    use locket_platform::PassphraseFallbackMasterKeyStore;
    use locket_store::{AuditWrite, KeyRecord, Store, StoreError};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    const PASSPHRASE: &str = "test-only conformance passphrase";
    const CANARIES: [&str; 4] =
        ["LEAK-CANARY-A", "LEAK-CANARY-B", "LEAK-CANARY-C", "LEAK-CANARY-D"];
    const DOTENV_A: &str = r#"ACCESS=LEAK-CANARY-A
CREATE=''
CREATE="LEAK-CANARY-B # quoted"
EXCLUDED=LEAK-CANARY-C
IGNORED=x
"#;
    const DOTENV_B: &str = r#"ACCESS='LEAK-CANARY-D # literal'
CREATE=short
CREATE="🦀\nline2=embedded"
EXCLUDED=""
IGNORED='long value ; # equals=sign'
"#;

    fn locket_command(program: &str, home: &Path, project: &Path) -> Command {
        let mut command = Command::new(program);
        command
            .current_dir(project)
            .env("HOME", home)
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_RUNTIME_DIR", home)
            .env("LOCKET_INSTANCE", "dev")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null());
        command
    }

    fn metadata(home: &Path, project: &Path, args: &[&str]) -> Result<Vec<u8>, Box<dyn Error>> {
        let output =
            locket_command(env!("CARGO_BIN_EXE_locket"), home, project).args(args).output()?;
        assert!(output.status.success(), "{args:?}: {output:?}");
        assert_eq!(output.stderr, b"", "{args:?}: {output:?}");
        assert_canaries_absent(&output.stdout);
        Ok(output.stdout)
    }

    fn assert_canaries_absent(output: &[u8]) {
        let text = String::from_utf8_lossy(output);
        for canary in CANARIES {
            assert!(!text.contains(canary), "metadata included a dotenv value");
        }
    }

    #[test]
    fn env_keys_and_scan_are_byte_identical_after_replacing_values() -> Result<(), Box<dyn Error>> {
        let home = tempfile::tempdir()?;
        let workspace = tempfile::tempdir()?;
        let root = workspace.path();
        for repo in ["client", "server"] {
            fs::create_dir_all(root.join(repo).join(".git"))?;
        }
        let keys = ["env", "keys", "client/.env", "--json"];
        let scan = ["env", "scan", "--json"];
        let write_values = |client: &str, server: &str| -> std::io::Result<()> {
            fs::write(root.join("client/.env"), client)?;
            fs::write(root.join("server/.env"), server)?;
            Ok(())
        };
        write_values(DOTENV_A, DOTENV_B)?;
        let key_report = metadata(home.path(), root, &keys)?;
        let scan_report = metadata(home.path(), root, &scan)?;
        write_values(DOTENV_B, DOTENV_A)?;
        assert_eq!(metadata(home.path(), root, &keys)?, key_report);
        assert_eq!(metadata(home.path(), root, &scan)?, scan_report);

        let key_report: Value = serde_json::from_slice(&key_report)?;
        assert_eq!(key_report["metadata_only"], true);
        assert_eq!(key_report["keys"], json!(["ACCESS", "CREATE", "EXCLUDED", "IGNORED"]));
        assert_eq!(key_report["warnings"][0]["line"], 3);
        assert_eq!(key_report["invalid"], 0);
        let scan_report: Value = serde_json::from_slice(&scan_report)?;
        assert_eq!(scan_report["metadata_only"], true);
        assert_eq!(scan_report["total_files"], 2);
        assert_eq!(scan_report["total_keys"], 8);
        let shared =
            scan_report["shared_candidates"].as_array().ok_or("missing shared candidates")?;
        assert_eq!(
            shared.iter().map(|entry| entry["key"].as_str()).collect::<Vec<_>>(),
            [Some("ACCESS"), Some("CREATE"), Some("EXCLUDED"), Some("IGNORED")]
        );
        assert_eq!(shared[0]["projects"].as_array().ok_or("missing project roots")?.len(), 2);
        assert_eq!(fs::read_dir(home.path())?.count(), 0);
        Ok(())
    }

    struct VaultFixture {
        directory: tempfile::TempDir,
        data_dir: PathBuf,
        project_id: ProjectId,
    }

    impl VaultFixture {
        fn new() -> Result<Self, Box<dyn Error>> {
            let directory = tempfile::tempdir()?;
            let home = directory.path();
            #[cfg(target_os = "linux")]
            let data_dir = home.join("data/locketdev");
            #[cfg(target_os = "macos")]
            let data_dir = home.join("Library/Application Support/dev.0xdoublesharp.Locket-Dev");
            fs::create_dir_all(&data_dir)?;
            fs::create_dir(home.join("project"))?;
            let fixture = Self { directory, data_dir, project_id: ProjectId::generate()? };
            fixture.initialize()?;
            Ok(fixture)
        }

        fn project(&self) -> PathBuf {
            self.directory.path().join("project")
        }

        fn store_path(&self) -> PathBuf {
            self.data_dir.join("store.db")
        }

        fn initialize(&self) -> Result<(), Box<dyn Error>> {
            let project = self.project();
            let config = ProjectConfig::new(
                self.project_id.clone(),
                "conformance".into(),
                ProfileName::new("dev")?,
            );
            fs::write(project.join("locket.toml"), toml::to_string(&config)?)?;
            let id = self.project_id.as_str();
            let profile = ProfileId::generate()?;
            let mut store = Store::open(self.store_path())?;
            store.initialize_schema()?;
            store.insert_project_if_absent(id, "conformance", 0)?;
            store.insert_profile_if_absent(profile.as_str(), id, "dev", false, 0)?;
            let canonical = project.canonicalize()?;
            let canonical = canonical.to_str().ok_or("non-UTF-8 fixture path")?;
            store.trust_project_root(id, &Sha256::digest(canonical).into(), Some(canonical), 0)?;

            let master = [21; 32];
            PassphraseFallbackMasterKeyStore::new(self.data_dir.join("passphrase-fallback"))
                .store_master_key(id, &master, PASSPHRASE.as_bytes(), 0)?;
            for (purpose, scope) in [
                (KeyPurpose::Audit, None),
                (KeyPurpose::ProfileSecret, Some(profile.as_str())),
                (KeyPurpose::ProfileFingerprint, Some(profile.as_str())),
            ] {
                let key = locket_core::KeyId::generate()?;
                let wrap = derive_wrapping_key_v1(&master, &HkdfWrapInfo::new(id, scope, purpose))?;
                let aad =
                    key_wrap_aad_v1(&KeyWrapAad::new(id, key.as_str(), scope, 0, purpose.into()))?;
                let wrapped = wrap_key_material_v1(&wrap, &[42; 32], &aad)?;
                store.insert_key(&KeyRecord {
                    id: key.into_string(),
                    project_id: id.into(),
                    profile_id: scope.map(str::to_owned),
                    purpose: purpose.as_str().into(),
                    wrapped_material: wrapped.ciphertext,
                    nonce: wrapped.nonce,
                    created_at: 0,
                })?;
            }
            Ok(())
        }

        fn live(&self, args: &[&str]) -> Result<Vec<u8>, Box<dyn Error>> {
            // The fallback deliberately requires a TTY. Isolate the vault without writing
            // a test key to the host keychain or changing the user's agent.
            let mut command = locket_command("script", self.directory.path(), &self.project());
            #[cfg(target_os = "macos")]
            command.args(["-q", "/dev/null", env!("CARGO_BIN_EXE_locket")]).args(args);
            #[cfg(target_os = "linux")]
            {
                let invocation = std::iter::once(env!("CARGO_BIN_EXE_locket"))
                    .chain(args.iter().copied())
                    .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
                    .collect::<Vec<_>>()
                    .join(" ");
                command.args(["-q", "-e", "-c", &invocation, "/dev/null"]);
            }
            let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
            let mut input = child.stdin.take().ok_or("missing terminal input")?;
            let mut reader = BufReader::new(child.stdout.take().ok_or("missing terminal output")?);
            let mut output = Vec::new();
            while reader.read_until(b' ', &mut output)? > 0 {
                if output.ends_with(b"locket passphrase: ") {
                    writeln!(input, "{PASSPHRASE}")?;
                    break;
                }
            }
            reader.read_to_end(&mut output)?;
            assert!(child.wait()?.success(), "{args:?}: {}", String::from_utf8_lossy(&output));
            assert_canaries_absent(&output);
            Ok(output)
        }
    }

    fn live_json(vault: &VaultFixture, args: &[&str]) -> Result<Value, Box<dyn Error>> {
        let output = vault.live(args)?;
        let json = output
            .split(|byte| *byte == b'\n')
            .find(|line| line.starts_with(b"{"))
            .ok_or("missing CLI JSON report")?;
        Ok(serde_json::from_slice(json)?)
    }

    #[test]
    fn dry_run_is_value_independent_and_matches_the_live_partition() -> Result<(), Box<dyn Error>> {
        for overwrite in [false, true] {
            let vault = VaultFixture::new()?;
            let home = vault.directory.path();
            let project = vault.project();
            let path = project.join(".env");
            fs::write(project.join(".env.seed"), "ACCESS=original\n")?;
            let seed = live_json(&vault, &["import", ".env.seed", "--json"])?;
            assert_eq!(seed["imported_names"], json!(["ACCESS"]));

            let mut args = vec![
                "import",
                ".env",
                "--only",
                "ACCESS,CREATE,EXCLUDED,MISSING",
                "--exclude",
                "EXCLUDED",
                "--json",
            ];
            if overwrite {
                args.push("--overwrite");
            }
            let mut plan_args = args.clone();
            plan_args.push("--dry-run");
            let database = fs::read(vault.store_path())?;
            fs::write(&path, DOTENV_A)?;
            let first = metadata(home, &project, &plan_args)?;
            fs::write(&path, DOTENV_B)?;
            assert_eq!(metadata(home, &project, &plan_args)?, first);
            assert_eq!(fs::read(vault.store_path())?, database, "dry run changed the store");
            assert!(fs::read(&path)? == DOTENV_B.as_bytes(), "dry run changed the dotenv file");

            let plan: Value = serde_json::from_slice(&first)?;
            assert_eq!(plan["env_names"], json!(["ACCESS", "CREATE"]));
            assert_eq!(plan["filtered_out_names"], json!(["EXCLUDED", "IGNORED"]));
            assert_eq!(plan["imported_names"], json!(["CREATE"]));
            let (changed, unchanged) =
                if overwrite { ("overwritten", "skipped") } else { ("skipped", "overwritten") };
            assert_eq!(plan[format!("{changed}_names")], json!(["ACCESS"]));
            assert_eq!(plan[format!("{unchanged}_names")], json!([]));

            let live = live_json(&vault, &args)?;
            assert_eq!(plan["dry_run"], true);
            assert_eq!(live["dry_run"], false);
            for field in [
                "env_names",
                "filtered_out",
                "filtered_out_names",
                "imported",
                "imported_names",
                "overwritten",
                "overwritten_names",
                "skipped",
                "skipped_names",
            ] {
                assert_eq!(live[field], plan[field], "{field}, overwrite={overwrite}");
            }
            assert_eq!(live["missing_in_profile"], json!([]));
        }
        Ok(())
    }

    #[test]
    fn audit_write_and_verify_reject_every_sampled_noncanonical_key_length()
    -> Result<(), Box<dyn Error>> {
        let mut store = Store::open(":memory:")?;
        store.initialize_schema()?;
        let project = "lk_proj_audit_conformance";
        store.insert_project_if_absent(project, "audit", 0)?;
        let audit = AuditWrite {
            project_id: project,
            profile_id: None,
            action: "DOCTOR",
            status: "SUCCESS",
            secret_name: None,
            command: None,
            metadata_json: &json!({
                "schema_version": 1, "action": "DOCTOR", "status": "SUCCESS", "check_names": ["audit"]
            }),
            timestamp: 1,
        };
        let malformed = AuditWrite { metadata_json: &json!({}), ..audit };
        let bytes = [42_u8; 65];
        for length in (0..=bytes.len()).filter(|length| *length != 32) {
            let key = &bytes[..length];
            assert!(
                matches!(store.append_audit(key, &audit), Err(StoreError::InvalidAuditKeyLength { actual }) if actual == length)
            );
            assert!(
                matches!(store.verify_audit_chain_read_only(project, key), Err(StoreError::InvalidAuditKeyLength { actual }) if actual == length)
            );
            assert!(matches!(
                store.append_audit(key, &malformed),
                Err(StoreError::AuditMetadataInvalid { .. })
            ));
        }
        let key = &bytes[..32];
        assert_eq!(store.verify_audit_chain_read_only(project, key)?.rows_verified, 0);
        store.append_audit(key, &audit)?;
        let verification = store.verify_audit_chain_read_only(project, key)?;
        assert!(verification.hmac_ok);
        assert_eq!(verification.rows_verified, 1);
        Ok(())
    }

    #[test]
    fn effective_command_rejects_a_public_default_denied_by_the_secret_acl()
    -> Result<(), Box<dyn Error>> {
        let vault = VaultFixture::new()?;
        let project = vault.project();
        let config = project.join("locket.toml");
        let mut document = fs::read_to_string(&config)?;
        document.push_str(
            r#"
        [commands.run]
        argv = ["/usr/bin/true"]
        [paths.app]
        required_secrets = ["FEATURE"]
        [secrets.FEATURE]
        allow_paths = ["app/allowed/**"]
        [variables.FEATURE]
        classification = "public"
        default = "commit-safe"
        "#,
        );
        fs::write(config, document)?;
        let invoke = |relative: &str| -> Result<_, std::io::Error> {
            let directory = project.join(relative);
            fs::create_dir_all(&directory)?;
            locket_command(env!("CARGO_BIN_EXE_locket"), vault.directory.path(), &directory)
                .args(["env", "inspect", "--policy", "run"])
                .output()
        };
        let denied = invoke("app/denied")?;
        assert_eq!(denied.status.code(), Some(i32::from(LocketError::InvalidPolicy.exit_code())));
        assert!(
            String::from_utf8(denied.stderr)?
                .contains("secret ACL denied command run for: FEATURE")
        );
        let allowed = invoke("app/allowed/sub")?;
        assert!(allowed.status.success(), "{allowed:?}");
        assert!(
            String::from_utf8(allowed.stdout)?
                .contains("FEATURE state=Ready source=public-default")
        );
        Ok(())
    }

    #[test]
    fn exported_backup_authenticates_its_audit_chain_under_the_lean_domain()
    -> Result<(), Box<dyn Error>> {
        let vault = VaultFixture::new()?;
        fs::write(vault.project().join(".env"), DOTENV_A)?;
        live_json(&vault, &["import", ".env", "--json"])?;

        let signing = ed25519_dalek::SigningKey::from_bytes(&[23; 32]).verifying_key().to_bytes();
        let recipient = x25519_dalek::StaticSecret::from([24; 32]);
        let sealing = x25519_dalek::PublicKey::from(&recipient).to_bytes();
        let descriptor = json!({
            "v": 2, "device_id": "lk_dev_conformance", "label": "recipient",
            "signing_public_key_ed25519": BASE64URL_NOPAD.encode(&signing),
            "sealing_public_key_x25519": BASE64URL_NOPAD.encode(&sealing),
            "fingerprint_sha256": fingerprint_hex(&device_fingerprint_v1(&signing, &sealing)),
            "safety_words": [],
        });
        let descriptor =
            format!("lkdev2_{}", BASE64URL_NOPAD.encode(&serde_json::to_vec(&descriptor)?));
        vault.live(&[
            "export",
            "--sealed",
            "--include-personal",
            "--include-audit",
            "--recipient",
            &descriptor,
            "--output",
            "proof.locket-bundle",
        ])?;
        let bundle =
            BundleContainer::deserialize(&fs::read(vault.project().join("proof.locket-bundle"))?)?;
        let plaintext = decrypt_bundle_payload_with_x25519_secret_zeroizing(
            &bundle.encrypted_payload,
            recipient.as_bytes(),
        )?;
        let payload: Value = serde_json::from_slice(&plaintext)?;
        let chain = &payload["audit_chain"];
        let bytes = |field: &str| -> Result<Vec<u8>, Box<dyn Error>> {
            Ok(BASE64URL_NOPAD
                .decode(chain[field].as_str().ok_or("missing audit chain bytes")?.as_bytes())?)
        };
        let schema =
            u16::try_from(chain["aad_schema_version"].as_u64().ok_or("missing AAD schema")?)?;
        let sequence =
            chain["checkpoint_sequence"].as_u64().ok_or("missing checkpoint sequence")?;
        let aad = [
            b"locket-bundle-audit-chain-v1\0".as_slice(),
            &schema.to_le_bytes(),
            &bundle.manifest.schema_version.to_le_bytes(),
            &sequence.to_le_bytes(),
            &bytes("checkpoint_hmac_b64")?,
        ]
        .concat();
        let nonce =
            XNonce::try_from(bytes("nonce_b64")?.as_slice()).map_err(|_| "wrong nonce length")?;
        let cipher = XChaCha20Poly1305::new_from_slice(&bytes("encryption_key_b64")?)
            .map_err(|_| "wrong key length")?;
        let ciphertext = bytes("encrypted_rows_b64")?;
        let rows = cipher
            .decrypt(&nonce, Payload { msg: &ciphertext, aad: &aad })
            .map_err(|_| "backup audit chain did not authenticate with the Lean domain")?;
        let rows: Vec<Value> = serde_json::from_slice(&rows)?;
        assert_eq!(rows.last().ok_or("empty exported audit chain")?["sequence"], sequence);
        Ok(())
    }
}
