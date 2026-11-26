//! Scan command implementation.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use ignore::{WalkBuilder, gitignore::GitignoreBuilder};
use locket_crypto::KeyPurpose;
use locket_scan::{
    EntropyRule, FindingKind, ScanFinding, Severity, SuppressedFinding,
    partition_inline_suppressions_strict, scan_text_with_entropy_rule,
};
use locket_store::AuditWrite;
use serde_json::{Value, json};

use crate::{
    CliError, ResolvedProject, RuntimeContext, ScanArgs, absolutize, collect_known_secret_values,
    git_worktree_required_error, load_project_key, metadata_invalid_error, now_unix_nanos,
    open_store, project_not_found_error, resolve_project, scan_finding_blocked_error,
};

const LOCKETIGNORE_FILE: &str = ".locketignore";

pub fn scan_command(
    context: &RuntimeContext,
    output: &mut impl io::Write,
    args: &ScanArgs,
) -> Result<(), CliError> {
    let project = resolve_project(&context.cwd)?;
    let git_root = if args.staged {
        Some(ensure_git_worktree(project.as_ref().map_or(&context.cwd, |project| &project.root))?)
    } else {
        None
    };
    if args.require_known && project.is_none() {
        return Err(project_not_found_error());
    }
    if args.no_gitignore {
        writeln!(output, "scan: gitignore rules disabled")?;
    }
    let scan_policy = project
        .as_ref()
        .map(|project| read_scan_policy(&project.root.join(crate::LOCKET_TOML)))
        .transpose()?
        .unwrap_or_default();

    let scan_root = args.path.as_deref().map_or_else(
        || project.as_ref().map_or_else(|| context.cwd.clone(), |project| project.root.clone()),
        |path| absolutize(&context.cwd, Path::new(path)),
    );
    let known_values = if args.require_known {
        let project = project.as_ref().ok_or_else(project_not_found_error)?;
        collect_known_secret_values(context, project, now_unix_nanos()?)?
    } else if args.known_if_unlocked {
        known_if_unlocked(context, project.as_ref())?
    } else {
        Vec::new()
    };

    let mut findings = Vec::new();
    let mut suppressed = Vec::new();
    if let Some(git_root) = git_root {
        scan_staged_path(
            &git_root,
            &known_values,
            scan_policy.entropy_rule,
            &mut findings,
            &mut suppressed,
        )?;
    } else {
        scan_path(
            &scan_root,
            &scan_root,
            &known_values,
            scan_policy.entropy_rule,
            !args.no_gitignore,
            &mut findings,
            &mut suppressed,
        )?;
    }
    for finding in &findings {
        writeln!(output, "{}", format_finding_with_policy(finding, scan_policy))?;
    }

    let warning_count = severity_count(&findings, scan_policy, Severity::Warning);
    let blocking_count = severity_count(&findings, scan_policy, Severity::Blocking);
    if findings.is_empty() {
        writeln!(output, "scan: no findings")?;
    } else {
        writeln!(
            output,
            "scan: {} finding(s) (blocking={blocking_count} warning={warning_count})",
            findings.len()
        )?;
    }

    if !suppressed.is_empty() {
        writeln!(output, "scan: {} suppressed finding(s)", suppressed.len())?;
        for finding in &suppressed {
            writeln!(output, "{}", format_suppressed_finding(finding))?;
        }
    }

    if args.require_known {
        writeln!(output, "scan: known-value coverage checked {} value(s)", known_values.len())?;
    }

    if let Some(project) = project.as_ref() {
        if args.known_if_unlocked && !known_values.is_empty() {
            write_known_hook_scan_audit(
                context,
                project,
                if args.staged { "staged" } else { "tree" },
                blocking_count,
                warning_count,
                suppressed.len(),
            )?;
        } else if !suppressed.is_empty() {
            write_scan_suppression_audit(
                context,
                project,
                &suppressed,
                &findings,
                args.staged,
                scan_policy,
            )?;
        }
    }

    if blocking_count > 0 {
        return Err(scan_finding_blocked_error(format!(
            "scan blocked by {blocking_count} finding(s)"
        )));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScanPolicy {
    pub entropy_rule: EntropyRule,
    provider_token_severity: Severity,
    env_file_severity: Severity,
}

impl Default for ScanPolicy {
    fn default() -> Self {
        Self {
            entropy_rule: EntropyRule::default(),
            provider_token_severity: FindingKind::ProviderTokenPattern.default_severity(),
            env_file_severity: FindingKind::EnvFileMarker.default_severity(),
        }
    }
}

impl ScanPolicy {
    const fn severity_for(self, kind: FindingKind) -> Severity {
        match kind {
            FindingKind::ProviderTokenPattern => self.provider_token_severity,
            FindingKind::EnvFileMarker => self.env_file_severity,
            FindingKind::HighEntropy | FindingKind::KnownSecretValue => kind.default_severity(),
        }
    }

    pub const fn provider_token_severity(self) -> Severity {
        self.provider_token_severity
    }

    pub const fn env_file_severity(self) -> Severity {
        self.env_file_severity
    }
}

fn severity_count(findings: &[ScanFinding], policy: ScanPolicy, severity: Severity) -> usize {
    findings.iter().filter(|finding| policy.severity_for(finding.kind) == severity).count()
}

fn format_suppressed_finding(finding: &SuppressedFinding) -> String {
    if finding.reason.is_empty() {
        format!(
            "{}:{}:{}: {} suppressed",
            finding.path_label, finding.line, finding.column, finding.rule_id,
        )
    } else {
        format!(
            "{}:{}:{}: {} suppressed reason={}",
            finding.path_label, finding.line, finding.column, finding.rule_id, finding.reason,
        )
    }
}

fn write_known_hook_scan_audit(
    context: &RuntimeContext,
    project: &ResolvedProject,
    scope: &str,
    blocking: usize,
    warning: usize,
    suppressed: usize,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    let project_id = project.config.project_id.as_str();
    let key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let status = if blocking == 0 { "SUCCESS" } else { "FAILED" };
    let metadata = json!({
        "schema_version": 1, "action": "SCAN", "status": status, "command": "scan",
        "scope": scope, "known_value_coverage": "unlocked", "pattern_only": false,
        "finding_counts": { "blocking": blocking, "warning": warning, "suppressed": suppressed },
    });
    store.append_audit(
        key.as_ref(),
        &AuditWrite {
            project_id,
            profile_id: None,
            action: "SCAN",
            status,
            secret_name: None,
            command: Some("scan"),
            metadata_json: &metadata,
            timestamp: now_unix_nanos()?,
        },
    )?;
    Ok(())
}

fn write_scan_suppression_audit(
    context: &RuntimeContext,
    project: &ResolvedProject,
    suppressed: &[SuppressedFinding],
    kept: &[ScanFinding],
    staged: bool,
    policy: ScanPolicy,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    if store.get_project(project.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key =
        load_project_key(context, &store, project.config.project_id.as_str(), KeyPurpose::Audit)?;

    let entries: Vec<Value> = suppressed
        .iter()
        .map(|finding| {
            json!({
                "path_label": finding.path_label,
                "line": finding.line,
                "column": finding.column,
                "rule_id": finding.rule_id,
                "reason": finding.reason,
                "severity": finding.kind.default_severity().as_str(),
            })
        })
        .collect();

    let metadata = json!({
        "schema_version": 1,
        "action": "SCAN",
        "status": "SUPPRESSED",
        "command": "scan",
        "scope": if staged { "staged" } else { "tree" },
        "suppressed_count": suppressed.len(),
        "suppressions": entries,
        "kept_blocking_count": severity_count(kept, policy, Severity::Blocking),
        "kept_warning_count": severity_count(kept, policy, Severity::Warning),
        "known_value_coverage": "pattern_only",
        "finding_counts": {
            "suppressed": suppressed.len(),
            "blocking": severity_count(kept, policy, Severity::Blocking),
            "warning": severity_count(kept, policy, Severity::Warning),
        },
        "pattern_only": true,
    });
    let audit = AuditWrite {
        project_id: project.config.project_id.as_str(),
        profile_id: None,
        action: "SCAN",
        status: "SUPPRESSED",
        secret_name: None,
        command: Some("scan"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

pub fn scan_path(
    root: &Path,
    path: &Path,
    known_values: &[zeroize::Zeroizing<String>],
    entropy_rule: EntropyRule,
    use_gitignore: bool,
    findings: &mut Vec<ScanFinding>,
    suppressed: &mut Vec<SuppressedFinding>,
) -> Result<(), CliError> {
    let metadata = fs::metadata(path).map_err(|error| {
        io::Error::new(error.kind(), format!("could not scan {}: {error}", path.display()))
    })?;
    if metadata.is_dir() {
        let mut builder = WalkBuilder::new(path);
        builder
            .add_custom_ignore_filename(LOCKETIGNORE_FILE)
            .filter_entry(|entry| !should_skip_scan_path(entry.path()))
            .hidden(false)
            .git_ignore(use_gitignore)
            .git_global(use_gitignore)
            .git_exclude(use_gitignore);
        for entry in builder.build() {
            let entry = entry.map_err(|error| metadata_invalid_error(error.to_string()))?;
            let child = entry.path();
            if child == path || !child.is_file() {
                continue;
            }
            scan_file(root, child, known_values, entropy_rule, findings, suppressed)?;
        }
        return Ok(());
    }

    if metadata.is_file() {
        scan_file(root, path, known_values, entropy_rule, findings, suppressed)
    } else {
        Err(metadata_invalid_error("scan path must be a regular file or directory"))
    }
}

fn scan_file(
    root: &Path,
    path: &Path,
    known_values: &[zeroize::Zeroizing<String>],
    entropy_rule: EntropyRule,
    findings: &mut Vec<ScanFinding>,
    suppressed: &mut Vec<SuppressedFinding>,
) -> Result<(), CliError> {
    if !path.is_file() {
        return Ok(());
    }

    let label = path_label(root, path);
    match fs::read_to_string(path) {
        Ok(text) => {
            let mut file_findings = scan_text_with_entropy_rule(&label, &text, entropy_rule);
            file_findings.extend(scan_known_values(&label, &text, known_values));
            let result = partition_inline_suppressions_strict(&text, file_findings)
                .map_err(|error| metadata_invalid_error(error.to_string()))?;
            findings.extend(result.kept);
            suppressed.extend(result.suppressed);
        }
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            findings.extend(scan_text_with_entropy_rule(&label, "", entropy_rule));
        }
        Err(error) => return Err(error.into()),
    }

    Ok(())
}

fn scan_staged_path(
    git_root: &Path,
    known_values: &[zeroize::Zeroizing<String>],
    entropy_rule: EntropyRule,
    findings: &mut Vec<ScanFinding>,
    suppressed: &mut Vec<SuppressedFinding>,
) -> Result<(), CliError> {
    let locket_ignore = locket_ignore(git_root)?;
    let staged_paths =
        git_output(git_root, ["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT"])?;

    for path_bytes in staged_paths.split(|byte| *byte == 0).filter(|path| !path.is_empty()) {
        let path = String::from_utf8_lossy(path_bytes);
        if locket_ignore.matched_path_or_any_parents(path.as_ref(), false).is_ignore() {
            continue;
        }
        if should_skip_scan_path(Path::new(path.as_ref())) {
            continue;
        }

        scan_git_blob(
            git_root,
            &format!(":{path}"),
            &path,
            known_values,
            entropy_rule,
            findings,
            suppressed,
        )?;
    }
    Ok(())
}

fn scan_git_blob(
    git_root: &Path,
    spec: &str,
    path: &str,
    known_values: &[zeroize::Zeroizing<String>],
    entropy_rule: EntropyRule,
    findings: &mut Vec<ScanFinding>,
    suppressed: &mut Vec<SuppressedFinding>,
) -> Result<(), CliError> {
    let object_type =
        String::from_utf8_lossy(&git_output(git_root, ["cat-file", "-t", spec])?).trim().to_owned();
    if object_type != "blob" {
        return Ok(());
    }

    let contents = zeroize::Zeroizing::new(git_output(git_root, ["cat-file", "-p", spec])?);
    match std::str::from_utf8(&contents) {
        Ok(text) => {
            let mut file_findings = scan_text_with_entropy_rule(path, text, entropy_rule);
            file_findings.extend(scan_known_values(path, text, known_values));
            let result = partition_inline_suppressions_strict(text, file_findings)
                .map_err(|error| metadata_invalid_error(error.to_string()))?;
            findings.extend(result.kept);
            suppressed.extend(result.suppressed);
        }
        Err(_) => findings.extend(scan_text_with_entropy_rule(path, "", entropy_rule)),
    }
    Ok(())
}

fn known_if_unlocked(
    context: &RuntimeContext,
    project: Option<&ResolvedProject>,
) -> Result<Vec<zeroize::Zeroizing<String>>, CliError> {
    let Some(project) = project else { return Ok(Vec::new()) };
    let id = project.config.project_id.as_str();
    if context.master_key_cache.get(id).is_none() {
        let Ok(key) = context.key_store.load_master_key(id) else { return Ok(Vec::new()) };
        context.master_key_cache.insert(id, key, crate::MasterKeySource::OsKeyStore);
    }
    Ok(collect_known_secret_values(context, project, now_unix_nanos()?).unwrap_or_default())
}

pub fn scan_push(
    context: &RuntimeContext,
    output: &mut impl io::Write,
    root: &Path,
    input: &mut impl io::BufRead,
) -> Result<(), CliError> {
    let project = resolve_project(root)?;
    let policy = project
        .as_ref()
        .map(|project| read_scan_policy(&project.root.join(crate::LOCKET_TOML)))
        .transpose()?
        .unwrap_or_default();
    let known_values = known_if_unlocked(context, project.as_ref())?;
    let ignore = locket_ignore(root)?;
    let mut findings = Vec::new();
    let mut suppressed = Vec::new();
    let mut commits = BTreeSet::new();
    for line in io::BufRead::lines(input) {
        let line = line?;
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        let [_, local, _, remote] = fields.as_slice() else {
            return Err(metadata_invalid_error("invalid Git pre-push input"));
        };
        if !valid_oid(local) || !valid_oid(remote) {
            return Err(metadata_invalid_error("invalid Git pre-push object id"));
        }
        if zero_oid(local) {
            continue;
        }
        let mut revisions = vec!["rev-list", *local];
        if !zero_oid(remote) && git_output(root, ["cat-file", "-e", remote]).is_ok() {
            revisions.extend(["--not", remote]);
        }
        for commit in String::from_utf8_lossy(&git_output(root, revisions)?).lines() {
            commits.insert(commit.to_owned());
        }
    }
    for commit in commits {
        let paths = git_output(
            root,
            [
                "diff-tree",
                "--root",
                "-m",
                "-r",
                "--no-commit-id",
                "--name-only",
                "-z",
                "--diff-filter=ACMRT",
                &commit,
            ],
        )?;
        for path in paths.split(|byte| *byte == 0).filter(|path| !path.is_empty()) {
            let path = String::from_utf8_lossy(path);
            if ignore.matched_path_or_any_parents(path.as_ref(), false).is_ignore()
                || should_skip_scan_path(Path::new(path.as_ref()))
            {
                continue;
            }
            scan_git_blob(
                root,
                &format!("{commit}:{path}"),
                &path,
                &known_values,
                policy.entropy_rule,
                &mut findings,
                &mut suppressed,
            )?;
        }
    }
    for finding in &findings {
        writeln!(output, "{}", format_finding_with_policy(finding, policy))?;
    }
    let blocking = severity_count(&findings, policy, Severity::Blocking);
    if let Some(project) = project.as_ref().filter(|_| !known_values.is_empty()) {
        write_known_hook_scan_audit(
            context,
            project,
            "pre-push",
            blocking,
            severity_count(&findings, policy, Severity::Warning),
            suppressed.len(),
        )?;
    }
    if blocking > 0 {
        return Err(scan_finding_blocked_error(format!("push blocked by {blocking} finding(s)")));
    }
    writeln!(output, "push scan: {} finding(s)", findings.len())?;
    Ok(())
}

fn valid_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64) && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn zero_oid(oid: &str) -> bool {
    oid.bytes().all(|byte| byte == b'0')
}

pub fn read_scan_entropy_rule(path: &Path) -> Result<EntropyRule, CliError> {
    read_scan_policy(path).map(|policy| policy.entropy_rule)
}

pub fn read_scan_policy(path: &Path) -> Result<ScanPolicy, CliError> {
    let content = fs::read_to_string(path)?;
    let document = toml::from_str::<toml::Value>(&content)?;
    let Some(scan) = document.get("scan") else {
        return Ok(ScanPolicy::default());
    };
    let scan = scan.as_table().ok_or_else(|| metadata_invalid_error("scan must be a table"))?;
    let mut policy = ScanPolicy::default();
    if let Some(high_entropy) = scan.get("high_entropy") {
        let high_entropy = high_entropy
            .as_table()
            .ok_or_else(|| metadata_invalid_error("scan.high_entropy must be a table"))?;
        if let Some(value) = high_entropy.get("min_length") {
            policy.entropy_rule.min_len = parse_entropy_min_length(value)?;
        }
        if let Some(value) = high_entropy.get("entropy_threshold") {
            policy.entropy_rule.threshold = parse_entropy_threshold(value)?;
        }
    }
    if let Some(severity) = scan.get("severity") {
        let severity = severity
            .as_table()
            .ok_or_else(|| metadata_invalid_error("scan.severity must be a table"))?;
        if let Some(value) = severity.get("provider_token") {
            policy.provider_token_severity =
                parse_scan_severity(value, "scan.severity.provider_token")?;
        }
    }
    if let Some(env) = scan.get("env") {
        let env =
            env.as_table().ok_or_else(|| metadata_invalid_error("scan.env must be a table"))?;
        if let Some(value) = env.get("severity") {
            policy.env_file_severity = parse_scan_severity(value, "scan.env.severity")?;
        }
    }
    Ok(policy)
}

fn parse_entropy_min_length(value: &toml::Value) -> Result<usize, CliError> {
    let Some(raw) = value.as_integer() else {
        return Err(metadata_invalid_error("scan.high_entropy.min_length must be an integer"));
    };
    usize::try_from(raw)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| metadata_invalid_error("scan.high_entropy.min_length must be positive"))
}

#[allow(clippy::cast_precision_loss)]
fn parse_entropy_threshold(value: &toml::Value) -> Result<f64, CliError> {
    let threshold =
        value.as_float().or_else(|| value.as_integer().map(|integer| integer as f64)).ok_or_else(
            || metadata_invalid_error("scan.high_entropy.entropy_threshold must be a number"),
        )?;
    if threshold.is_finite() && threshold >= 0.0 {
        Ok(threshold)
    } else {
        Err(metadata_invalid_error(
            "scan.high_entropy.entropy_threshold must be finite and non-negative",
        ))
    }
}

fn parse_scan_severity(value: &toml::Value, path: &str) -> Result<Severity, CliError> {
    match value.as_str() {
        Some("warning") => Ok(Severity::Warning),
        Some("blocking") => Ok(Severity::Blocking),
        _ => Err(metadata_invalid_error(format!("{path} must be \"warning\" or \"blocking\""))),
    }
}

fn locket_ignore(git_root: &Path) -> Result<ignore::gitignore::Gitignore, CliError> {
    let mut builder = GitignoreBuilder::new(git_root);
    let path = git_root.join(LOCKETIGNORE_FILE);
    if path.exists()
        && let Some(error) = builder.add(path)
    {
        return Err(metadata_invalid_error(error.to_string()));
    }
    builder.build().map_err(|error| metadata_invalid_error(error.to_string()))
}

fn scan_known_values(
    path_label: &str,
    text: &str,
    known_values: &[zeroize::Zeroizing<String>],
) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    for known_value in known_values {
        if known_value.is_empty() {
            continue;
        }
        let mut cursor = 0;
        let mut position_cursor = 0;
        let (mut line, mut column) = (1, 1);
        while let Some(relative) = text[cursor..].find(known_value.as_str()) {
            let start = cursor + relative;
            // Matches are ordered. Count each prefix character only once,
            // including newlines inside the preceding matched value.
            for character in text[position_cursor..start].chars() {
                if character == '\n' {
                    line += 1;
                    column = 1;
                } else {
                    column += 1;
                }
            }
            position_cursor = start;
            findings.push(ScanFinding {
                path_label: path_label.to_owned(),
                line,
                column,
                token_length: known_value.len(),
                kind: FindingKind::KnownSecretValue,
            });
            cursor = start + known_value.len();
        }
    }
    findings
}

fn should_skip_scan_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, ".git" | ".locket" | "target"))
}

fn path_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .filter(|relative| !relative.as_os_str().is_empty())
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

fn format_finding_with_policy(finding: &ScanFinding, policy: ScanPolicy) -> String {
    format!(
        "{}:{}:{}: [{}] {} token_length={}",
        finding.path_label,
        finding.line,
        finding.column,
        policy.severity_for(finding.kind).as_str(),
        finding_kind_label(finding.kind),
        finding.token_length
    )
}

const fn finding_kind_label(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::HighEntropy => "high-entropy",
        FindingKind::ProviderTokenPattern => "provider-token-pattern",
        FindingKind::EnvFileMarker => "env-file",
        FindingKind::KnownSecretValue => "known-secret",
    }
}

pub fn ensure_git_worktree(start: &Path) -> Result<PathBuf, CliError> {
    let mut current = start.canonicalize()?;
    loop {
        if current.join(".git").exists() {
            return Ok(current);
        }
        if !current.pop() {
            return Err(git_worktree_required_error("git worktree required for --staged"));
        }
    }
}

pub fn git_output<I, S>(git_root: &Path, args: I) -> Result<Vec<u8>, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = ProcessCommand::new("git").arg("-C").arg(git_root).args(args).output()?;
    if output.status.success() {
        return Ok(output.stdout);
    }

    let message = String::from_utf8_lossy(&output.stderr);
    Err(metadata_invalid_error(format!("git command failed: {}", message.trim())))
}

#[cfg(test)]
mod tests {
    use super::scan_known_values;
    use locket_scan::FindingKind;
    use zeroize::Zeroizing;

    #[test]
    fn known_matches_preserve_unicode_columns_and_multiline_values() {
        let values = [Zeroizing::new(String::new()), Zeroizing::new("a\nb".to_owned())];
        let matches = scan_known_values("sample.txt", "é🦀:a\nb;a\nb\r\na\nb", &values);
        assert_eq!(
            matches.iter().map(|finding| (finding.line, finding.column)).collect::<Vec<_>>(),
            [(1, 4), (2, 3), (4, 1)]
        );
        for finding in matches {
            assert_eq!(finding.path_label, "sample.txt");
            assert_eq!(finding.token_length, 3);
            assert_eq!(finding.kind, FindingKind::KnownSecretValue);
        }
    }

    #[test]
    fn dense_known_matches_report_every_position() {
        let record = "é:test-value,";
        let count = 10_000;
        let text = record.repeat(count);
        let values = [Zeroizing::new("test-value".to_owned())];
        let matches = scan_known_values("dense.txt", &text, &values);
        assert_eq!(matches.len(), count);
        for (index, finding) in matches.iter().enumerate() {
            assert_eq!(finding.line, 1);
            assert_eq!(finding.column, index * record.chars().count() + 3);
            assert_eq!(finding.token_length, "test-value".len());
        }
    }
}
