use super::*;
use std::process::{Command, Output};

const PROTECTION: &str = ".env\n.env.*\n.locket.local\n.locketignore\n";
const EXCEPTIONS: &str = concat!(
    "!.env.example\n!.env.sample\n!.env.template\n!.env.dist\n!.env.defaults\n",
    "!.env.*.example\n!.env.*.sample\n!.env.*.template\n",
);

#[test]
fn ignore_rules_append_missing_patterns_and_preserve_existing_lines() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join(".gitignore");
    fs::write(&path, "# local rules\n/target\n.env\n.env.*")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
    }

    ensure_secret_file_ignores(root.path())?;
    let expected = format!("# local rules\n/target\n{PROTECTION}{EXCEPTIONS}");
    assert_eq!(fs::read_to_string(&path)?, expected);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o640);
        let before = File::open(&path)?;
        ensure_secret_file_ignores(root.path())?;
        assert!(same_file(&before, &File::open(&path)?)?);
    }
    assert_eq!(fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn ignore_rules_create_file_and_reject_nonregular_destination() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join(".gitignore");
    ensure_secret_file_ignores(root.path())?;
    assert_eq!(fs::read_to_string(&path)?, format!("{PROTECTION}{EXCEPTIONS}"));
    fs::remove_file(&path)?;
    fs::create_dir(&path)?;
    assert!(ensure_secret_file_ignores(root.path()).is_err());
    assert!(path.is_dir());
    Ok(())
}

#[test]
fn ignore_rules_restore_an_exception_shadowed_by_the_wildcard() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join(".gitignore");
    fs::write(&path, "!.env.example\n.env.*\n.env\n.locket.local\n.locketignore\n")?;
    ensure_secret_file_ignores(root.path())?;
    assert!(fs::read_to_string(&path)?.ends_with(EXCEPTIONS));
    Ok(())
}

#[test]
fn ignore_rules_inherit_tracked_protection_without_creating_a_package_file() -> std::io::Result<()>
{
    let (repo, package) = git_package()?;
    let contents = format!("{PROTECTION}{EXCEPTIONS}");
    fs::write(repo.path().join(".gitignore"), &contents)?;
    git_ok(repo.path(), &["add", "--", ".gitignore"])?;
    ensure_secret_file_ignores(&package)?;
    assert!(!package.join(".gitignore").exists());
    assert_eq!(fs::read_to_string(repo.path().join(".gitignore"))?, contents);
    Ok(())
}

#[test]
fn ignore_rules_reject_untracked_and_repository_private_protection() -> std::io::Result<()> {
    for (source, original) in [
        (".gitignore", format!("{PROTECTION}{EXCEPTIONS}")),
        (".git/info/exclude", ".env\n".to_owned()),
    ] {
        let (repo, package) = git_package()?;
        fs::write(repo.path().join(source), original)?;
        ensure_secret_file_ignores(&package)?;
        assert_eq!(
            fs::read_to_string(package.join(".gitignore"))?,
            format!("{PROTECTION}{EXCEPTIONS}"),
        );
        ensure_secret_file_ignores(&package)?;
        assert_eq!(
            fs::read_to_string(package.join(".gitignore"))?,
            format!("{PROTECTION}{EXCEPTIONS}"),
        );
    }
    Ok(())
}

#[test]
fn ignore_rules_reject_global_excludes_even_with_a_tracked_gitignore_name() -> std::io::Result<()> {
    let (repo, package) = git_package()?;
    fs::write(package.join(".gitignore"), "/packages/nested/app/.env\n")?;
    git_ok(repo.path(), &["add", "--", "packages/nested/app/.gitignore"])?;
    git_ok(repo.path(), &["config", "core.excludesFile", "packages/nested/app/.gitignore"])?;
    git_ok(repo.path(), &["check-ignore", "--quiet", "--", "packages/nested/app/.env"])?;

    ensure_secret_file_ignores(&package)?;
    assert_eq!(
        fs::read_to_string(package.join(".gitignore"))?,
        format!("/packages/nested/app/.env\n{PROTECTION}{EXCEPTIONS}"),
    );
    Ok(())
}

#[test]
fn ignore_rules_require_the_gitignore_path_itself_to_be_tracked() -> std::io::Result<()> {
    let (repo, package) = git_package()?;
    let path = repo.path().join(".gitignore");
    fs::create_dir(&path)?;
    fs::write(path.join("tracked"), "")?;
    git_ok(repo.path(), &["add", "--", ".gitignore/tracked"])?;
    fs::remove_file(path.join("tracked"))?;
    fs::remove_dir(&path)?;
    fs::write(path, format!("{PROTECTION}{EXCEPTIONS}"))?;

    ensure_secret_file_ignores(&package)?;
    assert_eq!(
        fs::read_to_string(package.join(".gitignore"))?,
        format!("{PROTECTION}{EXCEPTIONS}"),
    );
    Ok(())
}

#[test]
fn ignore_rules_add_only_missing_protection_and_keep_templates_visible() -> std::io::Result<()> {
    let (repo, package) = git_package()?;
    fs::write(repo.path().join(".gitignore"), ".env\n")?;
    git_ok(repo.path(), &["add", "--", ".gitignore"])?;
    ensure_secret_file_ignores(&package)?;
    assert_eq!(
        fs::read_to_string(package.join(".gitignore"))?,
        format!(".env.*\n.locket.local\n.locketignore\n{EXCEPTIONS}"),
    );
    let ignored = git_ok(&package, &["check-ignore", "--", ".env.local", ".env.production"])?;
    assert_eq!(String::from_utf8_lossy(&ignored.stdout), ".env.local\n.env.production\n");
    for template in [
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.dist",
        ".env.defaults",
        ".env.local.example",
        ".env.local.sample",
        ".env.local.template",
    ] {
        let output = git(&package, &["check-ignore", "--quiet", "--", template])?;
        assert_eq!(output.status.code(), Some(1), "{template}");
    }
    Ok(())
}

#[test]
fn ignore_rules_add_only_exceptions_shadowed_by_tracked_rules() -> std::io::Result<()> {
    let (repo, package) = git_package()?;
    fs::write(repo.path().join(".gitignore"), format!("{PROTECTION}{EXCEPTIONS}.env.sample\n"))?;
    git_ok(repo.path(), &["add", "--", ".gitignore"])?;
    ensure_secret_file_ignores(&package)?;
    assert_eq!(fs::read_to_string(package.join(".gitignore"))?, "!.env.sample\n");
    Ok(())
}

#[test]
fn ignore_rules_replace_a_negated_match_with_positive_protection() -> std::io::Result<()> {
    let (repo, package) = git_package()?;
    fs::write(repo.path().join(".gitignore"), format!("{PROTECTION}{EXCEPTIONS}"))?;
    git_ok(repo.path(), &["add", "--", ".gitignore"])?;
    fs::write(package.join(".gitignore"), ".env\n!.env\n")?;
    ensure_secret_file_ignores(&package)?;
    assert_eq!(fs::read_to_string(package.join(".gitignore"))?, ".env\n!.env\n.env\n");
    Ok(())
}

#[test]
fn ignore_rules_stay_idempotent_when_git_cannot_read_the_package_rules() -> std::io::Result<()> {
    let (repo, package) = git_package()?;
    fs::write(repo.path().join(".git/info/exclude"), "/packages/\n")?;
    ensure_secret_file_ignores(&package)?;
    ensure_secret_file_ignores(&package)?;
    assert_eq!(
        fs::read_to_string(package.join(".gitignore"))?,
        format!("{PROTECTION}{EXCEPTIONS}"),
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn ignore_rules_refuse_symlinks_without_modifying_target() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    let target = root.path().join("original");
    fs::write(&target, "untouched")?;
    let path = root.path().join(".gitignore");
    std::os::unix::fs::symlink(&target, &path)?;
    assert!(ensure_secret_file_ignores(root.path()).is_err());
    assert_eq!(fs::read_to_string(&target)?, "untouched");
    assert_eq!(fs::read_link(&path)?, target);
    Ok(())
}

#[test]
fn missing_secret_file_ignores_reflects_tracked_parent_coverage() -> std::io::Result<()> {
    let (repo, package) = git_package()?;
    fs::write(repo.path().join(".gitignore"), format!("{PROTECTION}{EXCEPTIONS}"))?;
    // Untracked parent .gitignore must not satisfy coverage.
    assert_ne!(missing_secret_file_ignores(&package)?, [] as [&str; 0]);

    git_ok(repo.path(), &["add", ".gitignore"])?;
    // Tracked parent .gitignore satisfies all required entries without a subpackage file.
    assert_eq!(missing_secret_file_ignores(&package)?, [] as [&str; 0]);
    assert!(!package.join(".gitignore").exists());
    Ok(())
}

fn git_package() -> std::io::Result<(tempfile::TempDir, PathBuf)> {
    let repo = tempfile::tempdir()?;
    git_ok(repo.path(), &["init", "-q"])?;
    git_ok(repo.path(), &["config", "core.excludesFile", ""])?;
    let package = repo.path().join("packages/nested/app");
    fs::create_dir_all(&package)?;
    Ok((repo, package))
}

fn git(directory: &Path, args: &[&str]) -> std::io::Result<Output> {
    Command::new("git").arg("-C").arg(directory).args(args).output()
}

fn git_ok(directory: &Path, args: &[&str]) -> std::io::Result<Output> {
    let output = git(directory, args)?;
    assert!(output.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&output.stderr));
    Ok(output)
}
