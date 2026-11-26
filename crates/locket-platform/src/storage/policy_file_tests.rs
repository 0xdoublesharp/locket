use super::*;

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
    let expected =
        "# local rules\n/target\n.env\n.env.*\n!.env.example\n.locket.local\n.locketignore\n";
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
    assert_eq!(
        fs::read_to_string(&path)?,
        ".env\n.env.*\n!.env.example\n.locket.local\n.locketignore\n"
    );
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
    assert!(fs::read_to_string(&path)?.ends_with(".locketignore\n!.env.example\n"));
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
