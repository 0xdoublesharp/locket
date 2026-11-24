//! User-scoped macOS LaunchAgent configuration for the next login.

use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

use locket_platform::LocketInstance;

pub(crate) struct LaunchAgent {
    path: PathBuf,
    instance: LocketInstance,
}

impl LaunchAgent {
    #[cfg(target_os = "macos")]
    pub(crate) fn current() -> Result<Self, String> {
        let home = directories::BaseDirs::new()
            .ok_or_else(|| "Cannot locate the home directory.".to_owned())?;
        Ok(Self::new(home.home_dir(), LocketInstance::current()))
    }

    fn new(home: &Path, instance: LocketInstance) -> Self {
        Self {
            path: home.join("Library/LaunchAgents").join(format!("{}.plist", label(instance))),
            instance,
        }
    }

    pub(crate) fn enabled(&self) -> io::Result<bool> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.is_file() => Ok(true),
            Ok(_) => Err(io::Error::new(
                ErrorKind::InvalidData,
                "LaunchAgent path is not a regular file",
            )),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn enable(&self, executable: &Path) -> Result<(), locket_platform::PlatformError> {
        let contents = plist(self.instance, executable)?;
        if let Some(directory) = self.path.parent() {
            fs::create_dir_all(directory)?;
        }
        locket_platform::write_user_only_file(&self.path, contents.as_bytes())
    }

    pub(crate) fn disable(&self) -> io::Result<()> {
        if self.enabled()? {
            match fs::remove_file(&self.path) {
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
                result => result,
            }
        } else {
            Ok(())
        }
    }
}

const fn label(instance: LocketInstance) -> &'static str {
    match instance {
        LocketInstance::Installed => "app.locket.desktop",
        LocketInstance::Dev => "app.locket.desktop.dev",
    }
}

fn plist(instance: LocketInstance, executable: &Path) -> io::Result<String> {
    let executable = executable.to_str().filter(|_| executable.is_absolute()).ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidInput,
            "LaunchAgent needs an absolute Unicode executable path",
        )
    })?;
    let executable = xml_escape(executable)?;
    let label = label(instance);
    let environment = if instance == LocketInstance::Dev {
        // A release executable can also be running in the dev namespace.
        "
    <key>EnvironmentVariables</key>
    <dict><key>LOCKET_INSTANCE</key><string>dev</string></dict>"
    } else {
        ""
    };
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array><string>{executable}</string></array>
    <key>RunAtLoad</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>KeepAlive</key>
    <false/>{environment}
</dict>
</plist>
"#
    ))
}

fn xml_escape(value: &str) -> io::Result<String> {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            '\r' => escaped.push_str("&#13;"),
            '\t'
            | '\n'
            | '\u{20}'..='\u{d7ff}'
            | '\u{e000}'..='\u{fffd}'
            | '\u{10000}'..='\u{10ffff}' => escaped.push(character),
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "Executable path contains an invalid XML character",
                ));
            }
        }
    }
    Ok(escaped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_configures_an_interactive_one_shot_login_launch() -> io::Result<()> {
        let executable = std::env::current_exe()?;
        let installed = plist(LocketInstance::Installed, &executable)?;
        assert!(installed.contains("<string>app.locket.desktop</string>"));
        assert!(installed.contains("<key>RunAtLoad</key>\n    <true/>"));
        assert!(installed.contains("<key>ProcessType</key>\n    <string>Interactive</string>"));
        assert!(installed.contains("<key>KeepAlive</key>\n    <false/>"));
        assert!(!installed.contains("LOCKET_INSTANCE"));
        let dev = plist(LocketInstance::Dev, &executable)?;
        assert!(dev.contains("<string>app.locket.desktop.dev</string>"));
        assert!(dev.contains("<key>LOCKET_INSTANCE</key><string>dev</string>"));
        Ok(())
    }

    #[test]
    fn plist_escapes_executable_and_rejects_invalid_xml() -> io::Result<()> {
        let executable = std::env::current_exe()?.with_file_name("Locket & <test> \"it's\"\r");
        let document = plist(LocketInstance::Installed, &executable)?;
        assert!(document.contains("Locket &amp; &lt;test&gt; &quot;it&apos;s&quot;&#13;</string>"));
        assert!(xml_escape("invalid\u{1}").is_err());
        Ok(())
    }

    #[test]
    fn enable_and_disable_keep_the_two_instances_separate() -> Result<(), Box<dyn std::error::Error>>
    {
        let home = tempfile::tempdir()?;
        let installed = LaunchAgent::new(home.path(), LocketInstance::Installed);
        let dev = LaunchAgent::new(home.path(), LocketInstance::Dev);
        let executable = std::env::current_exe()?;
        assert!(!installed.enabled()?);
        assert!(!dev.enabled()?);

        installed.enable(&executable)?;
        let installed_contents = fs::read(&installed.path)?;
        dev.enable(&executable)?;
        assert!(installed.enabled()?);
        assert!(dev.enabled()?);
        assert_eq!(fs::read_to_string(&dev.path)?, plist(LocketInstance::Dev, &executable)?);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(fs::metadata(&dev.path)?.permissions().mode() & 0o777, 0o600);
        }

        dev.disable()?;
        dev.disable()?;
        assert!(!dev.enabled()?);
        assert_eq!(fs::read(&installed.path)?, installed_contents);
        installed.disable()?;
        assert!(!installed.enabled()?);
        Ok(())
    }
}
