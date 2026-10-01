//! Browser filesystem/network boundary. Every writable directory comes from
//! the service's temporary filesystem, so deployments can impose one disk cap.

use crate::error::{ErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    pub worker: PathBuf,
    pub bubblewrap: PathBuf,
    pub chromium_sandbox: PathBuf,
    pub fontconfig: PathBuf,
    pub store_paths: Vec<PathBuf>,
}

impl SandboxConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.worker.is_absolute()
            || !self.chromium_sandbox.is_absolute()
            || !self.fontconfig.is_absolute()
            || !self.bubblewrap.is_absolute()
            || self.store_paths.is_empty()
            || self.store_paths.len() > 1024
            || self
                .store_paths
                .iter()
                .any(|p| !crate::worker::store_root(p))
            || [&self.chromium_sandbox, &self.fontconfig]
                .iter()
                .any(|required| {
                    !self
                        .store_paths
                        .iter()
                        .any(|root| required.starts_with(root))
                })
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(())
    }
}

pub struct Workspace {
    root: tempfile::TempDir,
}

impl Workspace {
    pub fn new(temporary: &Path) -> Result<Self> {
        let root = tempfile::Builder::new()
            .prefix("browser-")
            .tempdir_in(temporary)
            .map_err(|_| ErrorCode::Storage)?;
        for name in ["scratch", "scratch/tmp", "output", "responses"] {
            let directory = root.path().join(name);
            std::fs::create_dir(&directory).map_err(|_| ErrorCode::Storage)?;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| ErrorCode::Storage)?;
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        self.root.path()
    }

    /// Remove the scratch tree, reporting failures instead of discarding them.
    ///
    /// `tempfile::TempDir`'s `Drop` ignores `remove_dir_all` errors. Cleanup is
    /// part of the security boundary, so a failed removal must be visible and
    /// retried, and callers must not release reusable capacity while scratch
    /// remains. Removal may race a descendant that is still releasing handles,
    /// hence the bounded retries.
    pub fn close(&mut self) -> std::io::Result<()> {
        let path = self.root.path().to_path_buf();
        let mut last = None;
        for attempt in 0..5u32 {
            match std::fs::remove_dir_all(&path) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => {
                    last = Some(error);
                    std::thread::sleep(std::time::Duration::from_millis(
                        25 * u64::from(attempt + 1),
                    ));
                }
            }
        }
        Err(last.expect("removal attempted at least once"))
    }

    /// The supervisor must kill and await this child before dropping Workspace.
    /// Bubblewrap's PID-namespace init owns and reaps Chromium descendants.
    /// `timezone` is the session profile's IANA zone; absent keeps the neutral
    /// UTC default.
    pub fn command(
        &self,
        config: &SandboxConfig,
        timezone: Option<&str>,
    ) -> Result<tokio::process::Command> {
        config.validate()?;
        let mut command = tokio::process::Command::new(&config.bubblewrap);
        command.env_clear().args([
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--setenv",
            "HOME",
            "/scratch",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--setenv",
            "LC_ALL",
            "C.UTF-8",
            "--setenv",
            "TZ",
            timezone.unwrap_or("UTC"),
            "--setenv",
            "PATH",
            "/nonexistent",
            "--dir",
            "/nix",
            "--dir",
            "/nix/store",
        ]);
        // The pinned Nixpkgs build resolves its helper through this variable.
        // An absent value crashes before namespace sandbox detection. Use the
        // packaged helper, never a host setuid wrapper or an empty value that
        // would disable the setuid sandbox through Chromium's environment API.
        command
            .args(["--setenv", "CHROME_DEVEL_SANDBOX"])
            .arg(&config.chromium_sandbox);
        command
            .args(["--setenv", "FONTCONFIG_FILE"])
            .arg(&config.fontconfig);
        for store_path in &config.store_paths {
            command.arg("--ro-bind").arg(store_path).arg(store_path);
        }
        command.arg("--ro-bind").arg(&config.worker).arg("/worker");
        for (source, destination, writable) in [
            ("scratch", "/scratch", true),
            ("scratch/tmp", "/tmp", true),
            ("output", "/output", true),
            ("responses", "/responses", false),
        ] {
            command
                .arg(if writable { "--bind" } else { "--ro-bind" })
                .arg(self.root.path().join(source))
                .arg(destination);
        }
        command
            .args(["--proc", "/proc", "--dev", "/dev"])
            // Shared memory uses the same supervised backing filesystem. The
            // remaining auxiliary root/dev mounts must not accept regular files.
            .arg("--bind")
            .arg(self.root.path().join("scratch/tmp"))
            .arg("/dev/shm")
            .args([
                "--remount-ro",
                "/dev",
                "--remount-ro",
                "/",
                "--chdir",
                "/scratch",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        Ok(command)
    }
}

#[cfg(test)]
mod tests {
    use super::Workspace;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn close_removes_scratch_and_reports_failure() {
        let parent = tempfile::tempdir().unwrap();
        let mut workspace = Workspace::new(parent.path()).unwrap();
        let scratch = workspace.root().join("scratch");
        std::fs::write(scratch.join("evidence"), b"raw").unwrap();

        // A directory without write permission blocks recursive removal for a
        // non-root user. Root bypasses this, so only the negative branch is
        // conditional; the successful removal and idempotency are asserted in
        // both cases.
        std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o500)).unwrap();
        let blocked = workspace.close().is_err();
        if blocked {
            std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(workspace.close().is_ok());
        }
        assert!(!workspace.root().exists());
        assert!(workspace.close().is_ok());
    }
}
