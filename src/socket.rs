//! Strict systemd activation. No development-mode PID exemption or TCP fallback.

use crate::error::{ErrorCode, Result};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use tokio::net::UnixStream;

/// Call during single-threaded startup, before constructing the Tokio runtime:
/// listenfd consumes systemd's environment variables as part of FD adoption.
pub fn activated_listener(
    fd: u32,
    expected_path: &Path,
) -> Result<std::os::unix::net::UnixListener> {
    if std::env::var_os("LISTEN_FDS_FIRST_FD").is_some() {
        return Err(ErrorCode::PermissionDenied);
    }
    validate_activation(
        fd,
        std::env::var("LISTEN_PID").ok().as_deref(),
        std::env::var("LISTEN_FDS").ok().as_deref(),
        std::process::id(),
    )?;
    let mut fds = listenfd::ListenFd::from_env();
    let listener = fds
        .take_unix_listener(0)
        .map_err(|_| ErrorCode::PermissionDenied)?
        .ok_or(ErrorCode::PermissionDenied)?;
    if listener
        .local_addr()
        .map_err(|_| ErrorCode::PermissionDenied)?
        .as_pathname()
        != Some(expected_path)
        || !rustix::net::sockopt::socket_acceptconn(&listener)
            .map_err(|_| ErrorCode::PermissionDenied)?
        || rustix::net::sockopt::socket_type(&listener).map_err(|_| ErrorCode::PermissionDenied)?
            != rustix::net::SocketType::STREAM
        || rustix::net::sockopt::socket_domain(&listener)
            .map_err(|_| ErrorCode::PermissionDenied)?
            != rustix::net::AddressFamily::UNIX
    {
        return Err(ErrorCode::PermissionDenied);
    }
    validate_socket_path(expected_path)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| ErrorCode::PermissionDenied)?;
    Ok(listener)
}

fn validate_activation(
    fd: u32,
    pid: Option<&str>,
    count: Option<&str>,
    actual_pid: u32,
) -> Result<()> {
    if fd != 3 || pid.and_then(|v| v.parse::<u32>().ok()) != Some(actual_pid) || count != Some("1")
    {
        return Err(ErrorCode::PermissionDenied);
    }
    Ok(())
}

pub fn validate_socket_path(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ErrorCode::PermissionDenied)?;
    if !metadata.file_type().is_socket()
        || metadata.mode() & 0o117 != 0
        || (metadata.uid() != 0 && metadata.uid() != rustix::process::getuid().as_raw())
    {
        return Err(ErrorCode::PermissionDenied);
    }
    Ok(())
}

pub fn authorized_peer(stream: &UnixStream, allowed: &[u32]) -> Result<u32> {
    let peer = stream
        .peer_cred()
        .map_err(|_| ErrorCode::PermissionDenied)?;
    if !allowed.contains(&peer.uid()) {
        return Err(ErrorCode::PermissionDenied);
    }
    Ok(peer.uid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    #[test]
    fn activation_requires_exact_pid_fd_and_count() {
        assert!(validate_activation(3, Some("42"), Some("1"), 42).is_ok());
        for (fd, pid, count) in [
            (4, Some("42"), Some("1")),
            (3, None, Some("1")),
            (3, Some("41"), Some("1")),
            (3, Some("42"), Some("2")),
            (3, Some(""), Some("1")),
        ] {
            assert_eq!(
                validate_activation(fd, pid, count, 42),
                Err(ErrorCode::PermissionDenied)
            );
        }
    }

    #[tokio::test]
    async fn real_unix_peer_and_permissions_are_checked() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        validate_socket_path(&path).unwrap();
        let client = UnixStream::connect(&path).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let uid = rustix::process::getuid().as_raw();
        assert_eq!(authorized_peer(&server, &[uid]).unwrap(), uid);
        assert_eq!(
            authorized_peer(&client, &[]),
            Err(ErrorCode::PermissionDenied)
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            validate_socket_path(&path),
            Err(ErrorCode::PermissionDenied)
        );
    }
}
