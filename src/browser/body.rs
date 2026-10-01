//! Large worker payloads use fixed numeric names beneath an already-open
//! directory. Paths never come from IPC, page content or a tool argument.
use crate::{
    config::MAX_HTTP_BODY_BYTES,
    error::{ErrorCode, Result},
    policy::sha256,
};
use rustix::fs::{AtFlags, Mode, OFlags, open, openat, unlinkat};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

pub const MAX_BYTES: u64 = MAX_HTTP_BODY_BYTES;

pub struct Bodies {
    directory: File,
}

impl Bodies {
    /// The path is a supervisor-authored workspace directory or a fixed worker
    /// mount. Retaining its descriptor prevents later path replacement from
    /// redirecting file reads, writes or cleanup outside the workspace.
    pub fn open(directory: &Path) -> Result<Self> {
        let directory = open(
            directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ErrorCode::Storage)?;
        Ok(Self {
            directory: directory.into(),
        })
    }

    fn name(id: u64) -> Result<String> {
        if id == 0 {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(format!("{id}.body"))
    }

    /// The caller publishes metadata only after this returns. IDs are unique
    /// within a session; an existing entry is never overwritten or followed.
    pub fn write(&self, id: u64, bytes: &[u8], maximum: u64) -> Result<()> {
        if maximum > MAX_BYTES || bytes.len() as u64 > maximum {
            return Err(ErrorCode::SizeLimit);
        }
        let name = Self::name(id)?;
        let mut file = File::from(
            openat(
                &self.directory,
                name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| ErrorCode::Storage)?,
        );
        if file.write_all(bytes).is_err() {
            let _ = unlinkat(&self.directory, name.as_str(), AtFlags::empty());
            return Err(ErrorCode::Storage);
        }
        Ok(())
    }

    pub fn read(&self, id: u64, length: u64, digest: &str, maximum: u64) -> Result<Vec<u8>> {
        if maximum > MAX_BYTES || length > maximum {
            return Err(ErrorCode::SizeLimit);
        }
        if !super::wire::digest_valid(digest) {
            return Err(ErrorCode::InvalidResponse);
        }
        let name = Self::name(id)?;
        let file = File::from(
            openat(
                &self.directory,
                name.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| ErrorCode::Storage)?,
        );
        let metadata = file.metadata().map_err(|_| ErrorCode::Storage)?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != length {
            return Err(ErrorCode::InvalidResponse);
        }
        let mut bytes = Vec::new();
        file.take(length + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ErrorCode::Storage)?;
        if bytes.len() as u64 != length || sha256(&bytes) != digest {
            return Err(ErrorCode::InvalidResponse);
        }
        Ok(bytes)
    }

    /// Only call for a pending ID that the peer has acknowledged, or after the
    /// worker has exited. Unlink never follows a replacement entry's target.
    pub fn remove(&self, id: u64) -> Result<()> {
        unlinkat(&self.directory, Self::name(id)?.as_str(), AtFlags::empty())
            .map_err(|_| ErrorCode::Storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn payload_identity_bounds_and_single_use_names() {
        let root = tempfile::tempdir().unwrap();
        let bodies = Bodies::open(root.path()).unwrap();
        let body = "Exact é 👩‍🔬 quote".as_bytes();
        bodies.write(1, body, 1024).unwrap();
        assert_eq!(
            bodies
                .read(1, body.len() as u64, &sha256(body), 1024)
                .unwrap(),
            body
        );
        assert_eq!(bodies.write(1, b"replace", 1024), Err(ErrorCode::Storage));
        assert_eq!(
            bodies.read(1, body.len() as u64, &sha256(b"wrong"), 1024),
            Err(ErrorCode::InvalidResponse)
        );
        assert_eq!(
            bodies.read(1, 1, &sha256(body), 1024),
            Err(ErrorCode::InvalidResponse)
        );
        assert_eq!(bodies.write(2, body, 1), Err(ErrorCode::SizeLimit));
        assert_eq!(
            bodies.read(1, body.len() as u64, &sha256(body), 1),
            Err(ErrorCode::SizeLimit)
        );
        assert_eq!(bodies.write(0, b"", 0), Err(ErrorCode::InvalidRequest));
        bodies.remove(1).unwrap();
        assert!(
            bodies
                .read(1, body.len() as u64, &sha256(body), 1024)
                .is_err()
        );
        bodies.write(2, b"", 0).unwrap();
        assert!(bodies.read(2, 0, &sha256(b""), 0).unwrap().is_empty());
    }

    #[test]
    fn hostile_entries_and_directory_replacement_cannot_redirect_access() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("canary"), b"outside").unwrap();
        let original = root.path().join("output");
        std::fs::create_dir(&original).unwrap();
        let bodies = Bodies::open(&original).unwrap();
        symlink(outside.path().join("canary"), original.join("1.body")).unwrap();
        assert!(bodies.read(1, 7, &sha256(b"outside"), 1024).is_err());
        assert!(bodies.write(1, b"overwrite", 1024).is_err());
        bodies.remove(1).unwrap();
        assert_eq!(
            std::fs::read(outside.path().join("canary")).unwrap(),
            b"outside"
        );
        std::fs::hard_link(outside.path().join("canary"), original.join("2.body")).unwrap();
        assert_eq!(
            bodies.read(2, 7, &sha256(b"outside"), 1024),
            Err(ErrorCode::InvalidResponse)
        );
        rustix::fs::mknodat(
            &bodies.directory,
            "3.body",
            rustix::fs::FileType::Fifo,
            Mode::RUSR | Mode::WUSR,
            0,
        )
        .unwrap();
        assert_eq!(
            bodies.read(3, 0, &sha256(b""), 1024),
            Err(ErrorCode::InvalidResponse)
        );
        std::fs::rename(&original, root.path().join("moved")).unwrap();
        symlink(outside.path(), &original).unwrap();
        assert!(Bodies::open(&original).is_err());
        bodies.write(4, b"inside", 1024).unwrap();
        assert!(!outside.path().join("4.body").exists());
        assert_eq!(
            std::fs::read(root.path().join("moved/4.body")).unwrap(),
            b"inside"
        );
    }
}
