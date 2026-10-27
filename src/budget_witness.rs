//! Fixed-target host witness for guarded ledger admissions. The wire protocol has
//! no paths, commands or credentials: a fresh nonce elicits one fixed reply.
use super::{GUARD_LOCK, Marker, checked_file, file_matches, name, open_at};
use crate::error::{ErrorCode, Result};
use rustix::event::{PollFd, PollFlags, Timespec};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

const REQUEST_MAGIC: &[u8; 8] = b"RLGW1REQ";
const RESPONSE_MAGIC: &[u8; 8] = b"RLGW1RES";
const REQUEST_LEN: usize = 24;
const RESPONSE_LEN: usize = 144;
const DEADLINE: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Evidence {
    pub state_directory: (u64, u64),
    pub state_owner: u32,
    pub state_mode: u32,
    pub directory: (u64, u64),
    pub marker: (u64, u64),
    pub lock: (u64, u64),
    pub digest: [u8; 32],
}

pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn wait_ready(fd: &impl AsFd, events: PollFlags, deadline: Instant) -> Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(ErrorCode::Storage)?;
        if remaining.is_zero() {
            return Err(ErrorCode::Storage);
        }
        let timeout = Timespec {
            tv_sec: remaining.as_secs() as i64,
            tv_nsec: remaining.subsec_nanos().into(),
        };
        let mut fds = [PollFd::new(fd, events)];
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(0) => return Err(ErrorCode::Storage),
            Ok(_)
                if fds[0].revents().intersects(
                    PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL | PollFlags::RDHUP,
                ) =>
            {
                return Err(ErrorCode::Storage);
            }
            Ok(_) if fds[0].revents().contains(events) => return Ok(()),
            Ok(_) => continue,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return Err(ErrorCode::Storage),
        }
    }
}

fn read_exact(stream: &UnixStream, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(ErrorCode::Storage);
        }
        match (&*stream).read(bytes) {
            Ok(0) => return Err(ErrorCode::Storage),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                wait_ready(stream, PollFlags::IN, deadline)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ErrorCode::Storage),
        }
    }
    Ok(())
}

fn write_all(stream: &UnixStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(ErrorCode::Storage);
        }
        match (&*stream).write(bytes) {
            Ok(0) => return Err(ErrorCode::Storage),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                wait_ready(stream, PollFlags::OUT, deadline)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ErrorCode::Storage),
        }
    }
    Ok(())
}

// The witness keeps the connection open until the client closes it. EOF or an
// extra byte before acceptance means the witness died or the frame was invalid.
fn no_extra_data(stream: &UnixStream) -> Result<()> {
    let mut byte = [0u8; 1];
    match rustix::net::recv(
        stream,
        &mut byte[..],
        rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
    ) {
        Err(rustix::io::Errno::AGAIN) => Ok(()),
        _ => Err(ErrorCode::Storage),
    }
}

fn connect(path: &Path, expected_uid: u32, deadline: Instant) -> Result<UnixStream> {
    let fd = rustix::net::socket_with(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::NONBLOCK | rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| ErrorCode::Storage)?;
    let address = rustix::net::SocketAddrUnix::new(path).map_err(|_| ErrorCode::Storage)?;
    match rustix::net::connect(&fd, &address) {
        Ok(()) => (),
        Err(rustix::io::Errno::INPROGRESS) => {
            wait_ready(&fd, PollFlags::OUT, deadline)?;
            rustix::net::sockopt::socket_error(&fd)
                .map_err(|_| ErrorCode::Storage)?
                .map_err(|_| ErrorCode::Storage)?;
        }
        Err(_) => return Err(ErrorCode::Storage),
    }
    if rustix::net::sockopt::socket_peercred(&fd)
        .map_err(|_| ErrorCode::Storage)?
        .uid
        .as_raw()
        != expected_uid
    {
        return Err(ErrorCode::PermissionDenied);
    }
    Ok(UnixStream::from(fd))
}

fn pair(bytes: &[u8]) -> Result<(u64, u64)> {
    Ok((
        u64::from_be_bytes(bytes[..8].try_into().map_err(|_| ErrorCode::Storage)?),
        u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| ErrorCode::Storage)?),
    ))
}

pub(super) struct WitnessClient {
    path: PathBuf,
    peer_uid: u32,
    epoch: Mutex<Option<[u8; 16]>>,
}

impl WitnessClient {
    pub(super) fn new(path: PathBuf, peer_uid: u32) -> Self {
        Self {
            path,
            peer_uid,
            epoch: Mutex::new(None),
        }
    }

    pub(super) fn verify(&self, expected: &Evidence) -> Result<()> {
        let deadline = Instant::now() + DEADLINE;
        let stream = connect(&self.path, self.peer_uid, deadline)?;
        let nonce = Uuid::new_v4();
        let mut request = [0u8; REQUEST_LEN];
        request[..8].copy_from_slice(REQUEST_MAGIC);
        request[8..].copy_from_slice(nonce.as_bytes());
        write_all(&stream, &request, deadline)?;
        let mut reply = [0u8; RESPONSE_LEN];
        read_exact(&stream, &mut reply, deadline)?;
        if &reply[..8] != RESPONSE_MAGIC
            || &reply[8..24] != nonce.as_bytes()
            || Instant::now() >= deadline
        {
            return Err(ErrorCode::Storage);
        }
        let epoch: [u8; 16] = reply[24..40].try_into().map_err(|_| ErrorCode::Storage)?;
        let evidence = Evidence {
            state_directory: pair(&reply[120..136])?,
            state_owner: u32::from_be_bytes(
                reply[136..140].try_into().map_err(|_| ErrorCode::Storage)?,
            ),
            state_mode: u32::from_be_bytes(
                reply[140..144].try_into().map_err(|_| ErrorCode::Storage)?,
            ),
            directory: pair(&reply[40..56])?,
            marker: pair(&reply[56..72])?,
            lock: pair(&reply[72..88])?,
            digest: reply[88..120].try_into().map_err(|_| ErrorCode::Storage)?,
        };
        if epoch == [0; 16] || &evidence != expected {
            return Err(ErrorCode::Storage);
        }
        no_extra_data(&stream)?;
        let mut pinned = self.epoch.lock().map_err(|_| ErrorCode::Storage)?;
        if pinned.is_some_and(|old| old != epoch) {
            return Err(ErrorCode::Storage);
        }
        *pinned = Some(epoch);
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HostSnapshot {
    marker_ancestors: Vec<(u64, u64)>,
    state_ancestors: Vec<(u64, u64)>,
    evidence: Evidence,
}

// Open only root-controlled ancestors. The final target is never opened here:
// the state directory can be service-owned mode 0700 and inaccessible to the witness.
fn trusted_parent(
    path: &Path,
    root: &Path,
    owner: u32,
    expected: Option<&[(u64, u64)]>,
) -> Result<(File, Vec<(u64, u64)>)> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ErrorCode::InvalidRequest)?;
    name(relative)?;
    let root_meta = std::fs::symlink_metadata(root).map_err(|_| ErrorCode::Storage)?;
    if !root_meta.is_dir() || root_meta.uid() != owner || root_meta.mode() & 0o022 != 0 {
        return Err(ErrorCode::PermissionDenied);
    }
    let mut directory = File::open(root).map_err(|_| ErrorCode::Storage)?;
    let opened_root = directory.metadata().map_err(|_| ErrorCode::Storage)?;
    if (root_meta.dev(), root_meta.ino()) != (opened_root.dev(), opened_root.ino()) {
        return Err(ErrorCode::Storage);
    }
    let mut ancestors = Vec::new();
    let mut visited = 0usize;
    let mut observe = |metadata: &std::fs::Metadata| -> Result<()> {
        let identity = (metadata.dev(), metadata.ino());
        if let Some(snapshot) = expected {
            if snapshot.get(visited) != Some(&identity) {
                return Err(ErrorCode::Storage);
            }
        } else {
            ancestors.push(identity);
        }
        visited += 1;
        Ok(())
    };
    observe(&root_meta)?;
    for component in relative
        .parent()
        .ok_or(ErrorCode::InvalidRequest)?
        .components()
    {
        let Component::Normal(part) = component else {
            return Err(ErrorCode::InvalidRequest);
        };
        directory = open_at(
            &directory,
            part,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            0,
        )?;
        let metadata = directory.metadata().map_err(|_| ErrorCode::Storage)?;
        if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
            return Err(ErrorCode::PermissionDenied);
        }
        observe(&metadata)?;
    }
    if expected.is_some_and(|snapshot| visited != snapshot.len()) {
        return Err(ErrorCode::Storage);
    }
    Ok((directory, ancestors))
}

fn capture(
    marker_path: &Path,
    state_path: &Path,
    root: &Path,
    owner: u32,
    service_uid: u32,
    expected: Option<&HostSnapshot>,
) -> Result<HostSnapshot> {
    let marker_name = name(marker_path)?;
    if marker_name == OsStr::new(GUARD_LOCK) {
        return Err(ErrorCode::InvalidRequest);
    }
    let (directory, marker_ancestors) = trusted_parent(
        marker_path,
        root,
        owner,
        expected.map(|snapshot| snapshot.marker_ancestors.as_slice()),
    )?;
    let (state_parent, state_ancestors) = trusted_parent(
        state_path,
        root,
        owner,
        expected.map(|snapshot| snapshot.state_ancestors.as_slice()),
    )?;
    let state = rustix::fs::statat(
        &state_parent,
        name(state_path)?,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|_| ErrorCode::Storage)?;
    if rustix::fs::FileType::from_raw_mode(state.st_mode) != rustix::fs::FileType::Directory
        || state.st_uid != service_uid
        || state.st_mode & 0o7777 != 0o700
    {
        return Err(ErrorCode::PermissionDenied);
    }
    let directory_meta = directory.metadata().map_err(|_| ErrorCode::Storage)?;
    let mut marker_file = open_at(&directory, marker_name, rustix::fs::OFlags::RDONLY, 0)?;
    let marker_meta = checked_file(&marker_file, owner)?;
    let mut bytes = [0u8; 1025];
    let mut size = 0;
    while size < bytes.len() {
        match marker_file.read(&mut bytes[size..]) {
            Ok(0) => break,
            Ok(count) => size += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ErrorCode::Storage),
        }
    }
    if size > 1024 {
        return Err(ErrorCode::Storage);
    }
    let bytes = &bytes[..size];
    let marker: Marker = serde_json::from_slice(bytes).map_err(|_| ErrorCode::Storage)?;
    if marker.version != 1 {
        return Err(ErrorCode::Storage);
    }
    file_matches(
        &directory,
        marker_name,
        &marker_file,
        owner,
        marker_meta.dev(),
        marker_meta.ino(),
    )?;
    let lock_file = open_at(
        &directory,
        OsStr::new(GUARD_LOCK),
        rustix::fs::OFlags::RDONLY,
        0,
    )?;
    file_matches(
        &directory,
        OsStr::new(GUARD_LOCK),
        &lock_file,
        owner,
        marker.lock_device,
        marker.lock_inode,
    )?;
    let evidence = Evidence {
        state_directory: (state.st_dev, state.st_ino),
        state_owner: state.st_uid,
        state_mode: state.st_mode,
        directory: (directory_meta.dev(), directory_meta.ino()),
        marker: (marker_meta.dev(), marker_meta.ino()),
        lock: (marker.lock_device, marker.lock_inode),
        digest: digest(bytes),
    };
    if expected.is_some_and(|snapshot| evidence != snapshot.evidence) {
        return Err(ErrorCode::Storage);
    }
    Ok(HostSnapshot {
        marker_ancestors,
        state_ancestors,
        evidence,
    })
}

pub(super) struct HostWitness {
    marker: PathBuf,
    state_path: PathBuf,
    root: PathBuf,
    owner: u32,
    state_owner: u32,
    service_uid: u32,
    initial: HostSnapshot,
    epoch: Uuid,
}

impl HostWitness {
    pub(super) fn new(
        marker: &Path,
        state_path: &Path,
        root: &Path,
        owner: u32,
        service_uid: u32,
    ) -> Result<Self> {
        let initial = capture(marker, state_path, root, owner, service_uid, None)?;
        Ok(Self {
            marker: marker.into(),
            state_path: state_path.into(),
            root: root.into(),
            owner,
            state_owner: service_uid,
            service_uid,
            initial,
            epoch: Uuid::new_v4(),
        })
    }

    #[cfg(test)]
    pub(super) fn with_test_peer(mut self, uid: u32) -> Self {
        self.service_uid = uid;
        self
    }

    // Only a detected host-state change is fatal to the witness. Unauthorized,
    // malformed and timed-out clients receive no reply and cannot change state.
    pub(super) fn handle(&self, stream: UnixStream) -> Result<()> {
        stream
            .set_nonblocking(true)
            .map_err(|_| ErrorCode::Storage)?;
        if rustix::net::sockopt::socket_peercred(&stream)
            .map_err(|_| ErrorCode::Storage)?
            .uid
            .as_raw()
            != self.service_uid
        {
            return Ok(());
        }
        let deadline = Instant::now() + DEADLINE;
        let mut request = [0u8; REQUEST_LEN];
        if read_exact(&stream, &mut request, deadline).is_err()
            || &request[..8] != REQUEST_MAGIC
            || no_extra_data(&stream).is_err()
        {
            return Ok(());
        }
        let current = capture(
            &self.marker,
            &self.state_path,
            &self.root,
            self.owner,
            self.state_owner,
            Some(&self.initial),
        )?;
        let mut reply = [0u8; RESPONSE_LEN];
        reply[..8].copy_from_slice(RESPONSE_MAGIC);
        reply[8..24].copy_from_slice(&request[8..24]);
        reply[24..40].copy_from_slice(self.epoch.as_bytes());
        for (offset, (device, inode)) in [
            (40, current.evidence.directory),
            (56, current.evidence.marker),
            (72, current.evidence.lock),
            (120, current.evidence.state_directory),
        ] {
            reply[offset..offset + 8].copy_from_slice(&device.to_be_bytes());
            reply[offset + 8..offset + 16].copy_from_slice(&inode.to_be_bytes());
        }
        reply[88..120].copy_from_slice(&current.evidence.digest);
        reply[136..140].copy_from_slice(&current.evidence.state_owner.to_be_bytes());
        reply[140..144].copy_from_slice(&current.evidence.state_mode.to_be_bytes());
        if write_all(&stream, &reply, deadline).is_err() {
            return Ok(());
        }
        // Hold this connection until the client closes or the deadline expires;
        // the client rejects a dead witness or unexpected trailing frame.
        let mut byte = [0u8; 1];
        let _ = read_exact(&stream, &mut byte, deadline);
        Ok(())
    }

    fn serve(&self, listener: UnixListener) -> Result<()> {
        loop {
            match listener.accept() {
                Ok((stream, _)) => self.handle(stream)?,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let _ = wait_ready(
                        &listener,
                        PollFlags::IN,
                        Instant::now() + Duration::from_secs(1),
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(ErrorCode::Storage),
            }
        }
    }
}

pub(super) fn run(
    marker: &Path,
    state_path: &Path,
    service_uid: u32,
    witness_uid: u32,
    listener: UnixListener,
) -> Result<()> {
    if witness_uid == 0
        || witness_uid == u32::MAX
        || witness_uid == service_uid
        || rustix::process::geteuid().as_raw() != witness_uid
        || service_uid == 0
        || service_uid == u32::MAX
    {
        return Err(ErrorCode::PermissionDenied);
    }
    listener
        .set_nonblocking(true)
        .map_err(|_| ErrorCode::Storage)?;
    HostWitness::new(marker, state_path, Path::new("/"), 0, service_uid)?.serve(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> Evidence {
        Evidence {
            state_directory: (8, 9),
            state_owner: 123,
            state_mode: 0o40700,
            directory: (1, 2),
            marker: (3, 4),
            lock: (5, 6),
            digest: [7; 32],
        }
    }

    fn reply(request: &[u8; REQUEST_LEN], expected: &Evidence) -> Vec<u8> {
        let mut bytes = vec![0u8; RESPONSE_LEN];
        bytes[..8].copy_from_slice(RESPONSE_MAGIC);
        bytes[8..24].copy_from_slice(&request[8..24]);
        bytes[24..40].copy_from_slice(&[9; 16]);
        for (offset, (device, inode)) in [
            (40, expected.directory),
            (56, expected.marker),
            (72, expected.lock),
            (120, expected.state_directory),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&device.to_be_bytes());
            bytes[offset + 8..offset + 16].copy_from_slice(&inode.to_be_bytes());
        }
        bytes[88..120].copy_from_slice(&expected.digest);
        bytes[136..140].copy_from_slice(&expected.state_owner.to_be_bytes());
        bytes[140..144].copy_from_slice(&expected.state_mode.to_be_bytes());
        bytes
    }

    #[test]
    fn witness_requires_the_explicit_distinct_nonroot_process_uid() {
        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("unused-marker");
        let uid = rustix::process::geteuid().as_raw();
        let wrong_uid = if uid == 1 { 2 } else { 1 };
        for (index, service_uid, witness_uid) in [(0, 12345, 0), (1, uid, uid), (2, 3, wrong_uid)] {
            let listener = UnixListener::bind(root.path().join(format!("socket-{index}"))).unwrap();
            assert!(matches!(
                run(&marker, root.path(), service_uid, witness_uid, listener),
                Err(ErrorCode::PermissionDenied)
            ));
        }
    }

    // Socket activation passes a listening descriptor between processes. This
    // unprivileged fixture verifies the kernel's peer identity is the listener
    // creator, not merely the process which calls accept().
    #[test]
    fn inherited_listener_child_fixture() {
        if std::env::var_os("RESEARCH_TEST_WITNESS_LISTENER").is_none() {
            return;
        }
        let fd = rustix::io::dup(rustix::stdio::stdin()).unwrap();
        let listener = UnixListener::from(fd);
        let (mut stream, _) = listener.accept().unwrap();
        std::io::Write::write_all(&mut stream, &[1]).unwrap();
    }

    #[test]
    fn inherited_listener_reports_creator_credentials() {
        use std::os::fd::OwnedFd;
        use std::process::{Command, Stdio};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let descriptor: OwnedFd = listener.into();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("budget::guard::witness::tests::inherited_listener_child_fixture")
            .env("RESEARCH_TEST_WITNESS_LISTENER", "1")
            .stdin(Stdio::from(descriptor))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let observed = (|| -> std::io::Result<_> {
            let mut stream = UnixStream::connect(&path)?;
            stream.set_read_timeout(Some(Duration::from_secs(4)))?;
            let peer = rustix::net::sockopt::socket_peercred(&stream)?;
            let mut response = [0u8; 1];
            std::io::Read::read_exact(&mut stream, &mut response)?;
            Ok((peer, response))
        })();
        if observed.is_err() {
            let _ = child.kill();
        }
        let status = child.wait().unwrap();
        let (peer, response) = observed.unwrap();
        assert!(status.success());
        assert_eq!(response, [1]);
        assert_eq!(peer.uid.as_raw(), rustix::process::geteuid().as_raw());
        assert_eq!(peer.pid, rustix::process::getpid());
        assert_ne!(peer.pid.as_raw_pid() as u32, child.id());
    }

    #[test]
    fn each_check_uses_a_new_challenge_and_authenticated_connection() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let expected = evidence();
        let server_evidence = expected.clone();
        let worker = std::thread::spawn(move || {
            let mut challenges = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut request = [0u8; REQUEST_LEN];
                std::io::Read::read_exact(&mut stream, &mut request).unwrap();
                challenges.push(request[8..24].to_vec());
                std::io::Write::write_all(&mut stream, &reply(&request, &server_evidence)).unwrap();
                let mut byte = [0u8; 1];
                let _ = std::io::Read::read(&mut stream, &mut byte);
            }
            challenges
        });
        let client = WitnessClient::new(path, rustix::process::geteuid().as_raw());
        client.verify(&expected).unwrap();
        client.verify(&expected).unwrap();
        let challenges = worker.join().unwrap();
        assert_ne!(challenges[0], challenges[1]);
    }

    #[test]
    fn state_device_inode_owner_and_mode_are_each_compared() {
        for field in 0..4 {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("socket");
            let listener = UnixListener::bind(&path).unwrap();
            let expected = evidence();
            let mut altered = expected.clone();
            match field {
                0 => altered.state_directory.0 += 1,
                1 => altered.state_directory.1 += 1,
                2 => altered.state_owner += 1,
                _ => altered.state_mode ^= 1,
            }
            let worker = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; REQUEST_LEN];
                std::io::Read::read_exact(&mut stream, &mut request).unwrap();
                std::io::Write::write_all(&mut stream, &reply(&request, &altered)).unwrap();
                let mut byte = [0u8; 1];
                let _ = std::io::Read::read(&mut stream, &mut byte);
            });
            let client = WitnessClient::new(path, rustix::process::geteuid().as_raw());
            assert!(client.verify(&expected).is_err());
            worker.join().unwrap();
        }
    }

    #[test]
    fn stale_challenge_and_extra_frame_are_rejected() {
        for extra in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("socket");
            let listener = UnixListener::bind(&path).unwrap();
            let expected = evidence();
            let server_evidence = expected.clone();
            let worker = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; REQUEST_LEN];
                std::io::Read::read_exact(&mut stream, &mut request).unwrap();
                let mut response = reply(&request, &server_evidence);
                if extra {
                    response.push(1);
                } else {
                    response[8] ^= 1;
                }
                std::io::Write::write_all(&mut stream, &response).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut byte = [0u8; 1];
                let _ = std::io::Read::read(&mut stream, &mut byte);
            });
            let client = WitnessClient::new(path, rustix::process::geteuid().as_raw());
            assert!(client.verify(&expected).is_err());
            worker.join().unwrap();
        }
    }

    #[test]
    fn stalled_witness_is_bounded_by_the_absolute_deadline() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let worker = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            std::thread::sleep(DEADLINE + Duration::from_millis(200));
        });
        let client = WitnessClient::new(path, rustix::process::geteuid().as_raw());
        let start = Instant::now();
        assert!(client.verify(&evidence()).is_err());
        assert!(start.elapsed() < DEADLINE + Duration::from_secs(1));
        worker.join().unwrap();
    }
}
