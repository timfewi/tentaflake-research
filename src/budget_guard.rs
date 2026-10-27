//! Opt-in protected paid-ledger provisioning and admission.
//!
//! Guarded databases use a persistent TRUNCATE rollback journal, not WAL.
//! A clean journal binds the ledger UUID and committed database generation.
//! Any other contents are ambiguous and are never handed to SQLite to recover.
use super::{JobLimits, JobState, Ledger, Serialization, Usage};
use crate::config::Limits;
use crate::error::{ErrorCode, Result};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

#[path = "budget_witness.rs"]
mod witness;

/// Run the fixed-target host witness on an already activated Unix listener.
pub fn run_guard_witness(
    marker: &Path,
    state_path: &Path,
    service_uid: u32,
    witness_uid: u32,
    listener: std::os::unix::net::UnixListener,
) -> Result<()> {
    witness::run(marker, state_path, service_uid, witness_uid, listener)
}

const GUARD_LOCK: &str = "ledger.lock";

const SCHEMA: &str = "CREATE TABLE jobs (
    id TEXT PRIMARY KEY, owner INTEGER NOT NULL, state TEXT NOT NULL,
    created_at INTEGER NOT NULL, deadline_at INTEGER NOT NULL,
    limits_json TEXT NOT NULL, usage_json TEXT NOT NULL
  );
  CREATE TABLE attempts (
    id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id),
    day TEXT NOT NULL, reserved_bytes INTEGER NOT NULL,
    reserved_cost INTEGER NOT NULL, actual_cost INTEGER,
    state TEXT NOT NULL
  );
  CREATE INDEX attempts_day ON attempts(day);
  CREATE INDEX attempts_job ON attempts(job_id);
  CREATE TABLE ledger_identity (
    id TEXT PRIMARY KEY NOT NULL, generation INTEGER NOT NULL,
    last_observed INTEGER NOT NULL
  );";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u32,
    identity: Uuid,
    database_device: u64,
    database_inode: u64,
    journal_device: u64,
    journal_inode: u64,
    lock_device: u64,
    lock_inode: u64,
}

fn open_at(dir: &File, name: &OsStr, flags: rustix::fs::OFlags, mode: u32) -> Result<File> {
    rustix::fs::openat(
        dir,
        name,
        flags
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::from_raw_mode(mode),
    )
    .map(File::from)
    .map_err(|_| ErrorCode::Storage)
}

// Open each component relative to its already-verified directory, never by
// following a symlink or trusting a service-writable ancestor. The final state
// directory may belong to the service; all marker directories must belong to root.
fn secure_directory(path: &Path, final_owner: Option<u32>) -> Result<File> {
    if !path.is_absolute() {
        return Err(ErrorCode::InvalidRequest);
    }
    let parts: Vec<_> = path.components().collect();
    if parts.first() != Some(&Component::RootDir)
        || parts
            .iter()
            .skip(1)
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut directory = File::open("/").map_err(|_| ErrorCode::Storage)?;
    let root = directory.metadata().map_err(|_| ErrorCode::Storage)?;
    if root.uid() != 0 || root.mode() & 0o022 != 0 {
        return Err(ErrorCode::PermissionDenied);
    }
    for (index, part) in parts.iter().enumerate().skip(1) {
        let Component::Normal(name) = part else {
            return Err(ErrorCode::InvalidRequest);
        };
        directory = open_at(
            &directory,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            0,
        )?;
        let metadata = directory.metadata().map_err(|_| ErrorCode::Storage)?;
        let owner = if index + 1 == parts.len() {
            final_owner.unwrap_or(0)
        } else {
            0
        };
        if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
            return Err(ErrorCode::PermissionDenied);
        }
    }
    Ok(directory)
}

fn marker_directory(path: &Path) -> Result<(File, &OsStr)> {
    let name = path.file_name().ok_or(ErrorCode::InvalidRequest)?;
    if name == OsStr::new(GUARD_LOCK) {
        return Err(ErrorCode::InvalidRequest);
    }
    let directory = secure_directory(path.parent().ok_or(ErrorCode::InvalidRequest)?, None)?;
    Ok((directory, name))
}

fn state_directory(path: &Path, owner: u32) -> Result<File> {
    secure_directory(path, Some(owner))
}

fn checked_file(file: &File, owner: u32) -> Result<std::fs::Metadata> {
    let metadata = file.metadata().map_err(|_| ErrorCode::Storage)?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Err(ErrorCode::Storage);
    }
    Ok(metadata)
}

fn absent(dir: &File, name: &OsStr) -> Result<()> {
    match rustix::fs::statat(dir, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        _ => Err(ErrorCode::Storage),
    }
}

fn names(path: &Path) -> Result<(&OsStr, PathBuf, PathBuf, PathBuf)> {
    let name = path.file_name().ok_or(ErrorCode::InvalidRequest)?;
    let mut journal = path.as_os_str().to_os_string();
    journal.push("-journal");
    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    let mut shm = path.as_os_str().to_os_string();
    shm.push("-shm");
    Ok((name, journal.into(), wal.into(), shm.into()))
}

fn name(path: &Path) -> Result<&OsStr> {
    path.file_name().ok_or(ErrorCode::InvalidRequest)
}

fn file_matches(
    dir: &File,
    name: &OsStr,
    held: &File,
    owner: u32,
    device: u64,
    inode: u64,
) -> Result<()> {
    let held_meta = checked_file(held, owner)?;
    // Do not open and close an extra descriptor for the database here:
    // POSIX record locks used by SQLite can be released by an unrelated close.
    let current = rustix::fs::statat(dir, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ErrorCode::Storage)?;
    if rustix::fs::FileType::from_raw_mode(current.st_mode) != rustix::fs::FileType::RegularFile
        || current.st_uid != owner
        || current.st_mode & 0o022 != 0
        || current.st_nlink != 1
        || (held_meta.dev(), held_meta.ino()) != (device, inode)
        || (current.st_dev, current.st_ino) != (device, inode)
    {
        return Err(ErrorCode::Storage);
    }
    Ok(())
}

fn directory_matches(path: &Path, held: &File, owner: u32) -> Result<()> {
    let current = std::fs::symlink_metadata(path).map_err(|_| ErrorCode::Storage)?;
    let original = held.metadata().map_err(|_| ErrorCode::Storage)?;
    if !current.is_dir()
        || current.uid() != owner
        || current.mode() & 0o022 != 0
        || (current.dev(), current.ino()) != (original.dev(), original.ino())
    {
        return Err(ErrorCode::Storage);
    }
    Ok(())
}

fn journal_sentinel(identity: Uuid, generation: i64, last_observed: i64) -> [u8; 64] {
    let mut sentinel = [0u8; 64];
    sentinel[32..48].copy_from_slice(identity.as_bytes());
    sentinel[48..56].copy_from_slice(&generation.to_be_bytes());
    sentinel[56..64].copy_from_slice(&last_observed.to_be_bytes());
    sentinel
}

fn write_sentinel(
    journal: &File,
    identity: Uuid,
    generation: i64,
    last_observed: i64,
) -> Result<()> {
    journal
        .write_all_at(&journal_sentinel(identity, generation, last_observed), 0)
        .map_err(|_| ErrorCode::Storage)?;
    journal.set_len(64).map_err(|_| ErrorCode::Storage)
}

pub(super) struct GuardedFiles {
    dir: File,
    marker_dir: File,
    state_directory_path: PathBuf,
    marker_directory_path: PathBuf,
    database: File,
    journal: File,
    marker_file: File,
    guard_lock: File,
    database_name: std::ffi::OsString,
    journal_name: std::ffi::OsString,
    wal_name: std::ffi::OsString,
    shm_name: std::ffi::OsString,
    marker_name: std::ffi::OsString,
    marker_data: Vec<u8>,
    marker: Marker,
    marker_device: u64,
    marker_inode: u64,
    service_owner: u32,
    marker_owner: u32,
    witness: Option<witness::WitnessClient>,
}

impl GuardedFiles {
    fn open_in(
        path: &Path,
        dir: File,
        marker_dir: File,
        marker_path: &Path,
        service_owner: u32,
        marker_owner: u32,
        witness: Option<witness::WitnessClient>,
    ) -> Result<Self> {
        let marker_name = name(marker_path)?;
        let (database_name, journal_path, wal_path, shm_path) = names(path)?;
        let journal_name = name(&journal_path)?;
        let wal_name = name(&wal_path)?;
        let shm_name = name(&shm_path)?;
        let mut marker_file = open_at(&marker_dir, marker_name, rustix::fs::OFlags::RDONLY, 0)?;
        let marker_meta = checked_file(&marker_file, marker_owner)?;
        let mut data = Vec::new();
        (&mut marker_file)
            .take(1025)
            .read_to_end(&mut data)
            .map_err(|_| ErrorCode::Storage)?;
        if data.len() > 1024 {
            return Err(ErrorCode::Storage);
        }
        let marker: Marker = serde_json::from_slice(&data).map_err(|_| ErrorCode::Storage)?;
        if marker.version != 1 {
            return Err(ErrorCode::Storage);
        }
        let guard_lock = lock_service(&marker_dir, marker_owner)?;
        file_matches(
            &marker_dir,
            OsStr::new(GUARD_LOCK),
            &guard_lock,
            marker_owner,
            marker.lock_device,
            marker.lock_inode,
        )?;
        let database = open_at(&dir, database_name, rustix::fs::OFlags::RDWR, 0)?;
        let journal = open_at(&dir, journal_name, rustix::fs::OFlags::RDWR, 0)?;
        let files = Self {
            dir,
            marker_dir,
            database,
            journal,
            marker_file,
            guard_lock,
            state_directory_path: path.parent().ok_or(ErrorCode::InvalidRequest)?.to_owned(),
            marker_directory_path: marker_path
                .parent()
                .ok_or(ErrorCode::InvalidRequest)?
                .to_owned(),
            database_name: database_name.to_owned(),
            journal_name: journal_name.to_owned(),
            wal_name: wal_name.to_owned(),
            shm_name: shm_name.to_owned(),
            marker_name: marker_name.to_owned(),
            marker_data: data,
            marker,
            marker_device: marker_meta.dev(),
            marker_inode: marker_meta.ino(),
            service_owner,
            marker_owner,
            witness,
        };
        files.ensure()?;
        let mut header = [0u8; 20];
        files
            .database
            .read_exact_at(&mut header, 0)
            .map_err(|_| ErrorCode::Storage)?;
        // WAL-mode database headers remain marked as such even if the WAL was
        // deleted. Never let SQLite interpret a missing WAL as an empty one.
        if &header[..16] != b"SQLite format 3\0" || header[18..20] != [1, 1] {
            return Err(ErrorCode::Storage);
        }
        Ok(files)
    }

    fn check_files(&self) -> Result<()> {
        directory_matches(&self.state_directory_path, &self.dir, self.service_owner)?;
        directory_matches(
            &self.marker_directory_path,
            &self.marker_dir,
            self.marker_owner,
        )?;
        file_matches(
            &self.marker_dir,
            &self.marker_name,
            &self.marker_file,
            self.marker_owner,
            self.marker_device,
            self.marker_inode,
        )?;
        file_matches(
            &self.marker_dir,
            OsStr::new(GUARD_LOCK),
            &self.guard_lock,
            self.marker_owner,
            self.marker.lock_device,
            self.marker.lock_inode,
        )?;
        file_matches(
            &self.dir,
            &self.database_name,
            &self.database,
            self.service_owner,
            self.marker.database_device,
            self.marker.database_inode,
        )?;
        file_matches(
            &self.dir,
            &self.journal_name,
            &self.journal,
            self.service_owner,
            self.marker.journal_device,
            self.marker.journal_inode,
        )?;
        absent(&self.dir, &self.wal_name)?;
        absent(&self.dir, &self.shm_name)
    }

    fn sentinel_state(&self) -> Result<(i64, i64)> {
        self.check_files()?;
        let marker_length = self
            .marker_file
            .metadata()
            .map_err(|_| ErrorCode::Storage)?
            .len();
        if marker_length != self.marker_data.len() as u64 || marker_length > 1024 {
            return Err(ErrorCode::Storage);
        }
        let mut marker = [0u8; 1024];
        self.marker_file
            .read_exact_at(&mut marker[..self.marker_data.len()], 0)
            .map_err(|_| ErrorCode::Storage)?;
        if marker[..self.marker_data.len()] != self.marker_data[..] {
            return Err(ErrorCode::Storage);
        }
        if self
            .journal
            .metadata()
            .map_err(|_| ErrorCode::Storage)?
            .len()
            != 64
        {
            return Err(ErrorCode::Storage);
        }
        let mut contents = [0u8; 64];
        self.journal
            .read_exact_at(&mut contents, 0)
            .map_err(|_| ErrorCode::Storage)?;
        let generation = i64::from_be_bytes(
            contents[48..56]
                .try_into()
                .map_err(|_| ErrorCode::Storage)?,
        );
        let last_observed = i64::from_be_bytes(
            contents[56..64]
                .try_into()
                .map_err(|_| ErrorCode::Storage)?,
        );
        if generation < 0
            || last_observed < 0
            || contents != journal_sentinel(self.marker.identity, generation, last_observed)
        {
            return Err(ErrorCode::Storage);
        }
        if let Some(witness) = &self.witness {
            witness.verify(&self.witness_evidence()?)?;
        }
        Ok((generation, last_observed))
    }

    fn witness_evidence(&self) -> Result<witness::Evidence> {
        let state = self.dir.metadata().map_err(|_| ErrorCode::Storage)?;
        let directory = self.marker_dir.metadata().map_err(|_| ErrorCode::Storage)?;
        Ok(witness::Evidence {
            state_directory: (state.dev(), state.ino()),
            state_owner: state.uid(),
            state_mode: state.mode(),
            directory: (directory.dev(), directory.ino()),
            marker: (self.marker_device, self.marker_inode),
            lock: (self.marker.lock_device, self.marker.lock_inode),
            digest: witness::digest(&self.marker_data),
        })
    }

    pub(super) fn ensure(&self) -> Result<()> {
        self.sentinel_state().map(|_| ())
    }

    pub(super) fn ensure_database(&self, connection: &Connection) -> Result<()> {
        let sentinel = self.sentinel_state()?;
        let (generation, last_observed): (i64, i64) = connection
            .query_row(
                "SELECT generation,last_observed FROM ledger_identity WHERE id=?1",
                [self.marker.identity.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| ErrorCode::Storage)?;
        if (generation, last_observed) != sentinel {
            return Err(ErrorCode::Storage);
        }
        Ok(())
    }

    pub(super) fn check_clock(&self, connection: &Connection, now: i64) -> Result<()> {
        let previous: i64 = connection
            .query_row(
                "SELECT last_observed FROM ledger_identity WHERE id=?1",
                [self.marker.identity.to_string()],
                |row| row.get(0),
            )
            .map_err(|_| ErrorCode::Storage)?;
        if now < previous {
            return Err(ErrorCode::Storage);
        }
        Ok(())
    }

    pub(super) fn advance(&self, connection: &Connection, now: i64) -> Result<(i64, i64)> {
        connection
            .query_row(
                "UPDATE ledger_identity SET generation=generation+1,last_observed=?2 \
             WHERE id=?1 AND last_observed<=?2 AND generation<9223372036854775807 \
             RETURNING generation,last_observed",
                rusqlite::params![self.marker.identity.to_string(), now],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| ErrorCode::Storage)
    }

    // A commit's new generation is durably written to the sentinel only after
    // SQLite and the database have synced. Any interrupted mismatch fails closed.
    pub(super) fn sync_write(&self, state: (i64, i64)) -> Result<()> {
        self.check_files()?;
        self.database.sync_all().map_err(|_| ErrorCode::Storage)?;
        if self
            .journal
            .metadata()
            .map_err(|_| ErrorCode::Storage)?
            .len()
            != 0
        {
            return Err(ErrorCode::Storage);
        }
        write_sentinel(&self.journal, self.marker.identity, state.0, state.1)?;
        self.journal.sync_all().map_err(|_| ErrorCode::Storage)?;
        self.dir.sync_all().map_err(|_| ErrorCode::Storage)?;
        self.ensure()
    }
}

fn open_existing(path: &Path) -> Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| ErrorCode::Storage)?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| ErrorCode::Storage)?;
    let mode: String = connection
        .query_row("PRAGMA journal_mode=TRUNCATE", [], |row| row.get(0))
        .map_err(|_| ErrorCode::Storage)?;
    if mode != "truncate" {
        return Err(ErrorCode::Storage);
    }
    connection
        .execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")
        .map_err(|_| ErrorCode::Storage)?;
    Ok(connection)
}

fn validate_database(connection: &Connection, identity: Uuid) -> Result<()> {
    let mut integrity = connection
        .prepare("PRAGMA integrity_check")
        .map_err(|_| ErrorCode::Storage)?;
    let answers = integrity
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| ErrorCode::Storage)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| ErrorCode::Storage)?;
    if answers != ["ok"] {
        return Err(ErrorCode::Storage);
    }
    let mut foreign = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|_| ErrorCode::Storage)?;
    if foreign
        .query([])
        .map_err(|_| ErrorCode::Storage)?
        .next()
        .map_err(|_| ErrorCode::Storage)?
        .is_some()
    {
        return Err(ErrorCode::Storage);
    }
    let extra: u64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type IN ('table','trigger','view') AND name NOT IN ('jobs','attempts','ledger_identity')", [], |row| row.get(0)
    ).map_err(|_| ErrorCode::Storage)?;
    let (count, id): (u64, Option<String>) = connection
        .query_row("SELECT count(*), min(id) FROM ledger_identity", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(|_| ErrorCode::Storage)?;
    if extra != 0 || count != 1 || id.as_deref() != Some(identity.to_string().as_str()) {
        return Err(ErrorCode::Storage);
    }

    let mut attempts = connection
        .prepare(
            "SELECT id,job_id,day,reserved_bytes,reserved_cost,actual_cost,state FROM attempts",
        )
        .map_err(|_| ErrorCode::Storage)?;
    let mut rows = attempts.query([]).map_err(|_| ErrorCode::Storage)?;
    while let Some(row) = rows.next().map_err(|_| ErrorCode::Storage)? {
        let id: String = row.get(0).map_err(|_| ErrorCode::Storage)?;
        let job: String = row.get(1).map_err(|_| ErrorCode::Storage)?;
        let day: String = row.get(2).map_err(|_| ErrorCode::Storage)?;
        let _: u64 = row.get(3).map_err(|_| ErrorCode::Storage)?;
        let _: u64 = row.get(4).map_err(|_| ErrorCode::Storage)?;
        let cost: Option<u64> = row.get(5).map_err(|_| ErrorCode::Storage)?;
        let state: String = row.get(6).map_err(|_| ErrorCode::Storage)?;
        if !Uuid::parse_str(&id).is_ok_and(|parsed| parsed.to_string() == id)
            || !Uuid::parse_str(&job).is_ok_and(|parsed| parsed.to_string() == job)
            || !chrono::NaiveDate::parse_from_str(&day, "%Y-%m-%d")
                .is_ok_and(|parsed| parsed.format("%Y-%m-%d").to_string() == day)
            || !matches!(
                (state.as_str(), cost),
                ("reserved" | "unknown", None) | ("settled", Some(_))
            )
        {
            return Err(ErrorCode::Storage);
        }
    }
    let mut jobs = connection
        .prepare(
            "SELECT j.id,j.owner,j.state,j.created_at,j.deadline_at,j.limits_json,j.usage_json,\
        coalesce(sum(CASE WHEN a.actual_cost IS NULL THEN a.reserved_cost ELSE 0 END),0),\
        coalesce(sum(CASE WHEN a.actual_cost IS NOT NULL THEN a.actual_cost ELSE 0 END),0),\
        coalesce(sum(CASE WHEN a.state='reserved' THEN a.reserved_bytes ELSE 0 END),0)\
        FROM jobs j LEFT JOIN attempts a ON a.job_id=j.id GROUP BY j.id",
        )
        .map_err(|_| ErrorCode::Storage)?;
    let mut rows = jobs.query([]).map_err(|_| ErrorCode::Storage)?;
    while let Some(row) = rows.next().map_err(|_| ErrorCode::Storage)? {
        let id: String = row.get(0).map_err(|_| ErrorCode::Storage)?;
        let _: u32 = row.get(1).map_err(|_| ErrorCode::Storage)?;
        let state: String = row.get(2).map_err(|_| ErrorCode::Storage)?;
        let created: i64 = row.get(3).map_err(|_| ErrorCode::Storage)?;
        let deadline: i64 = row.get(4).map_err(|_| ErrorCode::Storage)?;
        let limits: String = row.get(5).map_err(|_| ErrorCode::Storage)?;
        let usage: String = row.get(6).map_err(|_| ErrorCode::Storage)?;
        let _: JobLimits = serde_json::from_str(&limits).map_err(|_| ErrorCode::Storage)?;
        let usage: Usage = serde_json::from_str(&usage).map_err(|_| ErrorCode::Storage)?;
        let held: u64 = row.get(7).map_err(|_| ErrorCode::Storage)?;
        let known: u64 = row.get(8).map_err(|_| ErrorCode::Storage)?;
        let reserved: u64 = row.get(9).map_err(|_| ErrorCode::Storage)?;
        if Uuid::parse_str(&id).is_err()
            || serde_json::from_value::<JobState>(serde_json::Value::String(state)).is_err()
            || deadline < created
            || (
                usage.held_micro_usd,
                usage.known_micro_usd,
                usage.reserved_bytes,
            ) != (held, known, reserved)
        {
            return Err(ErrorCode::Storage);
        }
    }
    Ok(())
}

fn guarded_in(
    path: &Path,
    operator: Limits,
    dir: File,
    marker_dir: File,
    marker_path: &Path,
    owners: (u32, u32),
    witness: Option<witness::WitnessClient>,
) -> Result<Arc<Ledger>> {
    let (service_owner, marker_owner) = owners;
    operator.validate()?;
    let files = GuardedFiles::open_in(
        path,
        dir,
        marker_dir,
        marker_path,
        service_owner,
        marker_owner,
        witness,
    )?;
    let connection = open_existing(path)?;
    validate_database(&connection, files.marker.identity)?;
    files.ensure_database(&connection)?;
    Ok(Arc::new(Ledger {
        connection: Mutex::new(connection),
        operator,
        guard: Some(files),
        serialization: Serialization::new(),
    }))
}

/// Open a previously provisioned ledger without SQLite's CREATE flag.
pub fn open_guarded(
    path: &Path,
    marker: &Path,
    witness_socket: &Path,
    operator: Limits,
) -> Result<Arc<Ledger>> {
    let owner = rustix::process::geteuid().as_raw();
    if owner == 0 {
        return Err(ErrorCode::PermissionDenied);
    }
    if !witness_socket.is_absolute()
        || witness_socket.file_name().is_none()
        || witness_socket
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(ErrorCode::InvalidRequest);
    }
    let dir = state_directory(path.parent().ok_or(ErrorCode::InvalidRequest)?, owner)?;
    let (marker_dir, _) = marker_directory(marker)?;
    guarded_in(
        path,
        operator,
        dir,
        marker_dir,
        marker,
        (owner, 0),
        Some(witness::WitnessClient::new(witness_socket.to_owned(), 0)),
    )
}

/// Validate the service-owned state path before opening its lock file.
pub fn validate_guarded_state(state: &Path) -> Result<()> {
    let owner = rustix::process::geteuid().as_raw();
    if owner == 0 {
        return Err(ErrorCode::PermissionDenied);
    }
    state_directory(state, owner)?;
    Ok(())
}

fn create_file(dir: &File, name: &OsStr, mode: u32, owner: u32, group: u32) -> Result<File> {
    let file = open_at(
        dir,
        name,
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL,
        mode,
    )?;
    if rustix::process::geteuid().is_root() {
        rustix::fs::fchown(
            &file,
            Some(rustix::fs::Uid::from_raw(owner)),
            Some(rustix::fs::Gid::from_raw(group)),
        )
        .map_err(|_| ErrorCode::Storage)?;
    }
    rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(mode))
        .map_err(|_| ErrorCode::Storage)?;
    checked_file(&file, owner)?;
    Ok(file)
}

fn provision_in(
    path: &Path,
    dir: File,
    marker_dir: File,
    marker_name: &OsStr,
    guard_lock: &File,
    service_identity: (u32, u32),
    marker_identity: (u32, u32),
) -> Result<()> {
    let (service_owner, service_group) = service_identity;
    let (marker_owner, marker_group) = marker_identity;
    let (database_name, journal_path, wal_path, shm_path) = names(path)?;
    absent(&marker_dir, marker_name)?;
    for item in [
        database_name,
        name(&journal_path)?,
        name(&wal_path)?,
        name(&shm_path)?,
    ] {
        absent(&dir, item)?;
    }
    let database = create_file(&dir, database_name, 0o600, service_owner, service_group)?;
    dir.sync_all().map_err(|_| ErrorCode::Storage)?;
    let identity = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp();
    let connection = open_existing(path)?;
    // SQLite creates the journal during the first transaction. Pre-creating it
    // for a zero-page database would make SQLite delete it as a stale journal.
    connection
        .execute_batch(SCHEMA)
        .map_err(|_| ErrorCode::Storage)?;
    connection
        .execute(
            "INSERT INTO ledger_identity VALUES (?1,0,?2)",
            rusqlite::params![identity.to_string(), now],
        )
        .map_err(|_| ErrorCode::Storage)?;
    validate_database(&connection, identity)?;
    drop(connection);
    let journal = open_at(&dir, name(&journal_path)?, rustix::fs::OFlags::RDWR, 0)?;
    if rustix::process::geteuid().is_root() {
        rustix::fs::fchown(
            &journal,
            Some(rustix::fs::Uid::from_raw(service_owner)),
            Some(rustix::fs::Gid::from_raw(service_group)),
        )
        .map_err(|_| ErrorCode::Storage)?;
    }
    rustix::fs::fchmod(&journal, rustix::fs::Mode::from_raw_mode(0o600))
        .map_err(|_| ErrorCode::Storage)?;
    checked_file(&journal, service_owner)?;
    if journal.metadata().map_err(|_| ErrorCode::Storage)?.len() != 0 {
        return Err(ErrorCode::Storage);
    }
    write_sentinel(&journal, identity, 0, now)?;
    database.sync_all().map_err(|_| ErrorCode::Storage)?;
    journal.sync_all().map_err(|_| ErrorCode::Storage)?;
    dir.sync_all().map_err(|_| ErrorCode::Storage)?;
    let db_meta = checked_file(&database, service_owner)?;
    let journal_meta = checked_file(&journal, service_owner)?;
    let lock_meta = checked_file(guard_lock, marker_owner)?;
    file_matches(
        &marker_dir,
        OsStr::new(GUARD_LOCK),
        guard_lock,
        marker_owner,
        lock_meta.dev(),
        lock_meta.ino(),
    )?;
    let marker = Marker {
        version: 1,
        identity,
        database_device: db_meta.dev(),
        database_inode: db_meta.ino(),
        journal_device: journal_meta.dev(),
        journal_inode: journal_meta.ino(),
        lock_device: lock_meta.dev(),
        lock_inode: lock_meta.ino(),
    };
    // Publish last. A crash or failure before this point leaves no admissible
    // marker; retry refuses all partial files instead of replacing them.
    let mut file = create_file(&marker_dir, marker_name, 0o644, marker_owner, marker_group)?;
    let data = serde_json::to_vec(&marker).map_err(|_| ErrorCode::Storage)?;
    file.write_all(&data).map_err(|_| ErrorCode::Storage)?;
    file.sync_all().map_err(|_| ErrorCode::Storage)?;
    marker_dir.sync_all().map_err(|_| ErrorCode::Storage)?;
    Ok(())
}

fn prepare_guard_lock(dir: &File, marker_name: &OsStr, owner: u32, group: u32) -> Result<()> {
    match rustix::fs::statat(dir, GUARD_LOCK, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => {
            // A published marker means initialization already happened; never
            // replace its missing lock even during a provisioning attempt.
            absent(dir, marker_name)?;
            let file = create_file(dir, OsStr::new(GUARD_LOCK), 0o644, owner, group)?;
            file.sync_all().map_err(|_| ErrorCode::Storage)?;
            dir.sync_all().map_err(|_| ErrorCode::Storage)?;
        }
        Ok(_) => (),
        Err(_) => return Err(ErrorCode::Storage),
    }
    Ok(())
}

fn lock_service(dir: &File, owner: u32) -> Result<File> {
    let lock = open_at(dir, OsStr::new(GUARD_LOCK), rustix::fs::OFlags::RDONLY, 0)?;
    let metadata = checked_file(&lock, owner)?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| ErrorCode::Capacity)?;
    file_matches(
        dir,
        OsStr::new(GUARD_LOCK),
        &lock,
        owner,
        metadata.dev(),
        metadata.ino(),
    )?;
    Ok(lock)
}

fn check_host_marker_in(dir: &File, marker_name: &OsStr, owner: u32) -> Result<()> {
    let lock = lock_service(dir, owner)?;
    let mut file = open_at(dir, marker_name, rustix::fs::OFlags::RDONLY, 0)?;
    checked_file(&file, owner)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(1025)
        .read_to_end(&mut bytes)
        .map_err(|_| ErrorCode::Storage)?;
    if bytes.len() > 1024 {
        return Err(ErrorCode::Storage);
    }
    let marker: Marker = serde_json::from_slice(&bytes).map_err(|_| ErrorCode::Storage)?;
    if marker.version != 1 {
        return Err(ErrorCode::Storage);
    }
    file_matches(
        dir,
        OsStr::new(GUARD_LOCK),
        &lock,
        owner,
        marker.lock_device,
        marker.lock_inode,
    )?;
    Ok(())
}

/// Root-only pre-start validation of the actual host marker path and lock.
/// This is a snapshot, not continuous validation after a bind mount.
pub fn check_guarded_host(marker: &Path) -> Result<()> {
    if !rustix::process::geteuid().is_root() {
        return Err(ErrorCode::PermissionDenied);
    }
    let (dir, name) = marker_directory(marker)?;
    check_host_marker_in(&dir, name, 0)
}

/// Separately authorized root-only initialization. The state and protected
/// marker directories must already exist, and no existing state is replaced.
pub fn provision_guarded(state: &Path, marker: &Path) -> Result<()> {
    if !rustix::process::geteuid().is_root() {
        return Err(ErrorCode::PermissionDenied);
    }
    let state_metadata = std::fs::symlink_metadata(state).map_err(|_| ErrorCode::Storage)?;
    if !state_metadata.is_dir() || state_metadata.uid() == 0 {
        return Err(ErrorCode::PermissionDenied);
    }
    let dir = state_directory(state, state_metadata.uid())?;
    let metadata = dir.metadata().map_err(|_| ErrorCode::Storage)?;
    let (marker_dir, marker_name) = marker_directory(marker)?;
    prepare_guard_lock(&marker_dir, marker_name, 0, 0)?;
    let lock = lock_service(&marker_dir, 0)?;
    provision_in(
        &state.join("budget.sqlite"),
        dir,
        marker_dir,
        marker_name,
        &lock,
        (metadata.uid(), metadata.gid()),
        (0, 0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::{Charge, RequestedLimits};
    use crate::error::ErrorCode;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Fixture {
        root: tempfile::TempDir,
        owner: u32,
        group: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir(root.path().join("state")).unwrap();
            std::fs::set_permissions(
                root.path().join("state"),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            std::fs::create_dir(root.path().join("guard")).unwrap();
            Self {
                root,
                owner: rustix::process::geteuid().as_raw(),
                group: rustix::process::getegid().as_raw(),
            }
        }

        fn database(&self) -> PathBuf {
            self.root.path().join("state/budget.sqlite")
        }
        fn journal(&self) -> PathBuf {
            self.root.path().join("state/budget.sqlite-journal")
        }
        fn wal(&self) -> PathBuf {
            self.root.path().join("state/budget.sqlite-wal")
        }
        fn marker(&self) -> PathBuf {
            self.root.path().join("guard/budget.marker")
        }
        fn state_dir(&self) -> File {
            File::open(self.root.path().join("state")).unwrap()
        }
        fn marker_dir(&self) -> File {
            File::open(self.root.path().join("guard")).unwrap()
        }
        fn provision(&self) -> Result<()> {
            let marker_dir = self.marker_dir();
            prepare_guard_lock(
                &marker_dir,
                OsStr::new("budget.marker"),
                self.owner,
                self.group,
            )?;
            let lock = lock_service(&marker_dir, self.owner)?;
            provision_in(
                &self.database(),
                self.state_dir(),
                marker_dir,
                OsStr::new("budget.marker"),
                &lock,
                (self.owner, self.group),
                (self.owner, self.group),
            )
        }
        fn open(&self, limits: Limits) -> Result<Arc<Ledger>> {
            guarded_in(
                &self.database(),
                limits,
                self.state_dir(),
                self.marker_dir(),
                &self.marker(),
                (self.owner, self.owner),
                None,
            )
        }
        fn open_witness(&self, path: &Path, expected_peer: u32) -> Result<Arc<Ledger>> {
            guarded_in(
                &self.database(),
                Limits::default(),
                self.state_dir(),
                self.marker_dir(),
                &self.marker(),
                (self.owner, self.owner),
                Some(witness::WitnessClient::new(path.to_owned(), expected_peer)),
            )
        }
        fn spend(&self) {
            let ledger = self.open(Limits::default()).unwrap();
            let job = ledger.start(1001, RequestedLimits::default()).unwrap();
            ledger
                .reserve(
                    1001,
                    job.id,
                    Charge {
                        micro_usd: 10,
                        ..Charge::default()
                    },
                )
                .unwrap()
                .finish(0, Some(10))
                .unwrap();
        }
    }

    struct WitnessHarness {
        path: PathBuf,
        running: Arc<std::sync::atomic::AtomicBool>,
        worker: Option<std::thread::JoinHandle<()>>,
    }

    impl WitnessHarness {
        fn start(host: &Fixture, socket_root: &Path, service_uid: u32) -> Self {
            Self::start_with_state(
                host,
                socket_root,
                service_uid,
                &host.root.path().join("state"),
            )
        }

        fn start_with_state(
            host: &Fixture,
            socket_root: &Path,
            service_uid: u32,
            state: &Path,
        ) -> Self {
            let path = socket_root.join("witness.sock");
            let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();
            let witness = witness::HostWitness::new(
                &host.marker(),
                state,
                host.root.path(),
                host.owner,
                host.owner,
            )
            .unwrap()
            .with_test_peer(service_uid);
            let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let active = running.clone();
            let worker = std::thread::spawn(move || {
                while active.load(std::sync::atomic::Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            if witness.handle(stream).is_err() {
                                break;
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                path,
                running,
                worker: Some(worker),
            }
        }

        fn stop(&mut self) {
            self.running
                .store(false, std::sync::atomic::Ordering::SeqCst);
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
            let _ = std::fs::remove_file(&self.path);
        }
    }

    impl Drop for WitnessHarness {
        fn drop(&mut self) {
            self.stop();
        }
    }

    // The listener is real, but its synthetic host path and UID are temporary.
    // Pausing before handling one connection keeps the production witness client
    // and ledger lock occupied without mounting or reading any host state.
    struct PausedWitness {
        path: PathBuf,
        pause: Arc<std::sync::atomic::AtomicBool>,
        running: Arc<std::sync::atomic::AtomicBool>,
        entered: tokio::sync::mpsc::UnboundedReceiver<()>,
        release: std::sync::mpsc::Sender<()>,
        worker: Option<std::thread::JoinHandle<()>>,
    }

    impl PausedWitness {
        fn start(fixture: &Fixture) -> Self {
            use std::sync::atomic::{AtomicBool, Ordering};
            let path = fixture.root.path().join("service-witness.sock");
            let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();
            let witness = witness::HostWitness::new(
                &fixture.marker(),
                &fixture.root.path().join("state"),
                fixture.root.path(),
                fixture.owner,
                fixture.owner,
            )
            .unwrap();
            let pause = Arc::new(AtomicBool::new(false));
            let running = Arc::new(AtomicBool::new(true));
            let paused = pause.clone();
            let active = running.clone();
            let (entered_tx, entered) = tokio::sync::mpsc::unbounded_channel();
            let (release, resume) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                while active.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            if paused.swap(false, Ordering::SeqCst) {
                                let _ = entered_tx.send(());
                                let _ = resume.recv_timeout(Duration::from_secs(3));
                            }
                            if witness.handle(stream).is_err() {
                                break;
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                path,
                pause,
                running,
                entered,
                release,
                worker: Some(worker),
            }
        }

        fn pause_next(&self) {
            self.pause.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        async fn wait_paused(&mut self) {
            tokio::time::timeout(Duration::from_secs(1), self.entered.recv())
                .await
                .unwrap()
                .unwrap();
        }

        fn resume(&self) {
            self.release.send(()).unwrap();
        }

        fn stop(&mut self) {
            self.running
                .store(false, std::sync::atomic::Ordering::SeqCst);
            let _ = self.release.send(());
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
            let _ = std::fs::remove_file(&self.path);
        }
    }

    impl Drop for PausedWitness {
        fn drop(&mut self) {
            self.stop();
        }
    }

    struct FixturePaidTransport {
        ledger: Arc<Ledger>,
        posts: std::sync::atomic::AtomicUsize,
        posted: tokio::sync::Notify,
        respond: tokio::sync::Notify,
        settling: tokio::sync::Notify,
        long_body: std::sync::atomic::AtomicBool,
        job_stop: Mutex<Option<tokio_util::sync::CancellationToken>>,
    }

    #[async_trait::async_trait]
    impl crate::http::Transport for FixturePaidTransport {
        async fn get(
            &self,
            _: u32,
            _: Uuid,
            _: crate::http::HttpRequest,
            _: &tokio_util::sync::CancellationToken,
        ) -> Result<crate::http::HttpResponse> {
            Err(ErrorCode::ProviderUnavailable)
        }

        async fn post(
            &self,
            owner: u32,
            job: Uuid,
            request: crate::http::HttpRequest,
            _: Vec<u8>,
            stop: &tokio_util::sync::CancellationToken,
        ) -> Result<crate::http::HttpResponse> {
            *self.job_stop.lock().unwrap() = Some(stop.clone());
            let mut reservation = self.ledger.reserve(
                owner,
                job,
                Charge {
                    bytes: request.max_bytes + 1,
                    requests: 1,
                    queries: 1,
                    micro_usd: request.micro_usd,
                    ..Charge::default()
                },
            )?;
            self.posts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.posted.notify_one();
            self.respond.notified().await;
            let body = if self.long_body.load(std::sync::atomic::Ordering::SeqCst) {
                let hits: Vec<_> = (0..5)
                    .map(|index| {
                        serde_json::json!({
                            "title": format!("Fixture {index}"),
                            "url": format!("https://example.com/{index}"),
                            "description": "Synthetic ".repeat(150),
                        })
                    })
                    .collect();
                serde_json::to_vec(&serde_json::json!({"content": hits})).unwrap()
            } else {
                br#"{"content":[{"title":"Fixture","url":"https://example.com/","description":"Synthetic"}]}"#.to_vec()
            };
            reservation.remember_cost(Some(request.micro_usd));
            self.settling.notify_one();
            reservation
                .finish_serialized(body.len() as u64, Some(request.micro_usd))
                .await?;
            Ok(crate::http::HttpResponse {
                status: 200,
                headers: http::HeaderMap::new(),
                body,
            })
        }
    }

    struct GuardedServiceFixture {
        witness: PausedWitness,
        ledger: Arc<Ledger>,
        service: Arc<crate::service::Service>,
        transport: Arc<FixturePaidTransport>,
        owner: u32,
        connection: Uuid,
        ready: crate::egress::EgressState,
        _files: Fixture,
    }

    impl GuardedServiceFixture {
        async fn new() -> Self {
            use crate::config::{Capability, Config, DataClass, Privacy, ProviderConfig};
            use crate::service::{Dependencies, Service};
            let fixture = Fixture::new();
            fixture.provision().unwrap();
            let witness = PausedWitness::start(&fixture);
            let ledger = fixture.open_witness(&witness.path, fixture.owner).unwrap();
            let provider = ProviderConfig {
                endpoint: None,
                enable: true,
                capabilities: [Capability::Search].into(),
                data: [DataClass::Queries].into(),
                credential: Some("spider".into()),
                storage_rights: false,
                model: None,
                request_micro_usd: Some(10),
            };
            let config = Config {
                state_directory: fixture.root.path().join("state"),
                ledger_guard_marker: Some(fixture.marker()),
                ledger_guard_witness_socket: Some(witness.path.clone()),
                allowed_client_uids: vec![fixture.owner],
                egress_uid: Some(0),
                privacy: Privacy::Strict,
                providers: [("spider".into(), provider.clone())].into(),
                search_order: vec!["spider".into()],
                limits: Limits {
                    result_bytes: 4096,
                    ..Limits::default()
                },
                ..Config::default()
            };
            let store =
                crate::store::EvidenceStore::open(&config, fixture.root.path().to_owned()).unwrap();
            let transport = Arc::new(FixturePaidTransport {
                ledger: ledger.clone(),
                posts: std::sync::atomic::AtomicUsize::new(0),
                posted: tokio::sync::Notify::new(),
                respond: tokio::sync::Notify::new(),
                settling: tokio::sync::Notify::new(),
                long_body: std::sync::atomic::AtomicBool::new(false),
                job_stop: Mutex::new(None),
            });
            let service = Service::new(
                config,
                Dependencies {
                    ledger: ledger.clone(),
                    store,
                    http: transport.clone(),
                    parser: None,
                    search_providers: vec![Arc::new(
                        crate::provider::Spider::new(&provider, b"fixture-key").unwrap(),
                    )],
                    scrape_providers: vec![],
                    summarize_providers: vec![],
                },
            )
            .unwrap();
            let ready = crate::egress::EgressState {
                version: 1,
                generation: Uuid::new_v4(),
                mode: crate::egress::EgressMode::Ready,
                valid_until: chrono::Utc::now().timestamp() + 10,
                region: None,
            };
            service.update_egress(ready.clone()).await.unwrap();
            let owner = fixture.owner;
            Self {
                _files: fixture,
                witness,
                ledger,
                service,
                transport,
                owner,
                connection: Uuid::new_v4(),
                ready,
            }
        }

        async fn job(&self) -> Uuid {
            let result = self
                .service
                .call(
                    self.owner,
                    self.connection,
                    crate::protocol::Tool::ResearchJob,
                    serde_json::json!({"operation":"start"}),
                    tokio_util::sync::CancellationToken::new(),
                )
                .await
                .unwrap();
            serde_json::from_value(result["job"]["id"].clone()).unwrap()
        }
    }

    #[test]
    fn service_start_rechecks_cancel_while_egress_and_readiness_remain_responsive() {
        use crate::protocol::Tool;
        use tokio_util::sync::CancellationToken;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut fixture = GuardedServiceFixture::new().await;
            let service = fixture.service.clone();
            let owner = fixture.owner;
            let connection = fixture.connection;
            let request_stop = CancellationToken::new();
            let start_stop = request_stop.clone();
            fixture.witness.pause_next();
            let start = tokio::spawn(async move {
                service
                    .call(
                        owner,
                        connection,
                        Tool::ResearchJob,
                        serde_json::json!({"operation":"start"}),
                        start_stop,
                    )
                    .await
            });
            fixture.witness.wait_paused().await;
            let service = fixture.service.clone();
            let refreshed = fixture.ready.clone();
            let events = tokio::spawn(async move {
                request_stop.cancel();
                service.update_egress(refreshed).await?;
                service
                    .call(
                        owner,
                        connection,
                        Tool::ResearchJob,
                        serde_json::json!({"operation":"readiness"}),
                        CancellationToken::new(),
                    )
                    .await
            });
            let begin = std::time::Instant::now();
            let progress = tokio::time::timeout(Duration::from_secs(1), events).await;
            let elapsed = begin.elapsed();
            fixture.witness.resume();
            let start_result = tokio::time::timeout(Duration::from_secs(4), start)
                .await
                .unwrap()
                .unwrap();
            let readiness = progress.unwrap().unwrap().unwrap();
            assert!(elapsed < Duration::from_secs(1));
            assert_eq!(readiness["egress"]["mode"], "ready");
            assert!(matches!(start_result, Err(ErrorCode::Cancelled)));
            let db = fixture.ledger.connection.lock().unwrap();
            let active: u64 = db
                .query_row(
                    "SELECT count(*) FROM jobs WHERE state='active'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(active, 0);
        });
    }

    #[test]
    fn runtime_shutdown_during_guarded_start_reconciles_on_a_later_runtime() {
        use crate::protocol::Tool;
        use tokio_util::sync::CancellationToken;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let mut fixture = runtime.block_on(GuardedServiceFixture::new());
        let owner = fixture.owner;
        let connection = fixture.connection;
        let service = fixture.service.clone();
        fixture.witness.pause_next();
        let start = runtime.spawn(async move {
            service
                .call(
                    owner,
                    connection,
                    Tool::ResearchJob,
                    serde_json::json!({"operation":"start"}),
                    CancellationToken::new(),
                )
                .await
        });
        runtime.block_on(fixture.witness.wait_paused());
        // This drops the caller runtime while ledger start still owns a blocked
        // witness exchange. Only this synthetic temporary state is involved.
        runtime.shutdown_timeout(Duration::from_millis(50));
        drop(start);
        fixture.witness.resume();
        let later = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        later.block_on(async {
            tokio::time::timeout(Duration::from_secs(4), fixture.service.shutdown())
                .await
                .unwrap()
                .unwrap();
        });
        let db = fixture.ledger.connection.lock().unwrap();
        let active: u64 = db
            .query_row(
                "SELECT count(*) FROM jobs WHERE state='active'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active, 0);
    }

    #[test]
    fn pending_start_is_reconciled_on_disconnect_shutdown_or_egress_change() {
        use crate::protocol::Tool;
        use tokio_util::sync::CancellationToken;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            for reason in ["disconnect", "shutdown", "egress", "abort"] {
                let mut fixture = GuardedServiceFixture::new().await;
                let owner = fixture.owner;
                let connection = fixture.connection;
                let service = fixture.service.clone();
                fixture.witness.pause_next();
                let start = tokio::spawn(async move {
                    service
                        .call(
                            owner,
                            connection,
                            Tool::ResearchJob,
                            serde_json::json!({"operation":"start"}),
                            CancellationToken::new(),
                        )
                        .await
                });
                fixture.witness.wait_paused().await;
                if reason == "abort" {
                    start.abort();
                }
                let service = fixture.service.clone();
                let mut next = fixture.ready.clone();
                next.generation = Uuid::new_v4();
                let generation = next.generation.to_string();
                let lifecycle = tokio::spawn(async move {
                    match reason {
                        "disconnect" => service.disconnect(connection).await,
                        "shutdown" | "abort" => service.shutdown().await,
                        _ => service.update_egress(next).await,
                    }
                });
                let service = fixture.service.clone();
                let probe = tokio::spawn(async move {
                    loop {
                        let value = service
                            .call(
                                owner,
                                connection,
                                Tool::ResearchJob,
                                serde_json::json!({"operation":"readiness"}),
                                CancellationToken::new(),
                            )
                            .await?;
                        if reason == "disconnect"
                            || (matches!(reason, "shutdown" | "abort")
                                && value["accepting"] == false)
                            || (reason == "egress" && value["egress"]["generation"] == generation)
                        {
                            return Ok::<_, ErrorCode>(value);
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                });
                let progress = tokio::time::timeout(Duration::from_secs(1), probe).await;
                if reason == "disconnect" {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                fixture.witness.resume();
                let start = tokio::time::timeout(Duration::from_secs(4), start)
                    .await
                    .unwrap();
                tokio::time::timeout(Duration::from_secs(4), lifecycle)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert!(progress.unwrap().unwrap().is_ok(), "{reason}");
                if reason == "abort" {
                    assert!(start.unwrap_err().is_cancelled());
                } else {
                    assert!(
                        start.unwrap().is_err(),
                        "{reason} admitted an invalidated start"
                    );
                }
                let db = fixture.ledger.connection.lock().unwrap();
                let active: u64 = db
                    .query_row(
                        "SELECT count(*) FROM jobs WHERE state='active'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(active, 0, "{reason}");
            }
        });
    }

    #[test]
    fn service_admit_rechecks_egress_and_cancel_after_stalled_ledger() {
        use crate::egress::EgressMode;
        use crate::protocol::Tool;
        use tokio_util::sync::CancellationToken;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut fixture = GuardedServiceFixture::new().await;
            let id = fixture.job().await;
            let service = fixture.service.clone();
            let owner = fixture.owner;
            let connection = fixture.connection;
            fixture.witness.pause_next();
            let work = tokio::spawn(async move {
                service.call(owner, connection, Tool::ResearchSearch,
                    serde_json::json!({"job_id":id,"queries":[{"q":"battery recycling","count":1}]}),
                    CancellationToken::new()).await
            });
            fixture.witness.wait_paused().await;
            let service = fixture.service.clone();
            let cancel = tokio::spawn(async move {
                service.call(owner, connection, Tool::ResearchJob,
                    serde_json::json!({"operation":"cancel","job_id":id}), CancellationToken::new()).await
            });
            let service = fixture.service.clone();
            let mut draining = fixture.ready.clone();
            draining.mode = EgressMode::Draining;
            let probe = tokio::spawn(async move {
                service.update_egress(draining).await?;
                service.call(owner, connection, Tool::ResearchJob,
                    serde_json::json!({"operation":"readiness"}), CancellationToken::new()).await
            });
            let begin = std::time::Instant::now();
            let progress = tokio::time::timeout(Duration::from_secs(1), probe).await;
            let elapsed = begin.elapsed();
            fixture.witness.resume();
            let outcome = tokio::time::timeout(Duration::from_secs(4), work).await.unwrap().unwrap();
            let closed = tokio::time::timeout(Duration::from_secs(4), cancel).await.unwrap().unwrap().unwrap();
            let readiness = progress.unwrap().unwrap().unwrap();
            assert!(elapsed < Duration::from_secs(1));
            assert_eq!(readiness["egress"]["mode"], "draining");
            assert!(matches!(outcome, Err(ErrorCode::JobClosed | ErrorCode::EgressUnavailable | ErrorCode::Cancelled)));
            assert_eq!(closed["job"]["state"], "cancelled");
            assert_eq!(fixture.transport.posts.load(std::sync::atomic::Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn service_receipt_settlement_and_cancel_survive_contended_status() {
        use crate::protocol::Tool;
        use tokio_util::sync::CancellationToken;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            for scenario in ["complete", "cancel", "abort"] {
                let mut fixture = GuardedServiceFixture::new().await;
                let id = fixture.job().await;
                let owner = fixture.owner;
                let connection = fixture.connection;
                let service = fixture.service.clone();
                let work = tokio::spawn(async move {
                    service.call(owner, connection, Tool::ResearchSearch,
                        serde_json::json!({"job_id":id,"queries":[{"q":"battery recycling","count":1}]}),
                        CancellationToken::new()).await
                });
                tokio::time::timeout(Duration::from_secs(1), fixture.transport.posted.notified()).await.unwrap();
                fixture.witness.pause_next();
                let service = fixture.service.clone();
                let status = tokio::spawn(async move {
                    service.call(owner, connection, Tool::ResearchJob,
                        serde_json::json!({"operation":"status","job_id":id}), CancellationToken::new()).await
                });
                fixture.witness.wait_paused().await;
                fixture.transport.respond.notify_one();
                tokio::time::timeout(Duration::from_secs(1), fixture.transport.settling.notified()).await.unwrap();
                if scenario == "abort" { work.abort(); }
                let cancel = if scenario != "complete" {
                    let service = fixture.service.clone();
                    Some(tokio::spawn(async move {
                        service.call(owner, connection, Tool::ResearchJob,
                            serde_json::json!({"operation":"cancel","job_id":id}), CancellationToken::new()).await
                    }))
                } else { None };
                let cancellation = if scenario != "complete" {
                    let stop = fixture.transport.job_stop.lock().unwrap().clone().unwrap();
                    tokio::time::timeout(Duration::from_secs(1), stop.cancelled()).await.is_ok()
                } else { true };
                let service = fixture.service.clone();
                let probe = tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    service.call(owner, connection, Tool::ResearchJob,
                        serde_json::json!({"operation":"readiness"}), CancellationToken::new()).await
                });
                let begin = std::time::Instant::now();
                let progress = tokio::time::timeout(Duration::from_secs(1), probe).await;
                let elapsed = begin.elapsed();
                fixture.witness.resume();
                let _ = tokio::time::timeout(Duration::from_secs(4), status).await.unwrap().unwrap();
                let result = tokio::time::timeout(Duration::from_secs(4), work).await.unwrap();
                if let Some(cancel) = cancel {
                    let closed = tokio::time::timeout(Duration::from_secs(4), cancel).await.unwrap().unwrap().unwrap();
                    assert_eq!(closed["job"]["state"], "cancelled");
                    if scenario == "cancel" { assert!(result.unwrap().is_err()); }
                    else { assert!(result.unwrap_err().is_cancelled()); }
                } else {
                    let completed = result.unwrap().unwrap();
                    assert_eq!(completed["items"][0]["state"], "success");
                }
                assert!(progress.unwrap().unwrap().is_ok());
                assert!(cancellation, "{scenario} cancellation did not propagate while the witness was stalled");
                assert!(elapsed < Duration::from_secs(1));
                assert_eq!(fixture.transport.posts.load(std::sync::atomic::Ordering::SeqCst), 1);
                let job = fixture.ledger.get(owner, id).unwrap();
                assert_eq!(job.usage.known_micro_usd, 10, "{scenario}");
                assert_eq!(job.usage.held_micro_usd, 0, "{scenario}");
                assert_eq!(job.usage.requests, 1, "{scenario}");
            }
        });
    }

    #[test]
    fn failed_receipt_settlement_cannot_be_reported_as_closed() {
        use crate::protocol::Tool;
        use tokio_util::sync::CancellationToken;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut fixture = GuardedServiceFixture::new().await;
            let id = fixture.job().await;
            let owner = fixture.owner;
            let connection = fixture.connection;
            // First retain real job-scoped report and evidence; an accounting
            // failure on the next operation must not prevent their cleanup.
            fixture.transport.long_body.store(true, std::sync::atomic::Ordering::SeqCst);
            let service = fixture.service.clone();
            let saved = tokio::spawn(async move {
                service.call(owner, connection, Tool::ResearchSearch,
                    serde_json::json!({"job_id":id,"queries":[{"q":"existing evidence","count":5}]}),
                    CancellationToken::new()).await
            });
            tokio::time::timeout(Duration::from_secs(1), fixture.transport.posted.notified()).await.unwrap();
            fixture.transport.respond.notify_one();
            tokio::time::timeout(Duration::from_secs(1), fixture.transport.settling.notified()).await.unwrap();
            let saved = tokio::time::timeout(Duration::from_secs(4), saved).await.unwrap().unwrap().unwrap();
            let report = saved["report_id"].clone();
            assert!(!report.is_null());
            let read_report = || serde_json::json!({"kind":"report","report_id":report});
            fixture.service.call(owner, connection, Tool::ResearchRead, read_report(), CancellationToken::new()).await.unwrap();
            let evidence_directory = || std::fs::read_dir(fixture._files.root.path()).unwrap().any(|entry| {
                entry.unwrap().file_name().to_string_lossy().starts_with("evidence-")
            });
            assert!(evidence_directory());
            fixture.transport.long_body.store(false, std::sync::atomic::Ordering::SeqCst);
            let service = fixture.service.clone();
            let work = tokio::spawn(async move {
                service.call(owner, connection, Tool::ResearchSearch,
                    serde_json::json!({"job_id":id,"queries":[{"q":"battery recycling","count":1}]}),
                    CancellationToken::new()).await
            });
            tokio::time::timeout(Duration::from_secs(1), fixture.transport.posted.notified()).await.unwrap();
            fixture.witness.pause_next();
            let service = fixture.service.clone();
            let status = tokio::spawn(async move {
                service.call(owner, connection, Tool::ResearchJob,
                    serde_json::json!({"operation":"status","job_id":id}), CancellationToken::new()).await
            });
            fixture.witness.wait_paused().await;
            fixture.transport.respond.notify_one();
            tokio::time::timeout(Duration::from_secs(1), fixture.transport.settling.notified()).await.unwrap();
            fixture.witness.stop();
            let _ = tokio::time::timeout(Duration::from_secs(4), status).await.unwrap();
            let result = tokio::time::timeout(Duration::from_secs(4), work).await.unwrap().unwrap();
            assert!(result.is_err());
            let closed = fixture.service.call(owner, connection, Tool::ResearchJob,
                serde_json::json!({"operation":"cancel","job_id":id}), CancellationToken::new()).await;
            assert!(closed.is_err());
            let read = fixture.service.call(owner, connection, Tool::ResearchRead, read_report(), CancellationToken::new()).await;
            assert!(matches!(read, Err(ErrorCode::SourceExpired)));
            assert!(!evidence_directory());
            let status = fixture.service.call(owner, connection, Tool::ResearchJob,
                serde_json::json!({"operation":"status","job_id":id}), CancellationToken::new()).await;
            assert!(status.is_err());
            let db = fixture.ledger.connection.lock().unwrap();
            let encoded: String = db.query_row("SELECT usage_json FROM jobs WHERE id=?1", [id.to_string()], |row| row.get(0)).unwrap();
            let usage: Usage = serde_json::from_str(&encoded).unwrap();
            assert_eq!(usage.held_micro_usd, 10);
            assert_eq!(usage.known_micro_usd, 10);
        });
    }

    #[test]
    fn stalled_witness_cannot_starve_two_worker_runtime() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio_util::sync::CancellationToken;

        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let socket_path = fixture.root.path().join("witness.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let witness = witness::HostWitness::new(
            &fixture.marker(),
            &fixture.root.path().join("state"),
            fixture.root.path(),
            fixture.owner,
            fixture.owner,
        )
        .unwrap();
        let stall = Arc::new(AtomicBool::new(false));
        let server_stall = stall.clone();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let mut entered = Some(entered_tx);
            loop {
                match listener.accept() {
                    Ok((stream, _)) if server_stall.load(Ordering::SeqCst) => {
                        let _ = entered.take().unwrap().send(());
                        let _ = release_rx.recv_timeout(Duration::from_secs(3));
                        drop(stream);
                        break;
                    }
                    Ok((stream, _)) => {
                        if witness.handle(stream).is_err() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        let ledger = fixture.open_witness(&socket_path, fixture.owner).unwrap();
        let job_id = ledger.start(1001, RequestedLimits::default()).unwrap().id;
        stall.store(true, Ordering::SeqCst);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (progress, first) = runtime.block_on(async {
            let waiting_ledger = ledger.clone();
            let first = tokio::spawn(async move { waiting_ledger.get(1001, job_id) });
            tokio::time::timeout(Duration::from_secs(1), entered_rx)
                .await
                .unwrap()
                .unwrap();
            let contested_ledger = ledger.clone();
            let second = tokio::spawn(async move { contested_ledger.get(1001, job_id) });
            let cancel = CancellationToken::new();
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let monitor = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(25)).await;
                cancel.cancel();
                cancel.cancelled().await;
                ready_tx.send(()).unwrap();
            });
            let progress = tokio::time::timeout(Duration::from_secs(1), async {
                let result = second.await.unwrap();
                ready_rx.await.unwrap();
                monitor.await.unwrap();
                result
            })
            .await;
            let _ = release_tx.send(());
            let first = tokio::time::timeout(Duration::from_secs(3), first)
                .await
                .unwrap()
                .unwrap();
            (progress, first)
        });
        server.join().unwrap();
        assert!(matches!(progress, Ok(Err(ErrorCode::Capacity))));
        assert!(first.is_err());
    }

    #[test]
    fn witness_matching_then_missing_blocks_paid_admission() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let mut witness = WitnessHarness::start(&fixture, fixture.root.path(), fixture.owner);
        let ledger = fixture.open_witness(&witness.path, fixture.owner).unwrap();
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let mut dispatches = 0;
        let reservation = ledger
            .reserve(
                1001,
                job.id,
                Charge {
                    micro_usd: 1,
                    ..Charge::default()
                },
            )
            .unwrap();
        dispatches += 1;
        reservation.finish(0, Some(1)).unwrap();
        witness.stop();
        if let Ok(reservation) = ledger.reserve(
            1001,
            job.id,
            Charge {
                micro_usd: 1,
                ..Charge::default()
            },
        ) {
            dispatches += 1;
            drop(reservation);
        }
        assert_eq!(dispatches, 1);
    }

    #[test]
    fn witness_loss_preserves_an_uncertain_hold_across_recovery() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let job_id = {
            let mut witness = WitnessHarness::start(&fixture, fixture.root.path(), fixture.owner);
            let ledger = fixture.open_witness(&witness.path, fixture.owner).unwrap();
            let job = ledger.start(1001, RequestedLimits::default()).unwrap();
            let hold = ledger
                .reserve(
                    1001,
                    job.id,
                    Charge {
                        micro_usd: 17,
                        ..Charge::default()
                    },
                )
                .unwrap();
            witness.stop();
            assert_eq!(hold.finish(0, Some(17)).err(), Some(ErrorCode::Storage));
            job.id
        };
        let witness = WitnessHarness::start(&fixture, fixture.root.path(), fixture.owner);
        let ledger = fixture.open_witness(&witness.path, fixture.owner).unwrap();
        ledger.recover().unwrap();
        let recovered = ledger.get(1001, job_id).unwrap();
        assert_eq!(recovered.state, JobState::Interrupted);
        assert_eq!(recovered.usage.held_micro_usd, 17);
    }

    #[test]
    fn witness_restart_epoch_is_stale_and_denies_paid_admission() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let mut first = WitnessHarness::start(&fixture, fixture.root.path(), fixture.owner);
        let ledger = fixture.open_witness(&first.path, fixture.owner).unwrap();
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        first.stop();
        let _second = WitnessHarness::start(&fixture, fixture.root.path(), fixture.owner);
        assert_eq!(
            ledger
                .reserve(
                    1001,
                    job.id,
                    Charge {
                        micro_usd: 1,
                        ..Charge::default()
                    }
                )
                .err(),
            Some(ErrorCode::Storage)
        );
    }

    #[test]
    fn mismatched_witness_and_wrong_peers_refuse_before_paid_work() {
        let local = Fixture::new();
        local.provision().unwrap();
        let remote = Fixture::new();
        remote.provision().unwrap();
        {
            let witness = WitnessHarness::start(&remote, local.root.path(), local.owner);
            assert!(local.open_witness(&witness.path, local.owner).is_err());
        }
        {
            let witness =
                WitnessHarness::start(&local, local.root.path(), local.owner.wrapping_add(1));
            assert!(local.open_witness(&witness.path, local.owner).is_err());
        }
        {
            let witness = WitnessHarness::start(&local, local.root.path(), local.owner);
            assert_eq!(
                local
                    .open_witness(&witness.path, local.owner.wrapping_add(1))
                    .err(),
                Some(ErrorCode::PermissionDenied)
            );
        }
        let connection = open_existing(&local.database()).unwrap();
        let attempts: u64 = connection
            .query_row("SELECT count(*) FROM attempts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(attempts, 0);
    }

    #[test]
    fn replaced_host_marker_path_kills_witness_and_refuses_admission() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let witness = WitnessHarness::start(&fixture, fixture.root.path(), fixture.owner);
        let ledger = fixture.open_witness(&witness.path, fixture.owner).unwrap();
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let guard = ledger.guard.as_ref().unwrap();
        let evidence = guard.witness_evidence().unwrap();
        std::fs::rename(
            fixture.root.path().join("guard"),
            fixture.root.path().join("old-guard"),
        )
        .unwrap();
        std::fs::create_dir(fixture.root.path().join("guard")).unwrap();
        let client = witness::WitnessClient::new(witness.path.clone(), fixture.owner);
        assert!(client.verify(&evidence).is_err());
        assert_eq!(
            ledger
                .reserve(
                    1001,
                    job.id,
                    Charge {
                        micro_usd: 1,
                        ..Charge::default()
                    }
                )
                .err(),
            Some(ErrorCode::Storage)
        );
    }

    #[test]
    fn witness_state_identity_must_match_the_service_directory() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let other = fixture.root.path().join("other-state");
        std::fs::create_dir(&other).unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o700)).unwrap();
        let witness =
            WitnessHarness::start_with_state(&fixture, fixture.root.path(), fixture.owner, &other);
        assert!(fixture.open_witness(&witness.path, fixture.owner).is_err());
    }

    #[test]
    fn missing_replaced_symlinked_or_unsafe_host_state_blocks_admission() {
        for change in ["missing", "replaced", "symlink", "mode"] {
            let fixture = Fixture::new();
            fixture.provision().unwrap();
            let witness = WitnessHarness::start(&fixture, fixture.root.path(), fixture.owner);
            let ledger = fixture.open_witness(&witness.path, fixture.owner).unwrap();
            let job = ledger.start(1001, RequestedLimits::default()).unwrap();
            let evidence = ledger.guard.as_ref().unwrap().witness_evidence().unwrap();
            let client = witness::WitnessClient::new(witness.path.clone(), fixture.owner);
            client.verify(&evidence).unwrap();
            let state = fixture.root.path().join("state");
            if change == "mode" {
                std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
            } else {
                std::fs::rename(&state, fixture.root.path().join("old-state")).unwrap();
                if change == "replaced" {
                    std::fs::create_dir(&state).unwrap();
                    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                } else if change == "symlink" {
                    symlink("old-state", &state).unwrap();
                }
            }
            // Exercise the host witness directly, independently of the
            // service's own pathname checks in a non-bind-mounted fixture.
            assert!(client.verify(&evidence).is_err(), "{change}");
            assert_eq!(
                ledger
                    .reserve(
                        1001,
                        job.id,
                        Charge {
                            micro_usd: 1,
                            ..Charge::default()
                        }
                    )
                    .err(),
                Some(ErrorCode::Storage)
            );
        }
    }

    #[test]
    fn unsafe_state_ancestors_are_rejected_even_when_state_inode_is_unchanged() {
        for change in ["replaced", "symlink", "mode"] {
            let fixture = Fixture::new();
            fixture.provision().unwrap();
            let root = fixture.root.path();
            let parent = root.join("state-parent");
            std::fs::create_dir(&parent).unwrap();
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
            let state = parent.join("state");
            std::fs::rename(root.join("state"), &state).unwrap();
            let witness = WitnessHarness::start_with_state(&fixture, root, fixture.owner, &state);
            let marker_bytes = std::fs::read(fixture.marker()).unwrap();
            let marker: Marker = serde_json::from_slice(&marker_bytes).unwrap();
            let marker_meta = std::fs::metadata(fixture.marker()).unwrap();
            let directory = std::fs::metadata(root.join("guard")).unwrap();
            let original = std::fs::metadata(&state).unwrap();
            let evidence = witness::Evidence {
                state_directory: (original.dev(), original.ino()),
                state_owner: original.uid(),
                state_mode: original.mode(),
                directory: (directory.dev(), directory.ino()),
                marker: (marker_meta.dev(), marker_meta.ino()),
                lock: (marker.lock_device, marker.lock_inode),
                digest: witness::digest(&marker_bytes),
            };
            let client = witness::WitnessClient::new(witness.path.clone(), fixture.owner);
            client.verify(&evidence).unwrap();
            if change == "mode" {
                std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
            } else {
                let old_parent = root.join("old-state-parent");
                std::fs::rename(&parent, &old_parent).unwrap();
                if change == "symlink" {
                    symlink("old-state-parent", &parent).unwrap();
                } else {
                    std::fs::create_dir(&parent).unwrap();
                    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                    std::fs::rename(old_parent.join("state"), &state).unwrap();
                }
            }
            let current = std::fs::metadata(&state).unwrap();
            assert_eq!((current.dev(), current.ino()), evidence.state_directory);
            assert!(client.verify(&evidence).is_err(), "{change}");
        }
    }

    #[test]
    fn provisioning_uses_the_service_singleton_lock() {
        let fixture = Fixture::new();
        let dir = fixture.marker_dir();
        prepare_guard_lock(
            &dir,
            OsStr::new("budget.marker"),
            fixture.owner,
            fixture.group,
        )
        .unwrap();
        let running = lock_service(&dir, fixture.owner).unwrap();
        let legacy = fixture.root.path().join("state/service.lock");
        std::fs::write(&legacy, b"replaceable legacy lock").unwrap();
        std::fs::remove_file(&legacy).unwrap();
        assert!(matches!(
            lock_service(&dir, fixture.owner),
            Err(ErrorCode::Capacity)
        ));
        assert!(!fixture.database().exists());
        drop(running);
        fixture.provision().unwrap();
    }

    #[test]
    fn protected_lock_rejects_symlinks_and_unsafe_replacement() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let dir = fixture.marker_dir();
        let lock_path = fixture.root.path().join("guard/ledger.lock");
        std::fs::rename(&lock_path, fixture.root.path().join("guard/old-lock")).unwrap();
        symlink("old-lock", &lock_path).unwrap();
        assert!(lock_service(&dir, fixture.owner).is_err());
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::write(&lock_path, b"replacement").unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(lock_service(&dir, fixture.owner).is_err());
    }

    #[test]
    fn live_lock_deletion_refuses_admission_and_never_reprovisions_lock() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let ledger = fixture.open(Limits::default()).unwrap();
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let lock_path = fixture.root.path().join("guard/ledger.lock");
        std::fs::remove_file(&lock_path).unwrap();
        assert_eq!(
            ledger
                .reserve(
                    1001,
                    job.id,
                    Charge {
                        micro_usd: 1,
                        ..Charge::default()
                    }
                )
                .err(),
            Some(ErrorCode::Storage)
        );
        assert!(fixture.provision().is_err());
        assert!(!lock_path.exists());
        // Even an operator-created replacement cannot match the protected
        // marker's original lock inode while the original lock remains held.
        std::fs::write(&lock_path, b"replacement").unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(fixture.open(Limits::default()).is_err());
        assert!(
            check_host_marker_in(
                &fixture.marker_dir(),
                OsStr::new("budget.marker"),
                fixture.owner
            )
            .is_err()
        );
    }

    #[test]
    fn host_prestart_checks_real_marker_and_protected_lock() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let dir = fixture.marker_dir();
        check_host_marker_in(&dir, OsStr::new("budget.marker"), fixture.owner).unwrap();
        std::fs::write(fixture.marker(), b"{").unwrap();
        assert!(check_host_marker_in(&dir, OsStr::new("budget.marker"), fixture.owner).is_err());
        std::fs::remove_file(fixture.marker()).unwrap();
        assert!(check_host_marker_in(&dir, OsStr::new("budget.marker"), fixture.owner).is_err());
    }

    #[test]
    fn public_provisioning_refuses_unprivileged_callers() {
        if !rustix::process::geteuid().is_root() {
            let fixture = Fixture::new();
            assert_eq!(
                provision_guarded(&fixture.root.path().join("state"), &fixture.marker()).err(),
                Some(ErrorCode::PermissionDenied)
            );
            assert!(!fixture.database().exists());
        }
    }

    #[test]
    fn unprovisioned_and_partial_provision_never_admit_or_reinitialize() {
        let fixture = Fixture::new();
        assert!(fixture.open(Limits::default()).is_err());
        assert!(!fixture.database().exists());
        std::fs::write(fixture.database(), b"partial").unwrap();
        assert!(fixture.provision().is_err());
        assert_eq!(std::fs::read(fixture.database()).unwrap(), b"partial");
        assert!(!fixture.marker().exists());
        assert!(fixture.open(Limits::default()).is_err());

        // Simulate a crash after the database/journal were synced but before
        // the root-owned marker was durably published.
        let interrupted = Fixture::new();
        interrupted.provision().unwrap();
        std::fs::remove_file(interrupted.marker()).unwrap();
        assert!(interrupted.open(Limits::default()).is_err());
        assert!(interrupted.provision().is_err());
        std::fs::write(interrupted.marker(), b"{").unwrap();
        assert!(interrupted.open(Limits::default()).is_err());
        assert!(interrupted.provision().is_err());
    }

    #[test]
    fn provision_is_one_time_and_missing_spent_database_is_not_recreated() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        assert!(fixture.provision().is_err());
        fixture.spend();
        std::fs::remove_file(fixture.database()).unwrap();
        assert!(fixture.open(Limits::default()).is_err());
        assert!(fixture.provision().is_err());
        assert!(!fixture.database().exists());
    }

    #[test]
    fn marker_mismatch_corruption_and_inconsistent_accounting_refuse() {
        let mismatch = Fixture::new();
        mismatch.provision().unwrap();
        let saved = std::fs::read(mismatch.journal()).unwrap();
        let last_observed = i64::from_be_bytes(saved[56..64].try_into().unwrap());
        let mut marker: Marker =
            serde_json::from_slice(&std::fs::read(mismatch.marker()).unwrap()).unwrap();
        marker.identity = Uuid::new_v4();
        std::fs::write(mismatch.marker(), serde_json::to_vec(&marker).unwrap()).unwrap();
        let journal = std::fs::OpenOptions::new()
            .write(true)
            .open(mismatch.journal())
            .unwrap();
        write_sentinel(&journal, marker.identity, 0, last_observed).unwrap();
        assert!(mismatch.open(Limits::default()).is_err());

        let corrupt = Fixture::new();
        corrupt.provision().unwrap();
        std::fs::write(corrupt.database(), b"not a database").unwrap();
        assert!(corrupt.open(Limits::default()).is_err());

        let inconsistent = Fixture::new();
        inconsistent.provision().unwrap();
        inconsistent.spend();
        let saved = std::fs::read(inconsistent.journal()).unwrap();
        let generation = i64::from_be_bytes(saved[48..56].try_into().unwrap());
        let last_observed = i64::from_be_bytes(saved[56..64].try_into().unwrap());
        let connection = open_existing(&inconsistent.database()).unwrap();
        connection
            .execute("UPDATE jobs SET usage_json='{}'", [])
            .unwrap();
        drop(connection);
        let marker: Marker =
            serde_json::from_slice(&std::fs::read(inconsistent.marker()).unwrap()).unwrap();
        let journal = std::fs::OpenOptions::new()
            .write(true)
            .open(inconsistent.journal())
            .unwrap();
        write_sentinel(&journal, marker.identity, generation, last_observed).unwrap();
        assert!(inconsistent.open(Limits::default()).is_err());
    }

    #[test]
    fn older_database_in_place_with_intact_marker_and_journal_is_rejected() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let old = std::fs::read(fixture.database()).unwrap();
        let inode = std::fs::metadata(fixture.database()).unwrap().ino();
        fixture.spend();
        let marker = std::fs::read(fixture.marker()).unwrap();
        let journal = std::fs::read(fixture.journal()).unwrap();
        std::fs::write(fixture.database(), old).unwrap();
        assert_eq!(std::fs::metadata(fixture.database()).unwrap().ino(), inode);
        assert_eq!(std::fs::read(fixture.marker()).unwrap(), marker);
        assert_eq!(std::fs::read(fixture.journal()).unwrap(), journal);
        assert!(fixture.open(Limits::default()).is_err());
    }

    #[test]
    fn live_in_place_database_rollback_blocks_next_reservation() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let old = std::fs::read(fixture.database()).unwrap();
        let ledger = fixture.open(Limits::default()).unwrap();
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        ledger
            .reserve(
                1001,
                job.id,
                Charge {
                    micro_usd: 10,
                    ..Charge::default()
                },
            )
            .unwrap()
            .finish(0, None)
            .unwrap();
        let marker = std::fs::read(fixture.marker()).unwrap();
        let journal = std::fs::read(fixture.journal()).unwrap();
        let database = &ledger.guard.as_ref().unwrap().database;
        database.write_all_at(&old, 0).unwrap();
        database.set_len(old.len() as u64).unwrap();
        database.sync_all().unwrap();
        assert_eq!(std::fs::read(fixture.marker()).unwrap(), marker);
        assert_eq!(std::fs::read(fixture.journal()).unwrap(), journal);
        assert_eq!(
            ledger
                .reserve(
                    1001,
                    job.id,
                    Charge {
                        micro_usd: 1,
                        ..Charge::default()
                    }
                )
                .err(),
            Some(ErrorCode::Storage)
        );
    }

    #[test]
    fn crash_between_generation_commit_and_sentinel_sync_refuses() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let old_sentinel = std::fs::read(fixture.journal()).unwrap();
        let connection = open_existing(&fixture.database()).unwrap();
        connection
            .execute("UPDATE ledger_identity SET generation=generation+1", [])
            .unwrap();
        drop(connection);
        assert!(fixture.open(Limits::default()).is_err());
        // Even a restored clean-looking sentinel must match the database generation.
        std::fs::write(fixture.journal(), old_sentinel).unwrap();
        assert!(fixture.open(Limits::default()).is_err());
    }

    #[test]
    fn in_place_marker_corruption_blocks_live_paid_admission() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let ledger = fixture.open(Limits::default()).unwrap();
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let inode = std::fs::metadata(fixture.marker()).unwrap().ino();
        let mut changed = std::fs::read(fixture.marker()).unwrap();
        let original_length = changed.len();
        changed[0] = b'[';
        std::fs::write(fixture.marker(), changed).unwrap();
        assert_eq!(
            std::fs::metadata(fixture.marker()).unwrap().len(),
            original_length as u64
        );
        assert_eq!(std::fs::metadata(fixture.marker()).unwrap().ino(), inode);
        assert_eq!(
            ledger
                .reserve(
                    1001,
                    job.id,
                    Charge {
                        micro_usd: 1,
                        ..Charge::default()
                    }
                )
                .err(),
            Some(ErrorCode::Storage)
        );
    }

    #[test]
    fn lowering_persisted_clock_without_changing_generation_is_rejected() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let ledger = fixture.open(Limits::default()).unwrap();
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let saved = std::fs::read(fixture.journal()).unwrap();
        {
            let connection = ledger.connection.lock().unwrap();
            connection
                .execute(
                    "UPDATE ledger_identity SET last_observed=last_observed-1",
                    [],
                )
                .unwrap();
        }
        let journal = &ledger.guard.as_ref().unwrap().journal;
        journal.write_all_at(&saved, 0).unwrap();
        journal.set_len(saved.len() as u64).unwrap();
        journal.sync_all().unwrap();
        assert_eq!(std::fs::read(fixture.journal()).unwrap(), saved);
        assert_eq!(
            ledger
                .reserve(
                    1001,
                    job.id,
                    Charge {
                        micro_usd: 1,
                        ..Charge::default()
                    }
                )
                .err(),
            Some(ErrorCode::Storage)
        );
    }

    #[test]
    fn guarded_clock_rollback_is_refused_even_after_reopen() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let ledger = fixture.open(Limits::default()).unwrap();
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let future = chrono::Utc::now() + chrono::Duration::days(1);
        let future_timestamp = future.timestamp();
        let hold = ledger
            .reserve_inner(
                1001,
                job.id,
                Charge {
                    micro_usd: 1,
                    ..Charge::default()
                },
                None,
                Some(future),
            )
            .unwrap();
        assert_eq!(
            ledger
                .reserve_inner(
                    1001,
                    job.id,
                    Charge::default(),
                    None,
                    Some(chrono::Utc::now())
                )
                .err(),
            Some(ErrorCode::Storage)
        );
        // Both explicit settlement and its destructor retry see the rolled-back
        // clock before any SQLite write and must leave the durable hold intact.
        let before_settlement = std::fs::read(fixture.journal()).unwrap();
        assert_eq!(hold.finish(0, None).err(), Some(ErrorCode::Storage));
        assert_eq!(std::fs::read(fixture.journal()).unwrap(), before_settlement);
        drop(ledger);
        let reopened = fixture.open(Limits::default()).unwrap();
        let sentinel = std::fs::read(fixture.journal()).unwrap();
        assert_eq!(
            reopened.recover_at(future_timestamp - 1).err(),
            Some(ErrorCode::Storage)
        );
        assert_eq!(std::fs::read(fixture.journal()).unwrap(), sentinel);
        reopened.recover_at(future_timestamp + 1).unwrap();
        drop(reopened);
        let final_open = fixture.open(Limits::default()).unwrap();
        let recovered = final_open.get(1001, job.id).unwrap();
        assert_eq!(recovered.state, JobState::Interrupted);
        assert_eq!(recovered.usage.held_micro_usd, 1);
    }

    #[test]
    fn unknown_costs_remain_in_daily_cap_after_utc_day_changes() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let limits = Limits {
            daily_micro_usd: 500_000,
            ..Limits::default()
        };
        let ledger = fixture.open(limits).unwrap();
        let first = ledger.start(1001, RequestedLimits::default()).unwrap();
        ledger
            .reserve(
                1001,
                first.id,
                Charge {
                    micro_usd: 500_000,
                    ..Charge::default()
                },
            )
            .unwrap()
            .finish(0, None)
            .unwrap();
        ledger.end(1001, first.id, JobState::Cancelled).unwrap();
        let next = ledger.start(1001, RequestedLimits::default()).unwrap();
        let tomorrow = chrono::Utc::now() + chrono::Duration::days(1);
        assert_eq!(
            ledger
                .reserve_inner(
                    1001,
                    next.id,
                    Charge {
                        micro_usd: 1,
                        ..Charge::default()
                    },
                    None,
                    Some(tomorrow)
                )
                .err(),
            Some(ErrorCode::BudgetExceeded)
        );
    }

    #[test]
    fn missing_or_replaced_journal_invalid_wal_and_older_database_refuse() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let old = std::fs::read(fixture.database()).unwrap();
        fixture.spend();
        std::fs::remove_file(fixture.journal()).unwrap();
        // Even a structurally valid older database with the same UUID and inode
        // cannot be admitted after loss of the required sidecar.
        std::fs::write(fixture.database(), &old).unwrap();
        assert!(fixture.open(Limits::default()).is_err());
        std::fs::write(fixture.journal(), b"").unwrap();
        assert!(fixture.open(Limits::default()).is_err());

        let replaced = Fixture::new();
        replaced.provision().unwrap();
        let previous = std::fs::read(replaced.database()).unwrap();
        replaced.spend();
        std::fs::rename(
            replaced.database(),
            replaced.root.path().join("state/original"),
        )
        .unwrap();
        std::fs::write(replaced.database(), previous).unwrap();
        std::fs::set_permissions(replaced.database(), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert!(replaced.open(Limits::default()).is_err());

        let wal = Fixture::new();
        wal.provision().unwrap();
        wal.spend();
        std::fs::write(wal.wal(), b"invalid WAL").unwrap();
        assert!(wal.open(Limits::default()).is_err());

        let missing_wal = Fixture::new();
        missing_wal.provision().unwrap();
        missing_wal.spend();
        // A WAL-mode header with a vanished WAL is never handed to SQLite.
        let db = std::fs::OpenOptions::new()
            .write(true)
            .open(missing_wal.database())
            .unwrap();
        db.write_all_at(&[2, 2], 18).unwrap();
        db.sync_all().unwrap();
        assert!(!missing_wal.wal().exists());
        assert!(missing_wal.open(Limits::default()).is_err());
    }

    #[test]
    fn missing_real_wal_never_reverts_to_older_committed_database() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        fixture.spend();
        let saved = std::fs::read(fixture.journal()).unwrap();
        let generation = i64::from_be_bytes(saved[48..56].try_into().unwrap());
        let last_observed = i64::from_be_bytes(saved[56..64].try_into().unwrap());
        // Switching SQLite to WAL removes the rollback journal. Keep the
        // provisioned inode and sentinel aside so the eventual rejection is
        // specifically for the missing WAL, not a missing/mismatched journal.
        let saved_journal = fixture.root.path().join("state/saved-journal");
        std::fs::rename(fixture.journal(), &saved_journal).unwrap();
        let connection = open_existing(&fixture.database()).unwrap();
        let mode: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        let mut database = File::open(fixture.database()).unwrap();
        let mut older_image = Vec::new();
        database.read_to_end(&mut older_image).unwrap();
        assert_eq!(&older_image[18..20], &[2, 2]);
        connection
            .execute("UPDATE jobs SET state='cancelled'", [])
            .unwrap();
        assert!(fixture.wal().exists());
        let mut after_update = vec![0; older_image.len()];
        database.read_exact_at(&mut after_update, 0).unwrap();
        assert_eq!(after_update, older_image);
        // The database now has an older committed image plus a live WAL. A
        // vanished WAL must not make SQLite's older image admissible.
        std::fs::remove_file(fixture.wal()).unwrap();
        let shm = fixture.root.path().join("state/budget.sqlite-shm");
        std::fs::remove_file(&shm).unwrap();
        assert!(!fixture.journal().exists());
        std::fs::rename(&saved_journal, fixture.journal()).unwrap();
        let marker: Marker =
            serde_json::from_slice(&std::fs::read(fixture.marker()).unwrap()).unwrap();
        let journal_metadata = std::fs::symlink_metadata(fixture.journal()).unwrap();
        assert_eq!(
            (journal_metadata.dev(), journal_metadata.ino()),
            (marker.journal_device, marker.journal_inode)
        );
        assert_eq!(
            std::fs::read(fixture.journal()).unwrap(),
            journal_sentinel(marker.identity, generation, last_observed)
        );
        assert!(fixture.open(Limits::default()).is_err());
        assert!(!fixture.wal().exists());
        assert!(!shm.exists());
        drop(connection);
    }

    #[test]
    fn changed_sidecars_and_marker_links_are_rejected_before_reservation() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let ledger = fixture.open(Limits::default()).unwrap();
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        std::fs::write(fixture.journal(), b"hot or damaged").unwrap();
        assert_eq!(
            ledger
                .reserve(
                    1001,
                    job.id,
                    Charge {
                        micro_usd: 1,
                        ..Charge::default()
                    }
                )
                .err(),
            Some(ErrorCode::Storage)
        );
        drop(ledger);
        assert!(fixture.open(Limits::default()).is_err());

        let linked = Fixture::new();
        linked.provision().unwrap();
        std::fs::rename(linked.marker(), linked.root.path().join("guard/old")).unwrap();
        symlink("old", linked.marker()).unwrap();
        assert!(linked.open(Limits::default()).is_err());

        let hardlinked = Fixture::new();
        hardlinked.provision().unwrap();
        std::fs::hard_link(
            hardlinked.marker(),
            hardlinked.root.path().join("guard/alias"),
        )
        .unwrap();
        assert!(hardlinked.open(Limits::default()).is_err());

        let swapped = Fixture::new();
        swapped.provision().unwrap();
        let ledger = swapped.open(Limits::default()).unwrap();
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        std::fs::rename(
            swapped.root.path().join("guard"),
            swapped.root.path().join("old-guard"),
        )
        .unwrap();
        std::fs::create_dir(swapped.root.path().join("guard")).unwrap();
        assert_eq!(
            ledger
                .reserve(
                    1001,
                    job.id,
                    Charge {
                        micro_usd: 1,
                        ..Charge::default()
                    }
                )
                .err(),
            Some(ErrorCode::Storage)
        );

        let wrong_owner = Fixture::new();
        wrong_owner.provision().unwrap();
        assert!(
            guarded_in(
                &wrong_owner.database(),
                Limits::default(),
                wrong_owner.state_dir(),
                wrong_owner.marker_dir(),
                &wrong_owner.marker(),
                (wrong_owner.owner, wrong_owner.owner.wrapping_add(1)),
                None
            )
            .is_err()
        );

        let writable = Fixture::new();
        writable.provision().unwrap();
        std::fs::set_permissions(writable.marker(), std::fs::Permissions::from_mode(0o666))
            .unwrap();
        assert!(writable.open(Limits::default()).is_err());
    }

    #[test]
    fn live_missing_files_or_unexpected_wal_block_next_paid_reservation() {
        for removed in ["database", "marker", "wal"] {
            let fixture = Fixture::new();
            fixture.provision().unwrap();
            let ledger = fixture.open(Limits::default()).unwrap();
            let job = ledger.start(1001, RequestedLimits::default()).unwrap();
            match removed {
                "database" => std::fs::remove_file(fixture.database()).unwrap(),
                "marker" => std::fs::remove_file(fixture.marker()).unwrap(),
                "wal" => std::fs::write(fixture.wal(), b"unexpected").unwrap(),
                _ => unreachable!(),
            }
            assert_eq!(
                ledger
                    .reserve(
                        1001,
                        job.id,
                        Charge {
                            micro_usd: 1,
                            ..Charge::default()
                        }
                    )
                    .err(),
                Some(ErrorCode::Storage)
            );
            if removed == "database" {
                assert!(!fixture.database().exists());
            }
        }
    }

    // Called only as a child of the following test. Exit without destructors to
    // leave the SQLite transaction's durable reservation in the database.
    #[test]
    fn guarded_crash_fixture() {
        let Some(root) = std::env::var_os("RESEARCH_GUARD_CRASH_FIXTURE") else {
            return;
        };
        let root = PathBuf::from(root);
        let path = root.join("state/budget.sqlite");
        let owner = rustix::process::geteuid().as_raw();
        let limits = Limits {
            daily_micro_usd: 500_000,
            ..Limits::default()
        };
        let ledger = guarded_in(
            &path,
            limits,
            File::open(root.join("state")).unwrap(),
            File::open(root.join("guard")).unwrap(),
            &root.join("guard/budget.marker"),
            (owner, owner),
            None,
        )
        .unwrap();
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let _hold = ledger
            .reserve(
                1001,
                job.id,
                Charge {
                    micro_usd: 500_000,
                    bytes: 100,
                    ..Charge::default()
                },
            )
            .unwrap();
        std::fs::write(root.join("job"), job.id.to_string()).unwrap();
        std::process::exit(0);
    }

    #[test]
    fn reopened_guarded_ledger_recovers_crashed_reservations_without_freeing_spend() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "budget::guard::tests::guarded_crash_fixture"])
            .env("RESEARCH_GUARD_CRASH_FIXTURE", fixture.root.path())
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output);
        let id =
            Uuid::parse_str(&std::fs::read_to_string(fixture.root.path().join("job")).unwrap())
                .unwrap();
        let limits = Limits {
            daily_micro_usd: 500_000,
            ..Limits::default()
        };
        let ledger = fixture.open(limits).unwrap();
        ledger.recover().unwrap();
        let job = ledger.get(1001, id).unwrap();
        assert_eq!(job.state, JobState::Interrupted);
        assert_eq!(job.usage.held_micro_usd, 500_000);
        assert_eq!((job.usage.used_bytes, job.usage.reserved_bytes), (100, 0));
        let next = ledger.start(1001, RequestedLimits::default()).unwrap();
        assert_eq!(
            ledger
                .reserve(
                    1001,
                    next.id,
                    Charge {
                        micro_usd: 1,
                        ..Charge::default()
                    }
                )
                .err(),
            Some(ErrorCode::BudgetExceeded)
        );
    }
}
