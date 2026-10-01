//! Practical evidence is durable. Strict evidence and provider responses without
//! storage rights live only in job-owned temporary directories, apart from money.

use crate::archive::{Archive, Chunk, NewSource, Source};
use crate::config::{Config, Privacy};
use crate::error::{ErrorCode, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
use uuid::Uuid;

struct TemporaryArchive {
    owner: u32,
    archive: Arc<Archive>,
    _directory: tempfile::TempDir,
}
struct Lease {
    archive: Arc<Archive>,
    _temporary: Option<Arc<TemporaryArchive>>,
}

pub struct EvidenceStore {
    config: Config,
    temporary_directory: PathBuf,
    durable: Option<Arc<Archive>>,
    jobs: Mutex<HashMap<Uuid, Arc<TemporaryArchive>>>,
    reads: Semaphore,
}

impl EvidenceStore {
    pub(crate) fn temporary_directory(&self) -> &std::path::Path {
        &self.temporary_directory
    }

    pub fn open(config: &Config, temporary_directory: PathBuf) -> Result<Arc<Self>> {
        let durable = if config.privacy == Privacy::Practical {
            Some(Arc::new(Archive::open(
                &config.state_directory.join("evidence"),
                Duration::from_secs(config.retention.days as u64 * 86400),
                config.retention.bytes,
            )?))
        } else {
            None
        };
        Ok(Arc::new(Self {
            config: config.clone(),
            temporary_directory,
            durable,
            jobs: Mutex::new(HashMap::new()),
            reads: Semaphore::new(config.limits.store_reads),
        }))
    }

    fn lease(&self, owner: u32, job: Uuid, persistent_rights: bool) -> Result<Lease> {
        if persistent_rights && let Some(archive) = &self.durable {
            return Ok(Lease {
                archive: archive.clone(),
                _temporary: None,
            });
        }
        let mut jobs = self.jobs.lock().map_err(|_| ErrorCode::Storage)?;
        let entry = if let Some(entry) = jobs.get(&job) {
            entry.clone()
        } else {
            if jobs.len() >= self.config.limits.active_jobs {
                return Err(ErrorCode::Capacity);
            }
            let directory = tempfile::Builder::new()
                .prefix("evidence-")
                .tempdir_in(&self.temporary_directory)
                .map_err(|_| ErrorCode::Storage)?;
            let archive = Arc::new(Archive::open(
                directory.path(),
                Duration::from_secs(self.config.limits.job_seconds),
                self.config
                    .limits
                    .job_bytes
                    .min(self.config.retention.bytes),
            )?);
            let entry = Arc::new(TemporaryArchive {
                owner,
                archive,
                _directory: directory,
            });
            jobs.insert(job, entry.clone());
            entry
        };
        if entry.owner != owner {
            return Err(ErrorCode::PermissionDenied);
        }
        Ok(Lease {
            archive: entry.archive.clone(),
            _temporary: Some(entry),
        })
    }

    pub async fn insert(
        self: &Arc<Self>,
        owner: u32,
        source: NewSource,
        persistent_rights: bool,
    ) -> Result<Source> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let lease = store.lease(owner, source.job_id, persistent_rights)?;
            lease.archive.insert(owner, source)
        })
        .await
        .map_err(|_| ErrorCode::Storage)?
    }

    fn find(&self, owner: u32, source: Uuid) -> Result<Lease> {
        if let Some(archive) = &self.durable {
            match archive.get(owner, source) {
                Ok(_) => {
                    return Ok(Lease {
                        archive: archive.clone(),
                        _temporary: None,
                    });
                }
                Err(ErrorCode::NotFound) => (),
                Err(error) => return Err(error),
            }
        }
        let jobs: Vec<_> = self
            .jobs
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .values()
            .filter(|entry| entry.owner == owner)
            .cloned()
            .collect();
        for entry in jobs {
            match entry.archive.get(owner, source) {
                Ok(_) => {
                    return Ok(Lease {
                        archive: entry.archive.clone(),
                        _temporary: Some(entry),
                    });
                }
                Err(ErrorCode::NotFound) => (),
                Err(error) => return Err(error),
            }
        }
        // Missing ephemeral sources may have vanished at job end or restart.
        // Do not reveal whether another UID ever owned a guessed identifier.
        Err(ErrorCode::SourceExpired)
    }

    pub async fn get(self: &Arc<Self>, owner: u32, source: Uuid) -> Result<Source> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.find(owner, source)?.archive.get(owner, source))
            .await
            .map_err(|_| ErrorCode::Storage)?
    }

    /// Derived evidence must not outlive a job-only input representation.
    pub fn is_persistent(&self, owner: u32, source: Uuid) -> Result<bool> {
        Ok(self.find(owner, source)?._temporary.is_none())
    }

    pub async fn read(
        self: &Arc<Self>,
        owner: u32,
        source: Uuid,
        representation: Uuid,
        cursor: Option<String>,
        cap: usize,
    ) -> Result<Chunk> {
        let _permit = self
            .reads
            .acquire()
            .await
            .map_err(|_| ErrorCode::Cancelled)?;
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store.find(owner, source)?.archive.read(
                owner,
                source,
                representation,
                cursor.as_deref(),
                cap,
            )
        })
        .await
        .map_err(|_| ErrorCode::Storage)?
    }

    /// Bounded complete text of one text representation for derived work.
    pub async fn text(
        self: &Arc<Self>,
        owner: u32,
        source: Uuid,
        representation: Uuid,
        max_bytes: usize,
    ) -> Result<(crate::archive::Representation, String, bool)> {
        let _permit = self
            .reads
            .acquire()
            .await
            .map_err(|_| ErrorCode::Cancelled)?;
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store
                .find(owner, source)?
                .archive
                .text(owner, source, representation, max_bytes)
        })
        .await
        .map_err(|_| ErrorCode::Storage)?
    }

    pub async fn read_at(
        self: &Arc<Self>,
        owner: u32,
        source: Uuid,
        representation: Uuid,
        start: u64,
        cap: usize,
    ) -> Result<Chunk> {
        let _permit = self
            .reads
            .acquire()
            .await
            .map_err(|_| ErrorCode::Cancelled)?;
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store
                .find(owner, source)?
                .archive
                .read_at(owner, source, representation, start, cap)
        })
        .await
        .map_err(|_| ErrorCode::Storage)?
    }

    pub async fn job_sources(self: &Arc<Self>, owner: u32, job: Uuid) -> Result<Vec<Uuid>> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut ids = if let Some(archive) = &store.durable {
                archive.job_sources(owner, job)?
            } else {
                Vec::new()
            };
            let temporary = store
                .jobs
                .lock()
                .map_err(|_| ErrorCode::Storage)?
                .get(&job)
                .filter(|entry| entry.owner == owner)
                .cloned();
            if let Some(temporary) = temporary {
                ids.extend(temporary.archive.job_sources(owner, job)?);
            }
            Ok(ids)
        })
        .await
        .map_err(|_| ErrorCode::Storage)?
    }

    /// The supervisor cancels/joins job operations before removing its archive.
    /// Outstanding blocking IO retains a Lease until it has actually finished.
    pub fn finish_job(&self, owner: u32, job: Uuid) -> Result<()> {
        let mut jobs = self.jobs.lock().map_err(|_| ErrorCode::Storage)?;
        if jobs.get(&job).is_some_and(|entry| entry.owner != owner) {
            return Err(ErrorCode::PermissionDenied);
        }
        jobs.remove(&job);
        Ok(())
    }

    pub async fn maintenance(self: &Arc<Self>) -> Result<()> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            if let Some(archive) = &store.durable {
                archive.maintenance()?;
            }
            let jobs: Vec<_> = store
                .jobs
                .lock()
                .map_err(|_| ErrorCode::Storage)?
                .values()
                .cloned()
                .collect();
            for entry in jobs {
                entry.archive.maintenance()?;
            }
            Ok(())
        })
        .await
        .map_err(|_| ErrorCode::Storage)?
    }
}
