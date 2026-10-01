//! Translate an operator's root-owned VPN observation lease into research leases.
//! This does not discover VPN readiness: the host adapter must establish the VPN
//! path AND firewall invariant before reporting Ready. No tool controls this API.

use crate::egress::{EgressMode, EgressState};
use crate::error::{ErrorCode, Result};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// A generation is local to one uninterrupted observed exit and controller run.
/// Draining retains it only for a bounded, monotonic interval. Offline, lost
/// observations and restarts cannot revive old browser sessions. The region is
/// part of the observed exit identity and is dropped whenever the mode goes
/// offline or the exit changes.
pub struct Controller {
    generation: Uuid,
    observed: Option<Uuid>,
    drain_started: Option<Instant>,
    drain_limit: Duration,
    region: Option<String>,
}

impl Controller {
    pub fn new(drain_seconds: u64) -> Result<Self> {
        if !(1..=300).contains(&drain_seconds) {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self {
            generation: Uuid::new_v4(),
            observed: None,
            drain_started: None,
            drain_limit: Duration::from_secs(drain_seconds),
            region: None,
        })
    }

    pub fn update(
        &mut self,
        observation: Option<EgressState>,
        unix_now: i64,
        monotonic_now: Instant,
    ) -> EgressState {
        let observation = observation.filter(|state| state.valid_at(unix_now));
        let mode = match &observation {
            Some(state) if state.mode == EgressMode::Ready => {
                if self.observed != Some(state.generation) {
                    self.generation = Uuid::new_v4();
                }
                self.observed = Some(state.generation);
                self.drain_started = None;
                self.region = state.region.clone();
                EgressMode::Ready
            }
            Some(state)
                if state.mode == EgressMode::Draining
                    && self.observed == Some(state.generation) =>
            {
                let started = *self.drain_started.get_or_insert(monotonic_now);
                if monotonic_now.saturating_duration_since(started) < self.drain_limit {
                    // A matching drain keeps the observed exit identity, so the
                    // region still describes the exit existing work is using.
                    self.region = state.region.clone();
                    EgressMode::Draining
                } else {
                    EgressMode::Offline
                }
            }
            _ => EgressMode::Offline,
        };
        if mode == EgressMode::Offline {
            self.observed = None;
            self.drain_started = None;
            self.region = None;
        }
        // Never amplify the upstream lease. A dead controller additionally
        // loses its own permission within three seconds, even with a live input.
        let valid_until = observation
            .as_ref()
            .map(|state| state.valid_until)
            .unwrap_or(i64::MAX)
            .min(unix_now.saturating_add(3));
        EgressState {
            version: 1,
            generation: self.generation,
            mode,
            valid_until,
            region: self.region.clone(),
        }
    }
}

/// Require an absolute, normalized path through root-owned non-writable
/// directories, without symlinks. Checking only the final file's owner would
/// allow a writable ancestor to substitute an older root-owned Ready lease.
pub fn protected_parent(path: &Path) -> Result<()> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ErrorCode::InvalidRequest);
    }
    let parent = path.parent().ok_or(ErrorCode::InvalidRequest)?;
    let mut current = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::RootDir | Component::Normal(_) => current.push(component),
            _ => return Err(ErrorCode::InvalidRequest),
        }
        let metadata =
            std::fs::symlink_metadata(&current).map_err(|_| ErrorCode::PermissionDenied)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(ErrorCode::PermissionDenied);
        }
    }
    Ok(())
}

/// Own the output directory for the lifetime of the controller. The caller
/// must keep the returned file open. Locks are deliberately never unlinked.
pub fn lock_output(path: &Path) -> Result<File> {
    if path
        .file_name()
        .is_some_and(|name| name == "controller.lock")
    {
        return Err(ErrorCode::InvalidRequest);
    }
    if !rustix::process::geteuid().is_root() {
        return Err(ErrorCode::PermissionDenied);
    }
    protected_parent(path)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(
            path.parent()
                .ok_or(ErrorCode::InvalidRequest)?
                .join("controller.lock"),
        )
        .map_err(|_| ErrorCode::PermissionDenied)?;
    let metadata = lock.metadata().map_err(|_| ErrorCode::PermissionDenied)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(ErrorCode::PermissionDenied);
    }
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| ErrorCode::Capacity)?;
    Ok(lock)
}

/// Publish complete JSON by same-directory rename. Readers never see a partial
/// update; service identities can read but cannot write this root-owned file.
pub fn publish(path: &Path, state: &EgressState) -> Result<()> {
    if !rustix::process::geteuid().is_root() {
        return Err(ErrorCode::PermissionDenied);
    }
    protected_parent(path)?;
    publish_atomic(path, state)
}

fn publish_atomic(path: &Path, state: &EgressState) -> Result<()> {
    let mut temporary =
        tempfile::NamedTempFile::new_in(path.parent().ok_or(ErrorCode::InvalidRequest)?)
            .map_err(|_| ErrorCode::Storage)?;
    serde_json::to_writer(temporary.as_file_mut(), state).map_err(|_| ErrorCode::Storage)?;
    temporary.flush().map_err(|_| ErrorCode::Storage)?;
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o644))
        .map_err(|_| ErrorCode::Storage)?;
    temporary.persist(path).map_err(|_| ErrorCode::Storage)?;
    // Runtime leases are intentionally not durable; a reboot needs fresh proof.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(epoch: Uuid, mode: EgressMode, now: i64) -> EgressState {
        EgressState {
            version: 1,
            generation: epoch,
            mode,
            valid_until: now + 10,
            region: None,
        }
    }

    fn observed_region(epoch: Uuid, mode: EgressMode, now: i64, region: &str) -> EgressState {
        EgressState {
            region: Some(region.to_owned()),
            ..observation(epoch, mode, now)
        }
    }

    #[test]
    fn ready_refresh_keeps_generation_but_loss_and_restart_do_not() {
        let now = Instant::now();
        let input = observed_region(Uuid::new_v4(), EgressMode::Ready, 100, "DE");
        let mut controller = Controller::new(60).unwrap();
        let first = controller.update(Some(input.clone()), 100, now);
        assert_eq!(first.mode, EgressMode::Ready);
        assert_ne!(first.generation, input.generation);
        assert_eq!(first.valid_until, 103);
        assert_eq!(first.region.as_deref(), Some("DE"));
        let refresh = controller.update(Some(input.clone()), 101, now);
        assert_eq!(refresh.generation, first.generation);
        assert_eq!(refresh.region.as_deref(), Some("DE"));
        let offline = controller.update(None, 101, now);
        assert_eq!(offline.mode, EgressMode::Offline);
        assert_eq!(offline.region, None);
        let recovered = controller.update(Some(input.clone()), 102, now);
        assert_ne!(recovered.generation, first.generation);
        assert_eq!(recovered.region.as_deref(), Some("DE"));
        let restarted = Controller::new(60).unwrap().update(Some(input), 100, now);
        assert_ne!(restarted.generation, first.generation);
    }

    #[test]
    fn region_survives_a_matching_drain_and_is_dropped_on_offline_or_exit_change() {
        let now = Instant::now();
        let epoch = Uuid::new_v4();
        let mut controller = Controller::new(60).unwrap();
        let ready = controller.update(
            Some(observed_region(epoch, EgressMode::Ready, 100, "FR")),
            100,
            now,
        );
        assert_eq!(ready.region.as_deref(), Some("FR"));
        let draining = controller.update(
            Some(observed_region(epoch, EgressMode::Draining, 100, "FR")),
            100,
            now,
        );
        assert_eq!(draining.mode, EgressMode::Draining);
        assert_eq!(draining.generation, ready.generation);
        assert_eq!(draining.region.as_deref(), Some("FR"));
        let offline = controller.update(None, 100, now);
        assert_eq!(offline.mode, EgressMode::Offline);
        assert_eq!(offline.region, None);
        // A new exit is a new observed identity and takes its own region.
        let changed = controller.update(
            Some(observed_region(
                Uuid::new_v4(),
                EgressMode::Ready,
                100,
                "US",
            )),
            100,
            now,
        );
        assert_eq!(changed.mode, EgressMode::Ready);
        assert_ne!(changed.generation, ready.generation);
        assert_eq!(changed.region.as_deref(), Some("US"));
    }

    #[test]
    fn invalid_region_fails_closed_and_valid_region_is_carried() {
        let now = Instant::now();
        let epoch = Uuid::new_v4();
        let mut controller = Controller::new(60).unwrap();
        for region in ["de", "DEU", "D", "D3", "12", "é", ""] {
            let invalid = EgressState {
                region: Some(region.to_owned()),
                ..observation(epoch, EgressMode::Ready, 100)
            };
            assert_eq!(
                controller.update(Some(invalid), 100, now).mode,
                EgressMode::Offline,
                "region {region:?} must fail closed"
            );
        }
        let valid = controller.update(
            Some(observed_region(epoch, EgressMode::Ready, 100, "US")),
            100,
            now,
        );
        assert_eq!(valid.mode, EgressMode::Ready);
        assert_eq!(valid.region.as_deref(), Some("US"));
    }

    #[test]
    fn changed_exit_interrupts_even_without_an_observed_offline_interval() {
        let now = Instant::now();
        let mut controller = Controller::new(60).unwrap();
        let first = controller.update(
            Some(observation(Uuid::new_v4(), EgressMode::Ready, 100)),
            100,
            now,
        );
        let next = controller.update(
            Some(observation(Uuid::new_v4(), EgressMode::Ready, 101)),
            101,
            now,
        );
        assert_eq!(next.mode, EgressMode::Ready);
        assert_ne!(next.generation, first.generation);
    }

    #[test]
    fn drain_refresh_cannot_extend_monotonic_deadline_or_resurrect_sessions() {
        let now = Instant::now();
        let epoch = Uuid::new_v4();
        let mut controller = Controller::new(5).unwrap();
        let first = controller.update(Some(observation(epoch, EgressMode::Ready, 100)), 100, now);
        for second in 0..5 {
            let state = controller.update(
                Some(observation(epoch, EgressMode::Draining, 100)),
                100,
                now + Duration::from_secs(second),
            );
            assert_eq!(state.mode, EgressMode::Draining);
            assert_eq!(state.generation, first.generation);
        }
        // Wall clock deliberately stays still: the drain still expires.
        for second in 5..8 {
            assert_eq!(
                controller
                    .update(
                        Some(observation(epoch, EgressMode::Draining, 100)),
                        100,
                        now + Duration::from_secs(second)
                    )
                    .mode,
                EgressMode::Offline
            );
        }
        let ready = controller.update(
            Some(observation(epoch, EgressMode::Ready, 100)),
            100,
            now + Duration::from_secs(8),
        );
        assert_ne!(ready.generation, first.generation);
    }

    #[test]
    fn draining_requires_a_previously_ready_matching_exit() {
        let now = Instant::now();
        let epoch = Uuid::new_v4();
        let mut controller = Controller::new(60).unwrap();
        assert_eq!(
            controller
                .update(
                    Some(observation(epoch, EgressMode::Draining, 100)),
                    100,
                    now
                )
                .mode,
            EgressMode::Offline
        );
        controller.update(Some(observation(epoch, EgressMode::Ready, 100)), 100, now);
        assert_eq!(
            controller
                .update(
                    Some(observation(Uuid::new_v4(), EgressMode::Draining, 100)),
                    100,
                    now
                )
                .mode,
            EgressMode::Offline
        );
    }

    #[test]
    fn invalid_or_expired_input_fails_closed_and_short_lease_is_not_extended() {
        let now = Instant::now();
        let mut controller = Controller::new(60).unwrap();
        let input = observation(Uuid::new_v4(), EgressMode::Ready, 100);
        for invalid in [
            EgressState {
                version: 2,
                ..input.clone()
            },
            EgressState {
                generation: Uuid::nil(),
                ..input.clone()
            },
            EgressState {
                valid_until: 100,
                ..input.clone()
            },
            EgressState {
                valid_until: 111,
                ..input.clone()
            },
            EgressState {
                mode: EgressMode::Offline,
                ..input.clone()
            },
        ] {
            assert_eq!(
                controller.update(Some(invalid), 100, now).mode,
                EgressMode::Offline
            );
        }
        let short = EgressState {
            valid_until: 101,
            ..input
        };
        assert_eq!(
            controller.update(Some(short.clone()), 100, now).valid_until,
            101
        );
        assert_eq!(
            controller.update(Some(short), 101, now).mode,
            EgressMode::Offline
        );
        assert!(Controller::new(0).is_err());
        assert!(Controller::new(301).is_err());
    }

    #[test]
    fn publish_replaces_inode_without_modifying_existing_readers_or_symlink_targets() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let first = observation(Uuid::new_v4(), EgressMode::Ready, 100);
        publish_atomic(&path, &first).unwrap();
        let reader = File::open(&path).unwrap();
        let offline = EgressState {
            mode: EgressMode::Offline,
            ..first.clone()
        };
        publish_atomic(&path, &offline).unwrap();
        assert_eq!(
            serde_json::from_reader::<_, EgressState>(reader).unwrap(),
            first
        );
        assert_eq!(
            serde_json::from_reader::<_, EgressState>(File::open(&path).unwrap()).unwrap(),
            offline
        );
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
        let link = directory.path().join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        publish_atomic(&link, &first).unwrap();
        assert!(!std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(
            serde_json::from_reader::<_, EgressState>(File::open(&path).unwrap()).unwrap(),
            offline
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn controller_rejects_untrusted_ancestor_paths() {
        assert_eq!(
            lock_output(Path::new("/run/controller.lock")).unwrap_err(),
            ErrorCode::InvalidRequest
        );
        assert!(protected_parent(Path::new("relative/state.json")).is_err());
        assert!(protected_parent(Path::new("/tmp/state.json")).is_err());
        assert!(protected_parent(Path::new("/run/../state.json")).is_err());
    }
}
