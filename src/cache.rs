//! Bounded, policy-scoped cache and cancellation-safe single-flight. Keys retain
//! hashes rather than queries/URLs. Failed initialization is never cached.

use crate::error::{ErrorCode, Result};
use crate::policy::sha256;
use serde::Serialize;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    owner: u32,
    job: Option<Uuid>,
    digest: String,
}

impl Key {
    /// The caller supplies its policy and request dimensions. If a response can
    /// vary by request header, that header must be keyed or fixed for the cache.
    pub fn new(
        owner: u32,
        job: Option<Uuid>,
        policy: &str,
        request: &impl Serialize,
    ) -> Result<Self> {
        let bytes =
            serde_json::to_vec(&(policy, request)).map_err(|_| ErrorCode::InvalidRequest)?;
        if bytes.len() > 32 * 1024 {
            return Err(ErrorCode::SizeLimit);
        }
        Ok(Self {
            owner,
            job,
            digest: sha256(&bytes),
        })
    }
}

struct Entry<T> {
    value: Arc<T>,
    expires: Instant,
    weight: usize,
    serial: u64,
}
struct State<T> {
    entries: HashMap<Key, Entry<T>>,
    flights: HashMap<Key, Weak<tokio::sync::Mutex<()>>>,
    bytes: usize,
    serial: u64,
}

pub struct Cache<T> {
    state: Mutex<State<T>>,
    entries: usize,
    bytes: usize,
}

impl<T> Cache<T> {
    pub fn new(entries: usize, bytes: usize) -> Result<Self> {
        if entries == 0 || entries > 10_000 || bytes == 0 || bytes > 128 * 1024 * 1024 {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self {
            state: Mutex::new(State {
                entries: HashMap::new(),
                flights: HashMap::new(),
                bytes: 0,
                serial: 0,
            }),
            entries,
            bytes,
        })
    }

    fn lookup(&self, key: &Key) -> Result<Option<Arc<T>>> {
        let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
        prune(&mut state);
        state.serial = state.serial.wrapping_add(1);
        let serial = state.serial;
        Ok(state.entries.get_mut(key).map(|entry| {
            entry.serial = serial;
            entry.value.clone()
        }))
    }

    /// Returns (value, cache hit). Each waiting caller retains its own initializer:
    /// if the leader is cancelled, a waiter takes over with its own job budget.
    pub async fn get_or_init<F, Fut>(&self, key: Key, create: F) -> Result<(Arc<T>, bool)>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(T, Duration, usize)>>,
    {
        self.get_or_init_cancellable(key, &tokio_util::sync::CancellationToken::new(), create)
            .await
    }

    /// Waiting for another job's initializer is cancellable. Once admitted, the
    /// initializer owns cooperative cleanup and is never dropped by this cache.
    pub async fn get_or_init_cancellable<F, Fut>(
        &self,
        key: Key,
        stop: &tokio_util::sync::CancellationToken,
        create: F,
    ) -> Result<(Arc<T>, bool)>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(T, Duration, usize)>>,
    {
        if stop.is_cancelled() {
            return Err(ErrorCode::Cancelled);
        }
        if let Some(value) = self.lookup(&key)? {
            return Ok((value, true));
        }
        let flight = {
            let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
            state.flights.retain(|_, weak| weak.strong_count() != 0);
            if let Some(flight) = state.flights.get(&key).and_then(Weak::upgrade) {
                flight
            } else {
                if state.flights.len() >= self.entries {
                    return Err(ErrorCode::Capacity);
                }
                let flight = Arc::new(tokio::sync::Mutex::new(()));
                state.flights.insert(key.clone(), Arc::downgrade(&flight));
                flight
            }
        };
        let _guard = tokio::select! { biased; _ = stop.cancelled() => return Err(ErrorCode::Cancelled), guard = flight.lock() => guard };
        if let Some(value) = self.lookup(&key)? {
            return Ok((value, true));
        }
        let (value, ttl, weight) = create().await?;
        let value = Arc::new(value);
        if ttl.is_zero() || weight > self.bytes {
            return Ok((value, false));
        }
        let ttl = ttl.min(Duration::from_secs(86400));
        let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
        prune(&mut state);
        while state.entries.len() >= self.entries || state.bytes + weight > self.bytes {
            let oldest = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.serial)
                .map(|(key, _)| key.clone())
                .ok_or(ErrorCode::Storage)?;
            remove(&mut state, &oldest);
        }
        state.serial = state.serial.wrapping_add(1);
        let serial = state.serial;
        state.bytes += weight;
        state.entries.insert(
            key,
            Entry {
                value: value.clone(),
                expires: Instant::now() + ttl,
                weight,
                serial,
            },
        );
        Ok((value, false))
    }

    pub fn invalidate(&self, key: &Key) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
        remove(&mut state, key);
        Ok(())
    }

    pub fn maintenance(&self) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
        prune(&mut state);
        state.flights.retain(|_, weak| weak.strong_count() != 0);
        Ok(())
    }

    /// Called after cancelling and joining the job's in-flight operations.
    pub fn remove_job(&self, owner: u32, job: Uuid) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
        let keys: Vec<_> = state
            .entries
            .keys()
            .filter(|k| k.owner == owner && k.job == Some(job))
            .cloned()
            .collect();
        for key in keys {
            remove(&mut state, &key);
        }
        state
            .flights
            .retain(|key, _| key.owner != owner || key.job != Some(job));
        Ok(())
    }
}

fn remove<T>(state: &mut State<T>, key: &Key) {
    if let Some(entry) = state.entries.remove(key) {
        state.bytes -= entry.weight;
    }
}

fn prune<T>(state: &mut State<T>) {
    let now = Instant::now();
    state.entries.retain(|_, entry| {
        if entry.expires > now {
            true
        } else {
            state.bytes -= entry.weight;
            false
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    fn key(policy: &str, job: Option<Uuid>) -> Key {
        Key::new(1001, job, policy, &"https://example.com/").unwrap()
    }

    #[tokio::test]
    async fn cancelling_a_waiter_does_not_wait_for_or_cancel_another_jobs_initializer() {
        let cache = Arc::new(Cache::new(10, 100).unwrap());
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let leader = {
            let (cache, entered, release) = (cache.clone(), entered.clone(), release.clone());
            tokio::spawn(async move {
                cache
                    .get_or_init(key("shared", None), || async {
                        entered.notify_one();
                        release.notified().await;
                        Ok((42, Duration::from_secs(60), 8))
                    })
                    .await
            })
        };
        entered.notified().await;
        let stop = tokio_util::sync::CancellationToken::new();
        let waiting = cache.get_or_init_cancellable(key("shared", None), &stop, || async {
            panic!("waiter must not initialize")
        });
        tokio::pin!(waiting);
        assert!(futures_util::poll!(&mut waiting).is_pending());
        stop.cancel();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiting)
                .await
                .unwrap()
                .unwrap_err(),
            ErrorCode::Cancelled
        );
        assert!(!leader.is_finished());
        release.notify_one();
        assert_eq!(*leader.await.unwrap().unwrap().0, 42);
    }

    #[tokio::test]
    async fn simultaneous_callers_execute_one_initializer() {
        let cache = Cache::new(10, 100).unwrap();
        let calls = AtomicUsize::new(0);
        let requests = (0..8).map(|_| {
            cache.get_or_init(key("policy/1", None), || async {
                calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok((42, Duration::from_secs(60), 8))
            })
        });
        let results = futures_util::future::join_all(requests).await;
        assert!(
            results
                .iter()
                .all(|result| *result.as_ref().unwrap().0 == 42)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(results.iter().filter(|v| v.as_ref().unwrap().1).count(), 7);
    }

    #[tokio::test]
    async fn cancelled_initializer_releases_waiters_without_caching_failure() {
        let cache = Arc::new(Cache::new(10, 100).unwrap());
        let ready = Arc::new(tokio::sync::Notify::new());
        let (worker_cache, signal) = (cache.clone(), ready.clone());
        let started = ready.notified();
        let leader = tokio::spawn(async move {
            worker_cache
                .get_or_init(key("policy/1", None), || async {
                    signal.notify_one();
                    std::future::pending::<Result<(i32, Duration, usize)>>().await
                })
                .await
        });
        started.await;
        leader.abort();
        let _ = leader.await;
        let (value, hit) = tokio::time::timeout(
            Duration::from_secs(1),
            cache.get_or_init(key("policy/1", None), || async {
                Ok((7, Duration::from_secs(60), 8))
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(*value, 7);
        assert!(!hit);
    }

    #[tokio::test]
    async fn policy_scope_expiry_and_weight_prevent_stale_reuse() {
        let cache = Cache::new(2, 16).unwrap();
        let job = Uuid::new_v4();
        for (policy, scope, value) in [("v1", None, 1), ("v2", None, 2), ("v2", Some(job), 3)] {
            assert!(
                !cache
                    .get_or_init(key(policy, scope), || async {
                        Ok((value, Duration::from_secs(60), 8))
                    })
                    .await
                    .unwrap()
                    .1
            );
        }
        assert!(cache.lookup(&key("v1", None)).unwrap().is_none());
        assert_eq!(*cache.lookup(&key("v2", None)).unwrap().unwrap(), 2);
        cache.remove_job(1001, job).unwrap();
        assert!(cache.lookup(&key("v2", Some(job))).unwrap().is_none());
        assert!(cache.lookup(&key("v2", None)).unwrap().is_some());
        cache
            .get_or_init(key("short", None), || async {
                Ok((4, Duration::from_millis(1), 8))
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(cache.lookup(&key("short", None)).unwrap().is_none());
        assert!(cache.state.lock().unwrap().bytes <= 16);
    }
}
