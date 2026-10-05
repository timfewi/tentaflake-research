//! Reference root observer for the VPN/firewall observation lease. `update` is a
//! pure, fail-closed state machine over local, non-cryptographic evidence:
//! interface-up, an IPv4 default route on that interface and, when the operator
//! selects them, the link kind and the egress identity's IPv4/IPv6/DNS paths. A
//! root-owned firewall marker and a declared region are operator *assertions*,
//! never observed tunnel identity. A planned exit change is reported as draining.
//! The observer does not prove the cryptographic exit identity of the encrypted
//! tunnel; the kernel firewall remains the independent invariant.

use crate::egress::{EgressMode, EgressState, MAX_LEASE_SECONDS};
use uuid::Uuid;

/// One point-in-time reading of the local evidence the observer can gather.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub interface_up: bool,
    pub default_route: bool,
    /// Operator assertion: the firewall installer's marker, not the rules.
    pub firewall_marker: bool,
    /// Operator assertion: the declared exit region, never inferred.
    pub region: Option<String>,
    /// Observed link kind, when the operator selected one. `None` is not selected.
    pub link_kind: Option<bool>,
    /// Observed IPv4 tunnel path, IPv6 containment and resolver paths of the egress
    /// identity, when selected. `None` is not selected; `Some(false)` is offline.
    pub egress_paths: Option<bool>,
    /// The operator requested a planned exit change (a root-controlled drain marker).
    pub draining: bool,
}

impl Observation {
    /// Evidence that is not ready for any reason except a failed selection.
    pub fn not_ready() -> Self {
        Self {
            interface_up: false,
            default_route: false,
            firewall_marker: false,
            region: None,
            link_kind: None,
            egress_paths: None,
            draining: false,
        }
    }

    fn proven(&self) -> bool {
        self.interface_up
            && self.default_route
            && self.firewall_marker
            && self.link_kind != Some(false)
            && self.egress_paths != Some(false)
            && valid_region(&self.region)
    }
}

/// A region is `None` or exactly two ASCII uppercase letters. Anything else is
/// malformed and fails the whole observation closed, so a contradictory profile
/// is never selected from an unvalidated declaration.
fn valid_region(region: &Option<String>) -> bool {
    region.as_ref().is_none_or(|region| {
        region.len() == 2 && region.bytes().all(|byte| byte.is_ascii_uppercase())
    })
}

/// Owns the observed exit generation across ticks. The generation stays stable
/// while the exit is continuously Ready with the same region and is minted afresh
/// on every entry into Ready, on any region change and after a restart, so an old
/// browser session can never be revived.
pub struct Observer {
    generation: Uuid,
    ready: bool,
    draining: bool,
    region: Option<String>,
}

impl Default for Observer {
    fn default() -> Self {
        Self::new()
    }
}

impl Observer {
    pub fn new() -> Self {
        Self {
            generation: Uuid::new_v4(),
            ready: false,
            draining: false,
            region: None,
        }
    }

    /// Translate one reading into a short lease. The ten-second lifetime is
    /// deliberately independent of the observer's at-most-five-second renewal
    /// cadence. This leaves headroom for fractional wall-clock truncation and a
    /// bounded collection/scheduling delay without extending the contract's
    /// existing maximum lifetime. A not-Ready reading still fails closed on its
    /// next publication.
    ///
    /// A requested drain is only reported while the previous reading was Ready or
    /// Draining and the evidence still holds: the old path must stay protected for
    /// work that continues on it. The generation is kept for the drain and every
    /// return to Ready mints a new one, because the exit may have changed.
    pub fn update(&mut self, observation: &Observation, now: i64) -> EgressState {
        let proven = observation.proven();
        let draining = proven && observation.draining && (self.ready || self.draining);
        let ready = proven && !draining && !observation.draining;
        let region = if proven {
            // A drain keeps describing the exit that existing work is using.
            if draining {
                self.region.clone()
            } else {
                observation.region.clone()
            }
        } else {
            None
        };
        if ready && (!self.ready || region != self.region) {
            self.generation = Uuid::new_v4();
        }
        self.ready = ready;
        self.draining = draining;
        self.region = region.clone();
        EgressState {
            version: 1,
            generation: self.generation,
            mode: if draining {
                EgressMode::Draining
            } else if ready {
                EgressMode::Ready
            } else {
                EgressMode::Offline
            },
            valid_until: now.saturating_add(MAX_LEASE_SECONDS),
            region,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress_control::Controller;
    use std::time::{Duration, Instant};

    fn ready(region: Option<&str>) -> Observation {
        Observation {
            interface_up: true,
            default_route: true,
            firewall_marker: true,
            region: region.map(str::to_owned),
            link_kind: None,
            egress_paths: None,
            draining: false,
        }
    }

    #[test]
    fn ready_observation_publishes_ready_with_region_and_bounded_lease() {
        let mut observer = Observer::new();
        let state = observer.update(&ready(Some("DE")), 100);
        assert_eq!(state.version, 1);
        assert_eq!(state.mode, EgressMode::Ready);
        assert_eq!(state.region.as_deref(), Some("DE"));
        assert_eq!(state.valid_until, 110);
        assert!(!state.generation.is_nil());
    }

    #[test]
    fn every_failed_check_is_offline() {
        for observation in [
            Observation {
                interface_up: false,
                ..ready(Some("DE"))
            },
            Observation {
                default_route: false,
                ..ready(Some("DE"))
            },
            Observation {
                firewall_marker: false,
                ..ready(Some("DE"))
            },
        ] {
            let mut observer = Observer::new();
            let state = observer.update(&observation, 100);
            assert_eq!(state.mode, EgressMode::Offline);
            assert_eq!(state.region, None);
        }
    }

    #[test]
    fn invalid_region_fails_closed() {
        for region in ["de", "DEU", "D", "D3", "12", "é", ""] {
            let mut observer = Observer::new();
            let state = observer.update(&ready(Some(region)), 100);
            assert_eq!(state.mode, EgressMode::Offline, "region {region:?}");
            assert_eq!(state.region, None);
        }
    }

    #[test]
    fn region_change_and_recovery_rotate_generation_but_refresh_does_not() {
        let mut observer = Observer::new();
        let first = observer.update(&ready(Some("DE")), 100);
        let refresh = observer.update(&ready(Some("DE")), 101);
        assert_eq!(refresh.generation, first.generation);
        let rotated = observer.update(&ready(Some("FR")), 102);
        assert_ne!(rotated.generation, first.generation);
        assert_eq!(rotated.region.as_deref(), Some("FR"));
        let dropped = observer.update(&ready(None), 103);
        assert_eq!(dropped.mode, EgressMode::Ready);
        assert_ne!(dropped.generation, first.generation);
        let recovered = observer.update(&ready(Some("FR")), 104);
        assert_eq!(recovered.region.as_deref(), Some("FR"));
        let offline = observer.update(
            &Observation {
                interface_up: false,
                ..ready(Some("FR"))
            },
            105,
        );
        assert_eq!(offline.mode, EgressMode::Offline);
        // Recovery mints a fresh generation rather than resurrecting one.
        let back = observer.update(&ready(Some("FR")), 106);
        assert_ne!(back.generation, recovered.generation);
        let restarted = Observer::new().update(&ready(Some("FR")), 100);
        assert_ne!(restarted.generation, back.generation);
    }

    fn draining(region: Option<&str>) -> Observation {
        Observation {
            draining: true,
            ..ready(region)
        }
    }

    #[test]
    fn a_planned_drain_keeps_the_generation_and_every_return_to_ready_mints_a_new_one() {
        let mut observer = Observer::new();
        let first = observer.update(&ready(Some("DE")), 100);
        let drain = observer.update(&draining(Some("DE")), 101);
        assert_eq!(drain.mode, EgressMode::Draining);
        assert_eq!(drain.generation, first.generation);
        assert_eq!(drain.region.as_deref(), Some("DE"));
        assert_eq!(drain.valid_until, 111);
        let continued = observer.update(&draining(Some("DE")), 102);
        assert_eq!(continued.generation, first.generation);
        // The exit may have changed during the drain, so the old generation is gone.
        let back = observer.update(&ready(Some("DE")), 103);
        assert_eq!(back.mode, EgressMode::Ready);
        assert_ne!(back.generation, first.generation);
    }

    #[test]
    fn a_drain_without_a_prior_ready_or_with_failed_evidence_stays_offline() {
        let mut observer = Observer::new();
        assert_eq!(
            observer.update(&draining(Some("DE")), 100).mode,
            EgressMode::Offline
        );
        let mut observer = Observer::new();
        observer.update(&ready(Some("DE")), 100);
        let lost = Observation {
            interface_up: false,
            ..draining(Some("DE"))
        };
        let state = observer.update(&lost, 101);
        assert_eq!(state.mode, EgressMode::Offline);
        assert_eq!(state.region, None);
        // A drain request no longer applies once the exit was lost.
        assert_eq!(
            observer.update(&draining(Some("DE")), 102).mode,
            EgressMode::Offline
        );
    }

    #[test]
    fn selected_evidence_must_hold_and_unselected_evidence_is_ignored() {
        for failed in [
            Observation {
                link_kind: Some(false),
                ..ready(Some("DE"))
            },
            Observation {
                egress_paths: Some(false),
                ..ready(Some("DE"))
            },
        ] {
            let state = Observer::new().update(&failed, 100);
            assert_eq!(state.mode, EgressMode::Offline);
            assert_eq!(state.region, None);
        }
        let held = Observation {
            link_kind: Some(true),
            egress_paths: Some(true),
            ..ready(Some("DE"))
        };
        assert_eq!(Observer::new().update(&held, 100).mode, EgressMode::Ready);
    }

    #[test]
    fn assertions_alone_never_make_the_exit_ready() {
        // The marker and region are operator assertions; without observed
        // interface and route evidence they cannot produce a Ready lease.
        let asserted_only = Observation {
            interface_up: false,
            default_route: false,
            ..ready(Some("DE"))
        };
        assert_eq!(
            Observer::new().update(&asserted_only, 100).mode,
            EgressMode::Offline
        );
    }

    /// Observer and controller exactly as deployed: the observer publishes a
    /// short lease, the controller polls and publishes its own, and both can die.
    struct Chain {
        observer: Observer,
        controller: Controller,
        published: Option<EgressState>,
        start: Instant,
        origin: i64,
    }

    impl Chain {
        fn new(drain_seconds: u64) -> Self {
            Self {
                observer: Observer::new(),
                controller: Controller::new(drain_seconds).unwrap(),
                published: None,
                start: Instant::now(),
                origin: 1_000,
            }
        }

        /// The observer publishes a new reading, then the controller polls.
        fn observe(&mut self, observation: &Observation, second: i64) -> EgressState {
            self.published = Some(self.observer.update(observation, self.origin + second));
            self.poll(second)
        }

        /// The controller polls the last published lease (the observer may be dead).
        fn poll(&mut self, second: i64) -> EgressState {
            self.controller.update(
                self.published.clone(),
                self.origin + second,
                self.start + Duration::from_secs(second as u64),
            )
        }
    }

    #[test]
    fn tunnel_loss_exit_change_and_recovery_rotate_the_controller_generation() {
        let mut chain = Chain::new(60);
        let first = chain.observe(&ready(Some("DE")), 0);
        assert_eq!(first.mode, EgressMode::Ready);
        // Healthy refreshes never rotate the generation.
        for second in 1..=12 {
            let refreshed = chain.observe(&ready(Some("DE")), second);
            assert_eq!(refreshed.generation, first.generation, "second {second}");
        }
        // Tunnel loss is Offline on the very next poll and carries no region.
        let lost = chain.observe(
            &Observation {
                interface_up: false,
                ..ready(Some("DE"))
            },
            13,
        );
        assert_eq!(lost.mode, EgressMode::Offline);
        assert_eq!(lost.region, None);
        // Recovery is a new epoch, never a revived one.
        let recovered = chain.observe(&ready(Some("DE")), 14);
        assert_eq!(recovered.mode, EgressMode::Ready);
        assert_ne!(recovered.generation, first.generation);
        // An exit change without any gap is still a new generation and region.
        let changed = chain.observe(&ready(Some("FR")), 15);
        assert_eq!(changed.mode, EgressMode::Ready);
        assert_ne!(changed.generation, recovered.generation);
        assert_eq!(changed.region.as_deref(), Some("FR"));
    }

    #[test]
    fn a_planned_drain_preserves_work_until_its_deadline_and_recovers_with_a_new_generation() {
        let mut chain = Chain::new(60);
        let ready_state = chain.observe(&ready(Some("DE")), 0);
        let draining_state = chain.observe(&draining(Some("DE")), 5);
        assert_eq!(draining_state.mode, EgressMode::Draining);
        assert_eq!(draining_state.generation, ready_state.generation);
        assert_eq!(draining_state.region.as_deref(), Some("DE"));
        // Repeated drain heartbeats cannot extend the deadline.
        for second in [20, 40, 64] {
            let still = chain.observe(&draining(Some("DE")), second);
            assert_eq!(still.mode, EgressMode::Draining, "second {second}");
            assert_eq!(still.generation, ready_state.generation);
        }
        let expired = chain.observe(&draining(Some("DE")), 66);
        assert_eq!(expired.mode, EgressMode::Offline);
        assert_eq!(expired.region, None);
        // The marker is removed after the exit change: fresh proof, new generation.
        let recovered = chain.observe(&ready(Some("DE")), 70);
        assert_eq!(recovered.mode, EgressMode::Ready);
        assert_ne!(recovered.generation, ready_state.generation);
    }

    #[test]
    fn evidence_lost_during_a_drain_ends_it_immediately() {
        let mut chain = Chain::new(60);
        let ready_state = chain.observe(&ready(Some("DE")), 0);
        assert_eq!(
            chain.observe(&draining(Some("DE")), 1).mode,
            EgressMode::Draining
        );
        let lost = chain.observe(
            &Observation {
                default_route: false,
                ..draining(Some("DE"))
            },
            2,
        );
        assert_eq!(lost.mode, EgressMode::Offline);
        let recovered = chain.observe(&ready(Some("DE")), 3);
        assert_ne!(recovered.generation, ready_state.generation);
    }

    #[test]
    fn a_dead_or_stale_observer_expires_within_the_short_lease() {
        let mut chain = Chain::new(60);
        let first = chain.observe(&ready(Some("DE")), 0);
        // The observer dies after its last publication: its ten-second lease is
        // honored, and the controller never grants more than three seconds.
        let within = chain.poll(5);
        assert_eq!(within.mode, EgressMode::Ready);
        assert_eq!(within.generation, first.generation);
        assert!(within.valid_until <= chain.origin + 5 + 3);
        // At the lease's end the observation is stale and the exit is Offline.
        assert_eq!(chain.poll(10).mode, EgressMode::Offline);
        assert_eq!(chain.poll(300).mode, EgressMode::Offline);
        // A restarted observer starts a new epoch.
        let restarted = Chain {
            observer: Observer::new(),
            ..chain
        };
        let mut restarted = restarted;
        let back = restarted.observe(&ready(Some("DE")), 301);
        assert_eq!(back.mode, EgressMode::Ready);
        assert_ne!(back.generation, first.generation);
    }

    #[test]
    fn a_restarted_controller_never_resumes_the_previous_generation() {
        let mut chain = Chain::new(60);
        let first = chain.observe(&ready(Some("DE")), 0);
        // The controller process dies and restarts while the observer keeps publishing.
        chain.controller = Controller::new(60).unwrap();
        let resumed = chain.poll(1);
        assert_eq!(resumed.mode, EgressMode::Ready);
        assert_ne!(resumed.generation, first.generation);
        // A stale lease is never revived by a restart either.
        chain.controller = Controller::new(60).unwrap();
        assert_eq!(chain.poll(30).mode, EgressMode::Offline);
    }

    #[test]
    fn lease_uses_the_contract_maximum_independently_of_renewal_cadence() {
        let mut observer = Observer::new();
        assert_eq!(observer.update(&ready(Some("DE")), 100).valid_until, 110);
    }

    #[test]
    fn healthy_refreshes_remain_ready_across_fractional_clock_phases() {
        // Model the real producer/consumer relationship: the observer publishes
        // on five-second interval ticks after bounded collection/scheduling
        // delay, timestamps leases in whole Unix seconds, and the controller
        // polls every 250 ms. A continuously healthy observation must never
        // become Offline or rotate the controller generation between publishes.
        let publications_ms = [100_800_i64, 106_550, 110_900, 116_200];
        let end_ms = 120_000_i64;
        let monotonic_start = Instant::now();
        let mut observer = Observer::new();
        let mut controller = Controller::new(60).unwrap();
        let mut publication = 0;
        let mut observed = None;
        let mut generation = None;

        for poll_ms in (100_750_i64..=end_ms).step_by(250) {
            while publication < publications_ms.len() && publications_ms[publication] <= poll_ms {
                observed =
                    Some(observer.update(&ready(Some("DE")), publications_ms[publication] / 1_000));
                publication += 1;
            }
            let state = controller.update(
                observed.clone(),
                poll_ms / 1_000,
                monotonic_start + Duration::from_millis((poll_ms - 100_750) as u64),
            );
            if observed.is_none() {
                assert_eq!(state.mode, EgressMode::Offline);
                continue;
            }
            assert_eq!(
                state.mode,
                EgressMode::Ready,
                "healthy lease lapsed at {poll_ms} ms"
            );
            match generation {
                Some(initial) => assert_eq!(state.generation, initial),
                None => generation = Some(state.generation),
            }
        }
    }
}
