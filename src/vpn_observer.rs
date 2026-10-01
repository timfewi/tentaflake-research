//! Reference root observer for the VPN/firewall observation lease. `update` is a
//! pure, fail-closed state machine over local, non-cryptographic evidence:
//! interface-up, an IPv4 default route on that interface, a root-owned firewall
//! marker and an operator-declared region. It deliberately does not prove the
//! cryptographic exit identity of the encrypted tunnel; the kernel firewall
//! remains the independent invariant.

use crate::egress::{EgressMode, EgressState, MAX_LEASE_SECONDS};
use uuid::Uuid;

/// One point-in-time reading of the local evidence the observer can gather.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub interface_up: bool,
    pub default_route: bool,
    pub firewall_marker: bool,
    pub region: Option<String>,
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
            region: None,
        }
    }

    /// Translate one reading into a short lease. The ten-second lifetime is
    /// deliberately independent of the observer's at-most-five-second renewal
    /// cadence. This leaves headroom for fractional wall-clock truncation and a
    /// bounded collection/scheduling delay without extending the contract's
    /// existing maximum lifetime. A not-Ready reading still fails closed on its
    /// next publication.
    pub fn update(&mut self, observation: &Observation, now: i64) -> EgressState {
        let ready = observation.interface_up
            && observation.default_route
            && observation.firewall_marker
            && valid_region(&observation.region);
        let region = if ready {
            observation.region.clone()
        } else {
            None
        };
        if ready && (!self.ready || region != self.region) {
            self.generation = Uuid::new_v4();
        }
        self.ready = ready;
        self.region = region.clone();
        EgressState {
            version: 1,
            generation: self.generation,
            mode: if ready {
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
