//! Bounded, privacy-safe JSON diagnostics for the egress readiness path.
//!
//! Every field is selected by the service. Callers cannot attach queries, URLs,
//! bodies, keys, addresses, interface names, regions, paths, or upstream errors.

use crate::error::ErrorCode;
use serde::Serialize;

pub const SCHEMA: &str = "secure-research-diagnostic/v1";

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    VpnObserver,
    EgressControl,
    Service,
    Egress,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    InterfaceFlagsUnreadable,
    InterfaceDown,
    InterfaceFlagsMalformed,
    InterfaceIndexUnavailable,
    RouteDumpUnavailable,
    NoDefaultRoute,
    RouteDumpMalformed,
    FirewallMarkerMissing,
    FirewallMarkerInsecure,
    ObservationLeaseUnavailable,
    ObservationLeaseInvalid,
    ObservationLeaseExpired,
    ControlLeaseUnavailable,
    ControlLeaseInvalid,
    ControlLeaseExpired,
    GenerationChanged,
    RelayAcceptFailed,
    RelayConnectTimeout,
    RelayConnectFailed,
    RelayPeerUnauthorized,
    RelayTransportTimeout,
    RelayTransportFailed,
    DnsIpv4Failed,
    DnsIpv6Failed,
    UpstreamConnectFailed,
    TransportTimeout,
    TransportTlsFailed,
    TransportConnectFailed,
    TransportRequestBodyFailed,
    TransportDecodeFailed,
    TransportRequestFailed,
    TransportUnavailable,
    TransportSizeLimit,
    DestinationDenied,
    RequestRejected,
    TransportFailed,
    BrowserWorkspaceCleanupFailed,
    ProcessFailed,
}

impl Event {
    const fn phase(self) -> &'static str {
        match self {
            Self::InterfaceFlagsUnreadable
            | Self::InterfaceDown
            | Self::InterfaceFlagsMalformed
            | Self::InterfaceIndexUnavailable
            | Self::RouteDumpUnavailable
            | Self::NoDefaultRoute
            | Self::RouteDumpMalformed
            | Self::FirewallMarkerMissing
            | Self::FirewallMarkerInsecure => "observation",
            Self::ObservationLeaseUnavailable
            | Self::ObservationLeaseInvalid
            | Self::ObservationLeaseExpired => "observation_lease",
            Self::ControlLeaseUnavailable
            | Self::ControlLeaseInvalid
            | Self::ControlLeaseExpired
            | Self::GenerationChanged => "readiness",
            Self::RelayAcceptFailed
            | Self::RelayConnectTimeout
            | Self::RelayConnectFailed
            | Self::RelayPeerUnauthorized
            | Self::RelayTransportTimeout
            | Self::RelayTransportFailed => "relay",
            Self::DnsIpv4Failed | Self::DnsIpv6Failed => "dns",
            Self::UpstreamConnectFailed => "connect",
            Self::TransportTimeout
            | Self::TransportTlsFailed
            | Self::TransportConnectFailed
            | Self::TransportRequestBodyFailed
            | Self::TransportDecodeFailed
            | Self::TransportRequestFailed
            | Self::TransportUnavailable
            | Self::TransportSizeLimit
            | Self::DestinationDenied
            | Self::RequestRejected
            | Self::TransportFailed => "transport",
            Self::BrowserWorkspaceCleanupFailed | Self::ProcessFailed => "lifecycle",
        }
    }
}

#[derive(Serialize)]
struct Record {
    schema: &'static str,
    component: Component,
    event: Event,
    phase: &'static str,
    count: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<ErrorCode>,
}

fn line(component: Component, event: Event, error_code: Option<ErrorCode>) -> String {
    serde_json::to_string(&Record {
        schema: SCHEMA,
        component,
        event,
        phase: event.phase(),
        count: 1,
        error_code,
    })
    .unwrap_or_else(|_| {
        "{\"schema\":\"secure-research-diagnostic/v1\",\"component\":\"service\",\"event\":\"request_rejected\",\"phase\":\"transport\",\"count\":1}".to_owned()
    })
}

pub fn emit(component: Component, event: Event) {
    eprintln!("{}", line(component, event, None));
}

pub fn emit_error(component: Component, error_code: ErrorCode) {
    eprintln!(
        "{}",
        line(component, Event::ProcessFailed, Some(error_code))
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_are_single_line_bounded_and_have_only_fixed_fields() {
        let record = line(Component::Service, Event::TransportTlsFailed, None);
        assert!(record.len() < 256);
        assert!(!record.contains('\n') && !record.contains('\r'));
        let value: serde_json::Value = serde_json::from_str(&record).unwrap();
        assert_eq!(
            value.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["component", "count", "event", "phase", "schema"]
        );
        assert_eq!(value["schema"], SCHEMA);
        assert_eq!(value["component"], "service");
        assert_eq!(value["event"], "transport_tls_failed");
        assert_eq!(value["phase"], "transport");
        assert_eq!(value["count"], 1);

        let error = line(
            Component::EgressControl,
            Event::ProcessFailed,
            Some(ErrorCode::Capacity),
        );
        let value: serde_json::Value = serde_json::from_str(&error).unwrap();
        assert_eq!(value["component"], "egress_control");
        assert_eq!(value["event"], "process_failed");
        assert_eq!(value["phase"], "lifecycle");
        assert_eq!(value["error_code"], "capacity");

        let cleanup = line(
            Component::Service,
            Event::BrowserWorkspaceCleanupFailed,
            None,
        );
        let value: serde_json::Value = serde_json::from_str(&cleanup).unwrap();
        assert_eq!(value["event"], "browser_workspace_cleanup_failed");
        assert_eq!(value["phase"], "lifecycle");
        assert_eq!(value.as_object().unwrap().len(), 5);
    }
}
