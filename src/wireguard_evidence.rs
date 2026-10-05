//! WireGuard peer evidence from the generic-netlink device dump: which peers an
//! interface has and when each last completed a handshake. A handshake is
//! authenticated with the peer's key, so a recent one shows the configured peer is
//! alive, and the set of peer keys is the exit's identity.
//!
//! The kernel's dump also carries the interface's private key and any preshared
//! keys. This module reads only each peer's public key and handshake time and
//! never copies, stores or logs a secret attribute; callers scrub their receive
//! buffers after parsing. Pure parsing and evaluation only; the socket I/O lives
//! in the observer binary.

use crate::vpn_evidence::{align4, attributes, collect, read_u16};
use base64::{Engine, engine::general_purpose::STANDARD};

pub const GENL_ID_CTRL: u16 = 0x10;
/// A dump of a handful of peers is far below this; larger replies are refused so
/// the receive buffer never reallocates (and never leaves unscrubbed copies).
pub const MAX_DUMP_BYTES: usize = 64 * 1024;

const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const WG_CMD_GET_DEVICE: u8 = 0;
const WG_GENL_VERSION: u8 = 1;
const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PEERS: u16 = 8;
const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;

/// Network-order independent: lengths and ids use the host's byte order, as the
/// kernel expects for netlink.
fn request(kind: u16, flags: u16, command: u8, attribute: u16, value: &[u8]) -> Vec<u8> {
    let length = 16 + 4 + 4 + value.len();
    let mut bytes = vec![0u8; align4(length)];
    bytes[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
    bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
    bytes[6..8].copy_from_slice(&flags.to_ne_bytes());
    bytes[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
    bytes[16] = command;
    bytes[17] = if kind == GENL_ID_CTRL {
        2
    } else {
        WG_GENL_VERSION
    };
    bytes[20..22].copy_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
    bytes[22..24].copy_from_slice(&attribute.to_ne_bytes());
    bytes[24..24 + value.len()].copy_from_slice(value);
    bytes
}

/// Ask the generic-netlink controller for the WireGuard family id.
pub fn family_request() -> Vec<u8> {
    request(
        GENL_ID_CTRL,
        NLM_F_REQUEST,
        CTRL_CMD_GETFAMILY,
        CTRL_ATTR_FAMILY_NAME,
        b"wireguard\0",
    )
}

/// The family id from the controller's reply, or `None` when it is missing,
/// malformed or an error (for example, WireGuard is not available).
pub fn parse_family_id(reply: &[u8]) -> Option<u16> {
    for message in collect(reply, false)? {
        if message.kind != GENL_ID_CTRL || message.payload.len() < 4 {
            continue;
        }
        for (attribute, value) in attributes(message.payload, 4)? {
            if attribute == CTRL_ATTR_FAMILY_ID && value.len() == 2 {
                return read_u16(value, 0);
            }
        }
    }
    None
}

/// Dump the device named `interface`.
pub fn device_request(family: u16, interface: &str) -> Vec<u8> {
    let mut name = interface.as_bytes().to_vec();
    name.push(0);
    request(
        family,
        NLM_F_REQUEST | NLM_F_DUMP,
        WG_CMD_GET_DEVICE,
        WGDEVICE_A_IFNAME,
        &name,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub public_key: [u8; 32],
    /// Unix seconds of the last completed handshake; `None` if there never was one.
    pub last_handshake: Option<i64>,
}

/// The peers of the dumped device. Malformed, truncated or error-carrying dumps
/// are `None`. A peer split over several messages is merged by its public key.
pub fn parse_peers(dump: &[u8]) -> Option<Vec<Peer>> {
    let mut peers: Vec<Peer> = Vec::new();
    for message in collect(dump, true)? {
        if message.payload.len() < 4 {
            continue;
        }
        for (attribute, list) in attributes(message.payload, 4)? {
            // The private key and the other device attributes are skipped here.
            if attribute != WGDEVICE_A_PEERS {
                continue;
            }
            for (_, peer) in attributes(list, 0)? {
                let (mut key, mut handshake) = (None, None);
                for (attribute, value) in attributes(peer, 0)? {
                    match attribute {
                        WGPEER_A_PUBLIC_KEY => key = <[u8; 32]>::try_from(value).ok(),
                        WGPEER_A_LAST_HANDSHAKE_TIME if value.len() == 16 => {
                            let seconds = i64::from_ne_bytes(value[0..8].try_into().ok()?);
                            let nanoseconds = i64::from_ne_bytes(value[8..16].try_into().ok()?);
                            handshake = (seconds != 0 || nanoseconds != 0).then_some(seconds);
                        }
                        // Preshared keys and every other peer attribute are ignored.
                        _ => {}
                    }
                }
                let public_key = key?;
                match peers
                    .iter_mut()
                    .find(|known| known.public_key == public_key)
                {
                    Some(known) => known.last_handshake = known.last_handshake.max(handshake),
                    None => peers.push(Peer {
                        public_key,
                        last_handshake: handshake,
                    }),
                }
            }
        }
    }
    Some(peers)
}

/// A WireGuard public key as base64. It is not a secret.
pub fn decode_public_key(text: &str) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(STANDARD.decode(text.trim()).ok()?).ok()
}

/// Whether the peers satisfy the selected evidence. With `pins`, the device's peers
/// must be exactly those keys (the exit's identity); with `window`, each pinned
/// peer (or, without pins, at least one peer) must have completed a handshake no
/// longer ago than `window` seconds. A device without peers is never proof.
pub fn peers_ok(peers: &[Peer], pins: &[[u8; 32]], window: Option<u64>, now: i64) -> bool {
    let fresh = |peer: &Peer| {
        window.is_none_or(|window| {
            peer.last_handshake.is_some_and(|time| {
                now.saturating_sub(time) <= i64::try_from(window).unwrap_or(i64::MAX)
            })
        })
    };
    let identity = pins.is_empty()
        || (peers.len() == pins.len()
            && pins
                .iter()
                .all(|pin| peers.iter().any(|peer| peer.public_key == *pin)));
    let alive = if pins.is_empty() {
        peers.iter().any(fresh)
    } else {
        peers.iter().all(fresh)
    };
    !peers.is_empty() && identity && alive
}

/// Builders for synthetic generic-netlink dumps. They include secret attributes on
/// purpose, to show the parser never returns them.
#[cfg(any(test, feature = "isolation-tests"))]
pub mod synthetic {
    use super::*;

    const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
    const WGPEER_A_PRESHARED_KEY: u16 = 2;
    const NLA_F_NESTED: u16 = 0x8000;
    const NLMSG_DONE: u16 = 3;
    const NLMSG_ERROR: u16 = 2;
    /// A recognizable pattern standing in for key material.
    pub const SECRET: u8 = 0xA5;

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = 4 + value.len();
        let mut bytes = vec![0u8; align4(length)];
        bytes[0..2].copy_from_slice(&(length as u16).to_ne_bytes());
        bytes[2..4].copy_from_slice(&kind.to_ne_bytes());
        bytes[4..4 + value.len()].copy_from_slice(value);
        bytes
    }

    fn message(kind: u16, payload: &[u8]) -> Vec<u8> {
        let length = 16 + payload.len();
        let mut bytes = vec![0u8; align4(length)];
        bytes[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
        bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
        bytes[16..16 + payload.len()].copy_from_slice(payload);
        bytes
    }

    /// One nested peer element: public key, a preshared key and the handshake.
    pub fn peer(key: [u8; 32], handshake: Option<i64>) -> Vec<u8> {
        let mut inner = attribute(WGPEER_A_PUBLIC_KEY, &key);
        inner.extend(attribute(WGPEER_A_PRESHARED_KEY, &[SECRET; 32]));
        let mut time = handshake.unwrap_or(0).to_ne_bytes().to_vec();
        time.extend(0i64.to_ne_bytes());
        inner.extend(attribute(WGPEER_A_LAST_HANDSHAKE_TIME, &time));
        attribute(NLA_F_NESTED, &inner)
    }

    /// A device message carrying `peers` (and the device's private key), then DONE.
    pub fn device_dump(family: u16, peers: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = vec![WG_CMD_GET_DEVICE, WG_GENL_VERSION, 0, 0];
        payload.extend(attribute(WGDEVICE_A_PRIVATE_KEY, &[SECRET; 32]));
        payload.extend(attribute(WGDEVICE_A_PEERS | NLA_F_NESTED, &peers.concat()));
        let mut dump = message(family, &payload);
        dump.extend(message(NLMSG_DONE, &[]));
        dump
    }

    /// The controller's reply to [`family_request`].
    pub fn family_reply(id: u16) -> Vec<u8> {
        let mut payload = vec![1, 2, 0, 0];
        payload.extend(attribute(CTRL_ATTR_FAMILY_ID, &id.to_ne_bytes()));
        message(GENL_ID_CTRL, &payload)
    }

    pub fn error(errno: i32) -> Vec<u8> {
        message(NLMSG_ERROR, &errno.to_ne_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::synthetic::*;
    use super::*;

    const FAMILY: u16 = 33;
    const NOW: i64 = 1_000_000;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn peers(handshakes: &[(u8, Option<i64>)]) -> Vec<Peer> {
        let list: Vec<Vec<u8>> = handshakes
            .iter()
            .map(|(byte, time)| peer(key(*byte), *time))
            .collect();
        parse_peers(&device_dump(FAMILY, &list)).unwrap()
    }

    #[test]
    fn requests_name_the_family_and_the_device() {
        let family = family_request();
        assert_eq!(&family[4..6], &GENL_ID_CTRL.to_ne_bytes());
        assert!(family.windows(10).any(|window| window == b"wireguard\0"));
        let device = device_request(FAMILY, "wg0");
        assert_eq!(&device[4..6], &FAMILY.to_ne_bytes());
        assert_eq!(&device[6..8], &(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        assert!(device.windows(4).any(|window| window == b"wg0\0"));
        // The declared length excludes padding and never exceeds the buffer.
        for request in [family, device] {
            let length = u32::from_ne_bytes(request[0..4].try_into().unwrap()) as usize;
            assert!(length <= request.len() && request.len() - length < 4);
        }
    }

    #[test]
    fn the_family_id_comes_from_the_controller_reply() {
        assert_eq!(parse_family_id(&family_reply(FAMILY)), Some(FAMILY));
        assert_eq!(parse_family_id(&error(-2)), None, "family not found");
        assert_eq!(parse_family_id(&[]), None);
    }

    #[test]
    fn peers_carry_only_the_public_key_and_the_handshake_time() {
        let parsed = peers(&[(1, Some(NOW - 10)), (2, None)]);
        assert_eq!(
            parsed,
            vec![
                Peer {
                    public_key: key(1),
                    last_handshake: Some(NOW - 10)
                },
                Peer {
                    public_key: key(2),
                    last_handshake: None
                },
            ]
        );
        // The synthetic dump holds private and preshared key patterns; none of
        // the returned data contains them.
        let dump = device_dump(FAMILY, &[peer(key(1), Some(NOW))]);
        assert!(dump.windows(32).any(|window| window == [SECRET; 32]));
        assert!(parsed.iter().all(|peer| !peer.public_key.contains(&SECRET)));
    }

    #[test]
    fn a_peer_split_over_messages_keeps_its_latest_handshake() {
        let mut dump = device_dump(FAMILY, &[peer(key(1), Some(NOW - 50))]);
        dump.truncate(dump.len() - 16); // drop DONE between the two messages
        dump.extend(device_dump(FAMILY, &[peer(key(1), Some(NOW - 5))]));
        let parsed = parse_peers(&dump).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].last_handshake, Some(NOW - 5));
    }

    #[test]
    fn failing_truncated_or_unterminated_dumps_are_not_evidence() {
        let dump = device_dump(FAMILY, &[peer(key(1), Some(NOW))]);
        assert!(parse_peers(&dump).is_some());
        assert!(parse_peers(&dump[..dump.len() - 16]).is_none(), "no DONE");
        assert!(parse_peers(&dump[..10]).is_none());
        assert!(parse_peers(&error(-19)).is_none(), "no such device");
        assert!(parse_peers(&[]).is_none());
    }

    #[test]
    fn public_keys_are_decoded_from_base64_only_at_the_exact_length() {
        use base64::Engine;
        let text = STANDARD.encode(key(7));
        assert_eq!(decode_public_key(&text), Some(key(7)));
        assert_eq!(decode_public_key(&format!("{text}\n")), Some(key(7)));
        assert_eq!(decode_public_key("AAAA"), None);
        assert_eq!(decode_public_key("not base64!"), None);
        assert_eq!(decode_public_key(""), None);
    }

    #[test]
    fn pinned_peers_must_match_exactly_and_be_recent() {
        let fresh = peers(&[(1, Some(NOW - 10))]);
        assert!(peers_ok(&fresh, &[key(1)], Some(180), NOW));
        // Identity only (no window): the key matches even without a handshake.
        assert!(peers_ok(&peers(&[(1, None)]), &[key(1)], None, NOW));
        // A stale or missing handshake fails the window.
        assert!(!peers_ok(
            &peers(&[(1, Some(NOW - 181))]),
            &[key(1)],
            Some(180),
            NOW
        ));
        assert!(!peers_ok(&peers(&[(1, None)]), &[key(1)], Some(180), NOW));
        // A different or additional peer is not the pinned exit.
        assert!(!peers_ok(&fresh, &[key(2)], Some(180), NOW));
        let extra = peers(&[(1, Some(NOW)), (2, Some(NOW))]);
        assert!(!peers_ok(&extra, &[key(1)], Some(180), NOW));
        assert!(!peers_ok(&fresh, &[key(1), key(2)], Some(180), NOW));
        // A device without peers is never proof, pinned or not.
        assert!(!peers_ok(&[], &[], Some(180), NOW));
        assert!(!peers_ok(&[], &[key(1)], None, NOW));
    }

    #[test]
    fn without_pins_one_recent_peer_is_enough() {
        let mixed = peers(&[(1, Some(NOW - 1000)), (2, Some(NOW - 5))]);
        assert!(peers_ok(&mixed, &[], Some(180), NOW));
        assert!(!peers_ok(
            &peers(&[(1, Some(NOW - 1000))]),
            &[],
            Some(180),
            NOW
        ));
        // The boundary is inclusive.
        assert!(peers_ok(
            &peers(&[(1, Some(NOW - 180))]),
            &[],
            Some(180),
            NOW
        ));
    }
}
