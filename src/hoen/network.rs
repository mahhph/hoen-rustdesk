//! Direct local-network admission. Peer identity is authenticated separately.
//! This is a snapshot check, not a firewall, transport authentication, or transition monitor.
//! OS queries block: invoke them from a worker, never directly on an async runtime.
use std::net::{IpAddr, SocketAddr};

/// The local address is selected for this socket, not pinned to a particular network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub local_address: IpAddr,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub local_address: IpAddr,
    pub peer_address: IpAddr,
    pub physical_lan: bool,
    pub interface_up: bool,
    pub route_matches: bool,
    pub route_on_link: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denied {
    MissingPolicy,
    InvalidPolicy,
    NotApproved,
    SnapshotUnavailable,
}
fn valid_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.octets()[0] != 0 && a.octets()[0] < 224 && !a.is_loopback(),
        IpAddr::V6(a) => {
            !a.is_unspecified()
                && !a.is_loopback()
                && !a.is_multicast()
                && a.to_ipv4_mapped().is_none()
        }
    }
}
/// Verify the configured local address before binding a listener.
pub fn admit_binding(policy: Option<&Policy>, snapshot: &Snapshot) -> Result<(), Denied> {
    let p = policy.ok_or(Denied::MissingPolicy)?;
    if !valid_ip(p.local_address) {
        return Err(Denied::InvalidPolicy);
    }
    if p.local_address != snapshot.local_address || !snapshot.physical_lan || !snapshot.interface_up
    {
        return Err(Denied::NotApproved);
    }
    Ok(())
}
/// Verify accepted sockets on admission and recheck after any relevant network change.
pub fn admit(policy: Option<&Policy>, snapshot: &Snapshot) -> Result<(), Denied> {
    admit_binding(policy, snapshot)?;
    if !valid_ip(snapshot.peer_address)
        || snapshot.peer_address.is_ipv4() != snapshot.local_address.is_ipv4()
        || snapshot.peer_address == snapshot.local_address
        || !snapshot.route_matches
        || !snapshot.route_on_link
    {
        return Err(Denied::NotApproved);
    }
    Ok(())
}
/// Check a configured address before binding; this does not reserve it or open a listener.
#[cfg(windows)]
pub fn verify_binding(policy: Option<&Policy>, local: SocketAddr) -> Result<(), Denied> {
    let p = policy.ok_or(Denied::MissingPolicy)?.clone();
    std::thread::spawn(move || {
        let snapshot = windows_snapshot::query(local, None).ok_or(Denied::SnapshotUnavailable)?;
        admit_binding(Some(&p), &snapshot)
    })
    .join()
    .unwrap_or(Err(Denied::SnapshotUnavailable))
}
#[cfg(all(target_os = "macos", feature = "hoen-mac-dev"))]
pub fn verify_binding(policy: Option<&Policy>, local: SocketAddr) -> Result<(), Denied> {
    super::macos_network::verify_binding(policy, local)
}
#[cfg(any(
    not(any(windows, target_os = "macos")),
    all(target_os = "macos", not(feature = "hoen-mac-dev"))
))]
pub fn verify_binding(_: Option<&Policy>, _: SocketAddr) -> Result<(), Denied> {
    Err(Denied::SnapshotUnavailable)
}
/// Query the platform and apply policy to actual socket addresses.
/// The caller must reject the session on any error and separately enforce authenticated identity.
#[cfg(windows)]
pub fn admit_socket(
    policy: Option<&Policy>,
    local: SocketAddr,
    peer: SocketAddr,
) -> Result<(), Denied> {
    let p = policy.ok_or(Denied::MissingPolicy)?.clone();
    std::thread::spawn(move || {
        let snapshot =
            windows_snapshot::query(local, Some(peer)).ok_or(Denied::SnapshotUnavailable)?;
        admit(Some(&p), &snapshot)
    })
    .join()
    .unwrap_or(Err(Denied::SnapshotUnavailable))
}
#[cfg(all(target_os = "macos", feature = "hoen-mac-dev"))]
pub fn admit_socket(
    policy: Option<&Policy>,
    local: SocketAddr,
    peer: SocketAddr,
) -> Result<(), Denied> {
    super::macos_network::admit_socket(policy, local, peer)
}
#[cfg(any(
    not(any(windows, target_os = "macos")),
    all(target_os = "macos", not(feature = "hoen-mac-dev"))
))]
pub fn admit_socket(_: Option<&Policy>, _: SocketAddr, _: SocketAddr) -> Result<(), Denied> {
    Err(Denied::SnapshotUnavailable)
}

#[cfg(windows)]
mod windows_snapshot {
    use super::Snapshot;
    use std::{
        mem::size_of,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    };
    use windows::Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS},
        NetworkManagement::{
            IpHelper::*,
            Ndis::{
                IfOperStatusUp, MediaConnectStateConnected, NdisPhysicalMedium802_3,
                NdisPhysicalMediumNative802_11, NdisPhysicalMediumWirelessLan, TUNNEL_TYPE_NONE,
            },
        },
        Networking::WinSock::*,
    };
    fn sock(addr: SocketAddr) -> SOCKADDR_INET {
        match addr {
            SocketAddr::V4(a) => SOCKADDR_INET {
                Ipv4: SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: 0,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(a.ip().octets()),
                        },
                    },
                    sin_zero: [0; 8],
                },
            },
            SocketAddr::V6(a) => SOCKADDR_INET {
                Ipv6: SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 {
                            Byte: a.ip().octets(),
                        },
                    },
                    Anonymous: SOCKADDR_IN6_0 {
                        sin6_scope_id: a.scope_id(),
                    },
                },
            },
        }
    }
    unsafe fn socket_ip(address: *const SOCKADDR, length: i32) -> Option<IpAddr> {
        if address.is_null() {
            return None;
        }
        unsafe {
            match (*address).sa_family {
                AF_INET if length as usize >= size_of::<SOCKADDR_IN>() => {
                    let s = &*(address as *const SOCKADDR_IN);
                    Some(IpAddr::V4(Ipv4Addr::from(
                        s.sin_addr.S_un.S_addr.to_ne_bytes(),
                    )))
                }
                AF_INET6 if length as usize >= size_of::<SOCKADDR_IN6>() => {
                    let s = &*(address as *const SOCKADDR_IN6);
                    Some(IpAddr::V6(Ipv6Addr::from(s.sin6_addr.u.Byte)))
                }
                _ => None,
            }
        }
    }
    unsafe fn inet_ip(address: &SOCKADDR_INET) -> Option<IpAddr> {
        unsafe {
            socket_ip(
                (address as *const SOCKADDR_INET).cast(),
                size_of::<SOCKADDR_INET>() as i32,
            )
        }
    }
    pub fn query(local: SocketAddr, peer: Option<SocketAddr>) -> Option<Snapshot> {
        if peer.map_or(false, |p| local.is_ipv4() != p.is_ipv4()) {
            return None;
        }
        unsafe {
            let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
            let mut bytes = 0u32;
            if GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, None, &mut bytes)
                != ERROR_BUFFER_OVERFLOW.0
                || bytes == 0
                || bytes > 1024 * 1024
            {
                return None;
            }
            let mut storage =
                vec![0usize; (bytes as usize + size_of::<usize>() - 1) / size_of::<usize>()];
            let first = storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            if GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(first), &mut bytes)
                != ERROR_SUCCESS.0
            {
                return None;
            }
            let mut matched = None;
            let mut cur = first;
            while let Some(adapter) = cur.as_ref() {
                let mut u = adapter.FirstUnicastAddress;
                let mut has_local = false;
                while let Some(address) = u.as_ref() {
                    if address.DadState == IpDadStatePreferred
                        && socket_ip(address.Address.lpSockaddr, address.Address.iSockaddrLength)
                            == Some(local.ip())
                    {
                        has_local = true;
                    }
                    u = address.Next;
                }
                if has_local {
                    if matched.is_some() {
                        return None;
                    }
                    let mut row = MIB_IF_ROW2::default();
                    row.InterfaceLuid = adapter.Luid;
                    if GetIfEntry2(&mut row) != ERROR_SUCCESS {
                        return None;
                    }
                    let flags = row.InterfaceAndOperStatusFlags._bitfield;
                    let physical = (flags & 0x01 != 0)
                        && (flags & 0xfa == 0)
                        && row.MediaConnectState == MediaConnectStateConnected;
                    let physical_lan = physical
                        && adapter.TunnelType == TUNNEL_TYPE_NONE
                        && match adapter.IfType {
                            IF_TYPE_IEEE80211 => {
                                row.PhysicalMediumType == NdisPhysicalMediumNative802_11
                                    || row.PhysicalMediumType == NdisPhysicalMediumWirelessLan
                            }
                            IF_TYPE_ETHERNET_CSMACD => {
                                row.PhysicalMediumType == NdisPhysicalMedium802_3
                            }
                            _ => false,
                        };
                    let local_scope_valid = match local {
                        SocketAddr::V6(v6) if (v6.ip().segments()[0] & 0xffc0) == 0xfe80 => {
                            v6.scope_id() != 0 && v6.scope_id() == adapter.Ipv6IfIndex
                        }
                        _ => true,
                    };
                    matched = Some((
                        adapter.Luid,
                        physical_lan && local_scope_valid,
                        adapter.OperStatus == IfOperStatusUp,
                    ));
                }
                cur = adapter.Next;
            }
            let (luid, physical_lan, up) = matched?;
            let (peer_ip, route_matches, on_link) = if let Some(peer) = peer {
                let source = sock(local);
                let destination = sock(peer);
                let mut route = MIB_IPFORWARD_ROW2::default();
                let mut chosen = SOCKADDR_INET::default();
                if GetBestRoute2(
                    None,
                    0,
                    Some(&source),
                    &destination,
                    0,
                    &mut route,
                    &mut chosen,
                ) != ERROR_SUCCESS
                {
                    return None;
                }
                let valid_scope = [local, peer].iter().all(|a| match a {
                    SocketAddr::V6(v6) if (v6.ip().segments()[0] & 0xffc0) == 0xfe80 => {
                        v6.scope_id() == route.InterfaceIndex && v6.scope_id() != 0
                    }
                    _ => true,
                });
                (
                    peer.ip(),
                    valid_scope
                        && route.InterfaceLuid.Value == luid.Value
                        && inet_ip(&chosen) == Some(local.ip()),
                    inet_ip(&route.NextHop)?.is_unspecified(),
                )
            } else {
                (local.ip(), false, false)
            };
            Some(Snapshot {
                local_address: local.ip(),
                peer_address: peer_ip,
                physical_lan,
                interface_up: up,
                route_matches,
                route_on_link: on_link,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> (Policy, Snapshot) {
        let local = "192.168.3.10".parse().unwrap();
        let peer = "192.168.3.20".parse().unwrap();
        (
            Policy {
                local_address: local,
            },
            Snapshot {
                local_address: local,
                peer_address: peer,
                physical_lan: true,
                interface_up: true,
                route_matches: true,
                route_on_link: true,
            },
        )
    }
    #[test]
    fn any_on_link_peer_on_a_physical_lan_can_reach_authentication() {
        let (p, mut s) = sample();
        assert_eq!(admit(None, &s), Err(Denied::MissingPolicy));
        assert_eq!(admit(Some(&p), &s), Ok(()));
        s.peer_address = "192.168.3.21".parse().unwrap();
        assert_eq!(admit(Some(&p), &s), Ok(()));
        s.route_on_link = false;
        assert_eq!(admit(Some(&p), &s), Err(Denied::NotApproved));
    }
    #[test]
    fn rejects_virtual_offline_and_routed_paths() {
        let (p, s) = sample();
        for v in 0..4 {
            let mut x = s.clone();
            match v {
                0 => x.physical_lan = false,
                1 => x.interface_up = false,
                2 => x.route_matches = false,
                _ => x.route_on_link = false,
            };
            assert_eq!(admit(Some(&p), &x), Err(Denied::NotApproved));
        }
        assert_eq!(admit_binding(Some(&p), &s), Ok(()));
    }
    #[test]
    fn rejects_invalid_policy_and_non_unicast_or_self_peers() {
        let (mut p, mut s) = sample();
        p.local_address = "0.0.0.0".parse().unwrap();
        assert_eq!(admit(Some(&p), &s), Err(Denied::InvalidPolicy));
        p.local_address = s.local_address;
        for addr in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "192.168.3.10",
            "::ffff:192.168.3.20",
        ] {
            s.peer_address = addr.parse().unwrap();
            assert_eq!(admit(Some(&p), &s), Err(Denied::NotApproved));
        }
    }
    #[test]
    fn ipv6_peer_must_be_unicast_on_matching_route() {
        let (mut p, mut s) = sample();
        p.local_address = "fd00::10".parse().unwrap();
        s.local_address = p.local_address;
        s.peer_address = "fd00::20".parse().unwrap();
        assert_eq!(admit(Some(&p), &s), Ok(()));
        s.peer_address = "fd00::21".parse().unwrap();
        assert_eq!(admit(Some(&p), &s), Ok(()));
        s.route_matches = false;
        assert_eq!(admit(Some(&p), &s), Err(Denied::NotApproved));
    }
    #[cfg(all(target_os = "macos", not(feature = "hoen-mac-dev")))]
    #[test]
    fn mac_production_admission_remains_closed_pending_live_validation() {
        let (policy, _) = sample();
        let local = SocketAddr::new(policy.local_address, 1234);
        let peer: SocketAddr = "192.168.3.20:1234".parse().unwrap();
        assert_eq!(
            verify_binding(Some(&policy), local),
            Err(Denied::SnapshotUnavailable)
        );
        assert_eq!(
            admit_socket(Some(&policy), local, peer),
            Err(Denied::SnapshotUnavailable)
        );
    }
}
