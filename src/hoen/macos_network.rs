//! macOS Wi-Fi and route snapshots. An observation is never an approval; its opaque IDs must
//! match an enrollment approved separately. SSID/BSSID are not cryptographic authentication.
use hbb_common::{
    anyhow::{anyhow, bail},
    ResultType,
};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Debug)]
pub(super) struct Observation {
    pub adapter_id: u128,
    pub network_id: u128,
    pub address: Ipv4Addr,
    interface: String,
}

fn command(program: &str, args: &[&str]) -> ResultType<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("network query timed out");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if !status.success() {
        bail!("network query unavailable");
    }
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("network query unavailable"))?
        .take(8193)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        bail!("network query output too large");
    }
    String::from_utf8(bytes).map_err(|_| anyhow!("invalid network query output"))
}

fn route_info(output: &str) -> ResultType<(String, Vec<String>)> {
    let mut interface = None;
    let mut flags = None;
    for line in output.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("interface:") {
            let value = value.trim();
            if interface.is_some()
                || value.is_empty()
                || !value.bytes().all(|b| b.is_ascii_alphanumeric())
            {
                bail!("invalid route interface");
            }
            interface = Some(value.to_owned());
        }
        if let Some(value) = line.strip_prefix("flags:") {
            let value = value
                .trim()
                .strip_prefix('<')
                .and_then(|v| v.strip_suffix('>'))
                .ok_or_else(|| anyhow!("invalid route flags"))?;
            if flags.is_some() {
                bail!("duplicate route flags");
            }
            flags = Some(value.split(',').map(str::to_owned).collect::<Vec<_>>());
        }
    }
    let interface = interface.ok_or_else(|| anyhow!("route interface missing"))?;
    let flags = flags.ok_or_else(|| anyhow!("route flags missing"))?;
    if !flags.iter().any(|f| f == "UP") || flags.iter().any(|f| f == "REJECT" || f == "BLACKHOLE") {
        bail!("route unavailable");
    }
    Ok((interface, flags))
}

fn identifier(domain: &[u8], fields: &[&[u8]]) -> u128 {
    let mut hash = Sha256::new();
    hash.update(domain);
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    let result = hash.finalize();
    let mut short = [0u8; 16];
    short.copy_from_slice(&result[..16]);
    u128::from_be_bytes(short)
}
fn normalize_bssid(value: &str) -> ResultType<[u8; 6]> {
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 6 {
        bail!("Wi-Fi identity unavailable");
    }
    let mut bytes = [0u8; 6];
    for (out, part) in bytes.iter_mut().zip(parts) {
        if part.is_empty() || part.len() > 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("Wi-Fi identity unavailable");
        }
        *out = u8::from_str_radix(part, 16).map_err(|_| anyhow!("Wi-Fi identity unavailable"))?;
    }
    if bytes == [0; 6] || bytes[0] & 1 != 0 {
        bail!("Wi-Fi identity unavailable");
    }
    Ok(bytes)
}

#[link(name = "CoreWLAN", kind = "framework")]
extern "C" {}
#[link(name = "CoreLocation", kind = "framework")]
extern "C" {}

/// Called only by the explicit setup command, on the app's main thread. It requests permission
/// but never requests or records location coordinates.
pub(super) fn request_wifi_access() -> ResultType<()> {
    use cocoa::base::{id, nil, BOOL, YES};
    use core_foundation::runloop::{kCFRunLoopDefaultMode, CFRunLoopRunInMode};
    use objc::{msg_send, runtime::Class, sel, sel_impl};
    unsafe {
        let thread = Class::get("NSThread").ok_or_else(|| anyhow!("main thread unavailable"))?;
        let main: BOOL = msg_send![thread, isMainThread];
        if main != YES {
            bail!("Wi-Fi setup must run on the app's main thread");
        }
        let app_class =
            Class::get("NSApplication").ok_or_else(|| anyhow!("application unavailable"))?;
        let app: id = msg_send![app_class, sharedApplication];
        if app == nil {
            bail!("application unavailable");
        }
        let _: () = msg_send![app, activateIgnoringOtherApps: YES];
        let manager_class = Class::get("CLLocationManager")
            .ok_or_else(|| anyhow!("Location Services unavailable"))?;
        let allocated: id = msg_send![manager_class, alloc];
        let manager: id = msg_send![allocated, init];
        if manager == nil {
            bail!("Location Services unavailable");
        }
        let result = (|| {
            let mut status: i32 = msg_send![manager, authorizationStatus];
            if status == 0 {
                let _: () = msg_send![manager, requestAlwaysAuthorization];
                let deadline = Instant::now() + Duration::from_secs(60);
                while status == 0 && Instant::now() < deadline {
                    if matches!(CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.1, 1), 1 | 2) {
                        bail!("Wi-Fi permission prompt unavailable");
                    }
                    status = msg_send![manager, authorizationStatus];
                }
            }
            if status != 3 && status != 4 {
                bail!("Wi-Fi access was not authorized");
            }
            Ok(())
        })();
        let _: () = msg_send![manager, release];
        result
    }
}
fn wifi(interface: &str) -> ResultType<(Vec<u8>, [u8; 6])> {
    use cocoa::{
        base::{id, nil, BOOL, YES},
        foundation::{NSAutoreleasePool, NSString},
    };
    use objc::{msg_send, runtime::Class, sel, sel_impl};
    use std::ffi::CStr;
    unsafe {
        let pool = NSAutoreleasePool::new(nil);
        let result = (|| {
            let class =
                Class::get("CWWiFiClient").ok_or_else(|| anyhow!("Wi-Fi service unavailable"))?;
            let client: id = msg_send![class, sharedWiFiClient];
            if client == nil {
                bail!("Wi-Fi service unavailable");
            }
            let name = NSString::alloc(nil).init_str(interface);
            let name: id = msg_send![name, autorelease];
            let wifi: id = msg_send![client, interfaceWithName: name];
            if wifi == nil {
                bail!("route is not on a Wi-Fi interface");
            }
            let active: BOOL = msg_send![wifi, serviceActive];
            let power: BOOL = msg_send![wifi, powerOn];
            let mode: isize = msg_send![wifi, interfaceMode];
            let security: isize = msg_send![wifi, security];
            // WPA2/3 only; missing or ambiguous security information fails closed.
            if active != YES
                || power != YES
                || mode != 1
                || !matches!(security, 4 | 9 | 11 | 12 | 13)
            {
                bail!("approved Wi-Fi unavailable");
            }
            let ssid: id = msg_send![wifi, ssidData];
            let bssid: id = msg_send![wifi, bssid];
            if ssid == nil || bssid == nil {
                bail!("Wi-Fi identity unavailable; location access may be required");
            }
            let length: usize = msg_send![ssid, length];
            let bytes: *const u8 = msg_send![ssid, bytes];
            if length == 0 || length > 32 || bytes.is_null() {
                bail!("Wi-Fi identity unavailable");
            }
            let ssid = std::slice::from_raw_parts(bytes, length).to_vec();
            let text: *const std::ffi::c_char = msg_send![bssid, UTF8String];
            if text.is_null() {
                bail!("Wi-Fi identity unavailable");
            }
            let bssid = CStr::from_ptr(text)
                .to_str()
                .map_err(|_| anyhow!("Wi-Fi identity unavailable"))?;
            Ok((ssid, normalize_bssid(bssid)?))
        })();
        let _: () = msg_send![pool, drain];
        result
    }
}

pub(super) fn observe() -> ResultType<Observation> {
    let (interface, _) = route_info(&command("/sbin/route", &["-n", "get", "default"])?)?;
    let (ssid, bssid) = wifi(&interface)?;
    let text = command("/usr/sbin/ipconfig", &["getifaddr", &interface])?;
    let address: Ipv4Addr = text
        .trim()
        .parse()
        .map_err(|_| anyhow!("Wi-Fi IPv4 address unavailable"))?;
    if !address.is_private() || address.is_loopback() || address.is_link_local() {
        bail!("private Wi-Fi address unavailable");
    }
    let adapter_id = identifier(b"hoen-macos-adapter-v1", &[interface.as_bytes()]);
    let network_id = identifier(b"hoen-macos-network-v1", &[&ssid, &bssid]);
    if adapter_id == 0 || network_id == 0 {
        bail!("Wi-Fi identity unavailable");
    }
    Ok(Observation {
        adapter_id,
        network_id,
        address,
        interface,
    })
}

pub(super) fn peer_on_link(observation: &Observation, peer: IpAddr) -> ResultType<bool> {
    let peer = match peer {
        IpAddr::V4(ip) if ip.is_private() && !ip.is_loopback() && !ip.is_link_local() => ip,
        _ => return Ok(false),
    };
    let (interface, flags) =
        route_info(&command("/sbin/route", &["-n", "get", &peer.to_string()])?)?;
    Ok(interface == observation.interface && !flags.iter().any(|flag| flag == "GATEWAY"))
}

/// Resolve the current address only after matching both identifiers from protected enrollment.
pub(super) fn approved_address(adapter_id: u128, network_id: u128) -> ResultType<Ipv4Addr> {
    let observation = observe()?;
    address_if_approved(adapter_id, network_id, &observation)
}

fn address_if_approved(
    adapter_id: u128,
    network_id: u128,
    observation: &Observation,
) -> ResultType<Ipv4Addr> {
    if adapter_id == 0
        || network_id == 0
        || observation.adapter_id != adapter_id
        || observation.network_id != network_id
    {
        bail!("approved Wi-Fi unavailable");
    }
    Ok(observation.address)
}

fn check_snapshot(
    policy: Option<&super::network::Policy>,
    observation: &Observation,
    local: SocketAddr,
    peer: Option<SocketAddr>,
    on_link: bool,
) -> Result<(), super::network::Denied> {
    use super::network::{self, Denied, Snapshot};
    let policy = policy.ok_or(Denied::MissingPolicy)?;
    if local.ip() != IpAddr::V4(observation.address) {
        return Err(Denied::NotApproved);
    }
    let snapshot = Snapshot {
        adapter_id: observation.adapter_id,
        network_id: observation.network_id,
        local_address: IpAddr::V4(observation.address),
        peer_address: peer.map_or(IpAddr::V4(observation.address), |p| p.ip()),
        wifi: true,
        interface_up: true,
        private_profile: true,
        route_matches: on_link,
        route_on_link: on_link,
    };
    if peer.is_some() {
        network::admit(Some(policy), &snapshot)
    } else {
        network::admit_binding(Some(policy), &snapshot)
    }
}

pub(super) fn verify_binding(
    policy: Option<&super::network::Policy>,
    local: SocketAddr,
) -> Result<(), super::network::Denied> {
    use super::network::Denied;
    let policy = policy.ok_or(Denied::MissingPolicy)?;
    let observation = observe().map_err(|_| Denied::SnapshotUnavailable)?;
    check_snapshot(Some(policy), &observation, local, None, false)
}

pub(super) fn admit_socket(
    policy: Option<&super::network::Policy>,
    local: SocketAddr,
    peer: SocketAddr,
) -> Result<(), super::network::Denied> {
    use super::network::Denied;
    let policy = policy.ok_or(Denied::MissingPolicy)?;
    let observation = observe().map_err(|_| Denied::SnapshotUnavailable)?;
    check_snapshot(Some(policy), &observation, local, None, false)?;
    let on_link = peer_on_link(&observation, peer.ip()).map_err(|_| Denied::SnapshotUnavailable)?;
    check_snapshot(Some(policy), &observation, local, Some(peer), on_link)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn core_wlan_class_is_available() {
        assert!(objc::runtime::Class::get("CWWiFiClient").is_some());
        assert!(objc::runtime::Class::get("CLLocationManager").is_some());
        assert!(wifi("hoen-nonexistent-interface").is_err());
        // Rust tests run off the application main thread; this must not show a prompt there.
        assert!(request_wifi_access().is_err());
    }
    #[test]
    fn route_parser_rejects_down_rejected_or_ambiguous_routes() {
        assert!(route_info("interface: en0\nflags: <UP,HOST,DONE>\n").is_ok());
        for output in [
            "interface: en0\nflags: <HOST>\n",
            "interface: en0\nflags: <UP,REJECT>\n",
            "interface: en0\ninterface: en1\nflags: <UP>\n",
        ] {
            assert!(route_info(output).is_err());
        }
    }
    #[test]
    fn network_identity_is_stable_and_distinguishes_networks() {
        let a = normalize_bssid("2:11:22:33:44:55").unwrap();
        assert_eq!(a, normalize_bssid("02:11:22:33:44:55").unwrap());
        assert!(normalize_bssid("ff:ff:ff:ff:ff:ff").is_err());
        assert_ne!(
            identifier(b"network", &[b"home", &a]),
            identifier(b"network", &[b"other", &a])
        );
        assert_ne!(
            identifier(b"network", &[b"ab", b"c"]),
            identifier(b"network", &[b"a", b"bc"])
        );
    }

    #[test]
    fn rejects_unapproved_network_or_routed_peer() {
        use super::super::network::Policy;
        let local: SocketAddr = "192.168.4.8:1234".parse().unwrap();
        let peer: SocketAddr = "192.168.4.9:1234".parse().unwrap();
        let observed = Observation {
            adapter_id: 1,
            network_id: 2,
            address: "192.168.4.8".parse().unwrap(),
            interface: "en0".into(),
        };
        let mut policy = Policy {
            adapter_id: 1,
            network_id: 2,
            local_address: local.ip(),
        };
        assert!(check_snapshot(Some(&policy), &observed, local, Some(peer), true).is_ok());
        assert!(check_snapshot(Some(&policy), &observed, local, Some(peer), false).is_err());
        policy.network_id = 3;
        assert!(check_snapshot(Some(&policy), &observed, local, Some(peer), true).is_err());
        assert!(check_snapshot(None, &observed, local, Some(peer), true).is_err());
        assert_eq!(
            address_if_approved(1, 2, &observed).unwrap(),
            observed.address
        );
        let after_reboot = Observation {
            address: "192.168.4.11".parse().unwrap(),
            ..observed
        };
        assert_eq!(
            address_if_approved(1, 2, &after_reboot).unwrap(),
            after_reboot.address
        );
        assert!(address_if_approved(1, 3, &after_reboot).is_err());
    }
}
