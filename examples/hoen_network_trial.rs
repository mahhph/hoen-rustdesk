//! Opt-in read-only trial of the real Windows snapshot and notification APIs.
//! This example opens no listener or desktop session and changes no network state.
#[cfg(all(windows, feature = "hoen-mailbox"))]
#[path = "../src/hoen/network.rs"]
mod network;
#[cfg(all(windows, feature = "hoen-mailbox"))]
#[path = "../src/hoen/network_monitor.rs"]
mod network_monitor;

#[cfg(all(windows, feature = "hoen-mailbox"))]
use hbb_common::tokio;
#[cfg(all(windows, feature = "hoen-mailbox"))]
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

#[cfg(all(windows, feature = "hoen-mailbox"))]
fn guid(value: &str) -> Result<u128, &'static str> {
    let value = value
        .trim_matches(|c| c == '{' || c == '}')
        .replace('-', "");
    if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("GUID must be 32 hexadecimal digits");
    }
    let id = u128::from_str_radix(&value, 16).map_err(|_| "invalid GUID")?;
    if id == 0 {
        return Err("GUID must not be zero");
    }
    Ok(id)
}

#[cfg(all(windows, feature = "hoen-mailbox"))]
#[tokio::main]
async fn main() {
    if let Err(error) = trial().await {
        eprintln!("Trial did not pass: {error}");
        std::process::exit(1);
    }
}
#[cfg(all(windows, feature = "hoen-mailbox"))]
async fn trial() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if !(args.len() == 5 || args.len() == 6) {
        return Err("usage: hoen_network_trial <approved-adapter-guid> <approved-network-guid> <local-ip> <wait-seconds:1..300> [peer-ip]".into());
    }
    let adapter_id = guid(&args[1])?;
    let network_id = guid(&args[2])?;
    let local_address: IpAddr = args[3].parse()?;
    let seconds: u64 = args[4].parse()?;
    if !(1..=300).contains(&seconds) {
        return Err("wait-seconds must be 1..300".into());
    }
    let peer = args.get(5).map(|v| v.parse::<IpAddr>()).transpose()?;
    let policy = network::Policy {
        adapter_id,
        network_id,
        local_address,
    };
    let monitor = network_monitor::NetworkMonitor::start()
        .await
        .map_err(|_| "Windows network notifications unavailable")?;
    let mut events = monitor.subscribe();
    let captured = monitor.state();
    if captured.closed {
        return Err("network monitor is closed".into());
    }
    // Take snapshots off the async thread, as in the application. The APIs make
    // their own dedicated COM-thread query and do not alter the network.
    let local = SocketAddr::new(local_address, 0);
    let approved = policy.clone();
    let result =
        tokio::task::spawn_blocking(move || network::verify_binding(Some(&approved), local))
            .await?;
    if result.is_err() || !monitor.is_current(captured) {
        return Err(format!(
            "approved policy was not verified or changed during snapshot: {result:?}"
        )
        .into());
    }
    println!(
        "PASS: explicit adapter/network/local-address policy matches a live private Wi-Fi binding."
    );
    let mut bad = policy.clone();
    bad.adapter_id = if bad.adapter_id == 1 {
        2
    } else {
        bad.adapter_id ^ 1
    };
    let rejected =
        tokio::task::spawn_blocking(move || network::verify_binding(Some(&bad), local)).await?;
    if !matches!(rejected, Err(network::Denied::NotApproved)) || !monitor.is_current(captured) {
        return Err(format!("negative policy check was inconclusive: {rejected:?}").into());
    }
    println!("PASS: a different adapter identifier was rejected by the real snapshot.");
    if let Some(peer) = peer {
        let approved = policy.clone();
        let destination = SocketAddr::new(peer, 1);
        let route = tokio::task::spawn_blocking(move || {
            network::admit_socket(Some(&approved), local, destination)
        })
        .await?;
        if !monitor.is_current(captured) {
            return Err("network changed during peer route query".into());
        }
        match route {
            Ok(()) => println!("PASS: supplied peer is on the approved interface and on-link according to the route snapshot."),
            Err(reason) => println!("Peer route was not admitted: {reason:?}. No connection was attempted."),
        }
    } else {
        println!("Peer route was not tested; no peer address was supplied.");
    }
    println!("Waiting up to {seconds}s for a real OS network notification; no change will be requested or made.");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    loop {
        if monitor.state().closed {
            return Err("network monitor closed unexpectedly".into());
        }
        if !monitor.is_current(captured) {
            println!("OBSERVED: OS notification invalidated the captured network state.");
            break;
        }
        match tokio::time::timeout_at(deadline, events.changed()).await {
            // An unseen notification may predate the captured generation; in
            // that case keep waiting rather than claiming a new transition.
            Ok(Ok(())) => continue,
            Ok(Err(_)) => return Err("network notification channel closed".into()),
            Err(_) => {
                if monitor.state().closed {
                    return Err("network monitor closed unexpectedly".into());
                }
                if monitor.is_current(captured) {
                    println!("NOT OBSERVED: no network invalidation occurred during the wait.");
                } else {
                    println!("OBSERVED: captured state was invalidated during the wait.");
                }
                break;
            }
        }
    }
    monitor
        .shutdown()
        .await
        .map_err(|_| "network monitor teardown failed")?;
    println!(
        "No listener, authenticated peer, or desktop session was exercised; no network change was initiated."
    );
    Ok(())
}
#[cfg(not(all(windows, feature = "hoen-mailbox")))]
fn main() {
    eprintln!("This trial requires Windows and --features hoen-mailbox.");
    std::process::exit(2);
}
