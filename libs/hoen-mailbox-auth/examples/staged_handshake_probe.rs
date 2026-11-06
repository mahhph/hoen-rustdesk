#[path = "../src/tls_pin.rs"]
mod tls_pin;
use hoen_mailbox_auth::mailbox::Fingerprint;
use std::{
    net::{IpAddr, SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};
fn handshake(root: &[u8], pin: [u8; 32], name: &str) -> Result<(), String> {
    let config = tls_pin::pinned_config(root, pin).map_err(|_| "invalid root".to_string())?;
    let ip: IpAddr = name.parse().map_err(|_| "invalid IP")?;
    let address: SocketAddr = "127.0.0.1:42831".parse().map_err(|_| "invalid endpoint")?;
    let mut tcp = TcpStream::connect_timeout(&address, Duration::from_secs(3))
        .map_err(|e| format!("connect: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let mut tls =
        rustls::ClientConnection::new(Arc::new(config), rustls::ServerName::IpAddress(ip))
            .map_err(|e| e.to_string())?;
    while tls.is_handshaking() {
        tls.complete_io(&mut tcp).map_err(|e| e.to_string())?;
    }
    tls.send_close_notify();
    let _ = tls.complete_io(&mut tcp);
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("supply candidate PEM and unrelated root PEM".into());
    }
    let root = std::fs::read(&args[1])?;
    let wrong = std::fs::read(&args[2])?;
    let pin =
        *Fingerprint::parse("7fe74d2d232d6ae1a3f3efd0a453a82655f5a52c3c103ed113341853b839995f")?
            .as_bytes();
    handshake(&root, pin, "127.0.0.1")?;
    println!("PASS correct sole root / expected IP / exact pin");
    for (label, pem, fp, ip, reason) in [
        (
            "wrong root",
            wrong.as_slice(),
            pin,
            "127.0.0.1",
            "UnknownIssuer",
        ),
        (
            "wrong expected IP",
            root.as_slice(),
            pin,
            "192.168.1.25",
            "NotValidForName",
        ),
        (
            "wrong exact pin",
            root.as_slice(),
            [0; 32],
            "127.0.0.1",
            "pin mismatch",
        ),
    ] {
        match handshake(pem, fp, ip) {
            Err(e) if e.contains(reason) => println!("PASS {label}: {e}"),
            other => return Err(format!("unexpected {label} result: {other:?}").into()),
        }
    }
    println!("No HTTP requests or credentials sent.");
    Ok(())
}
