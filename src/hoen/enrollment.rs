//! Explicit bootstrap commands. No credentials are accepted in command-line arguments.
use hbb_common::{
    anyhow::{anyhow, bail},
    ResultType,
};

#[cfg(any(windows, target_os = "macos"))]
pub(crate) fn command() -> Option<ResultType<()>> {
    use super::credentials::{Purpose, Secret, MAX_SECRET_BYTES};
    use std::io::Read;
    let mut args = std::env::args().skip(1);
    let command = args.next();
    #[cfg(target_os = "macos")]
    if command.as_deref() == Some("--hoen-request-wifi-access") {
        return Some((|| {
            if args.next().is_some() { bail!("Wi-Fi setup accepts no arguments"); }
            super::macos_network::request_wifi_access()
        })());
    }
    #[cfg(target_os = "macos")]
    if command.as_deref() == Some("--hoen-network-identifiers") {
        return Some((|| {
            if args.next().is_some() { bail!("network inspection accepts no arguments"); }
            let network = super::macos_network::observe()?;
            println!("adapter_id={:032x}\nnetwork_id={:032x}\nlocal_address={}", network.adapter_id, network.network_id, network.address);
            Ok(())
        })());
    }
    let purpose = match command.as_deref() {
        Some("--hoen-import-viewer") => Purpose::Viewer,
        Some("--hoen-import-host") => Purpose::HostService,
        _ => return None,
    };
    Some((|| {
        if args.next().is_some() {
            bail!("enrollment accepts input on stdin only");
        }
        let mut bytes = Vec::new();
        std::io::stdin()
            .take((MAX_SECRET_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow!("unable to read enrollment input"))?;
        let secret = Secret::new(bytes).map_err(|_| anyhow!("invalid enrollment input size"))?;
        super::runtime::import_enrollment(purpose, &secret)
    })())
}

#[cfg(not(any(windows, target_os = "macos")))]
pub(crate) fn command() -> Option<ResultType<()>> {
    None
}
