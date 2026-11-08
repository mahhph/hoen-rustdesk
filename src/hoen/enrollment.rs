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
    #[cfg(windows)]
    if command.as_deref() == Some("--hoen-machine-config-preflight") {
        return Some((|| {
            if args.next().is_some() { bail!("machine configuration preflight takes no arguments"); }
            println!("{}", super::runtime::migration::preflight_host()?);
            Ok(())
        })());
    }
    #[cfg(target_os = "macos")]
    if command.as_deref() == Some("--hoen-host-permissions") {
        return Some((|| {
            if args.next().is_some() {
                bail!("host permission check takes no arguments");
            }
            let screen = crate::platform::macos::is_can_screen_recording(false);
            let accessibility = crate::platform::macos::is_process_trusted(false);
            println!("{}", host_permission_report(screen, accessibility));
            if !screen || !accessibility {
                bail!("Mac host permissions are incomplete");
            }
            Ok(())
        })());
    }
    #[cfg(target_os = "macos")]
    if command.as_deref() == Some("--hoen-provision-host-from-viewer") {
        return Some((|| {
            if args.next().is_some() {
                bail!("host provisioning takes no arguments");
            }
            super::runtime::provision_host_from_viewer()
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

#[cfg(target_os = "macos")]
fn host_permission_report(screen: bool, accessibility: bool) -> String {
    let state = |granted| if granted { "granted" } else { "not granted" };
    format!("Screen Recording: {}\nAccessibility: {}", state(screen), state(accessibility))
}

#[cfg(all(test, target_os = "macos"))]
mod mac_permission_tests {
    use super::host_permission_report;

    #[test]
    fn report_names_each_permission_and_its_actual_state() {
        assert_eq!(host_permission_report(true, false),
            "Screen Recording: granted\nAccessibility: not granted");
        assert_eq!(host_permission_report(false, true),
            "Screen Recording: not granted\nAccessibility: granted");
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
pub(crate) fn command() -> Option<ResultType<()>> {
    None
}
