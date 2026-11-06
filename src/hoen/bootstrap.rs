//! Select the fixed Hoen namespace before Windows configuration and IPC are touched.
use hbb_common::config;
use std::sync::OnceLock;

const NAME: &str = "Remote Desktop Client";
pub(crate) const SERVICE_NAME: &str = "RemoteDesktopService";
static SELECTED: OnceLock<bool> = OnceLock::new();

fn select(current: &str) -> Option<&'static str> {
    match current {
        "RustDesk" | NAME => Some(NAME),
        _ => None,
    }
}

/// Idempotent; reject a pre-existing or later conflicting app name.
pub(crate) fn initialize() -> bool {
    let selected = *SELECTED.get_or_init(|| {
        let Ok(mut name) = config::APP_NAME.write() else {
            return false;
        };
        let Some(value) = select(&name) else {
            return false;
        };
        *name = value.to_owned();
        true
    });
    selected && config::APP_NAME.read().map_or(false, |name| *name == NAME)
}

/// Stock Windows installer and update commands remain disabled until the Hoen installer exists.
pub(crate) fn blocked_command(command: &str) -> bool {
    matches!(
        command,
        "--install"
            | "--silent-install"
            | "--uninstall"
            | "--update"
            | "--after-install"
            | "--before-uninstall"
            | "--uninstall-cert"
            | "--install-idd"
            | "--uninstall-amyuni-idd"
            | "--install-remote-printer"
            | "--uninstall-remote-printer"
            | "--install-service"
            | "--uninstall-service"
            | "--service-control"
            | "--import-config"
            | "--remove"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn namespace_is_fixed_and_rejects_prior_custom_names() {
        assert_eq!(select("RustDesk"), Some("Remote Desktop Client"));
        assert_eq!(select("Remote Desktop Client"), Some("Remote Desktop Client"));
        assert_eq!(select("OtherProduct"), None);
    }
    #[test]
    fn blocks_stock_install_and_update_but_allows_enrollment_and_runtime() {
        for cmd in [
            "--install",
            "--uninstall",
            "--service-control",
            "--update",
            "--import-config",
        ] {
            assert!(blocked_command(cmd));
        }
        for cmd in [
            "--hoen-import-viewer",
            "--hoen-import-host",
            "--server",
            "--version",
        ] {
            assert!(!blocked_command(cmd));
        }
    }
}
