//! Select a separate Mac application namespace before configuration or IPC starts.
use hbb_common::config;
use std::sync::OnceLock;

#[cfg(feature = "hoen-mac-dev")]
const NAME: &str = "HoenRemoteDev";
#[cfg(not(feature = "hoen-mac-dev"))]
const NAME: &str = "HoenRemote";
static SELECTED: OnceLock<bool> = OnceLock::new();

fn select(current: &str) -> Option<&'static str> {
    if current == "RustDesk" || current == NAME {
        Some(NAME)
    } else {
        None
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uses_a_fixed_non_rustdesk_namespace() {
        assert_eq!(select("RustDesk"), Some(NAME));
        assert_eq!(select(NAME), Some(NAME));
        assert_ne!(NAME, "RustDesk");
        assert_eq!(select("unrelated-custom-client"), None);
    }
}
