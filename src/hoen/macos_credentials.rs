//! Keychain storage for an interactive macOS user. Network admission and the signed application
//! enrollment lifecycle still need validation before mailbox hosting can be enabled.
use super::{CredentialStore, Purpose, Secret, StoreError};
use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};

#[cfg(not(feature = "hoen-mac-dev"))]
const SERVICE: &str = "com.hoensolutions.remote.enrollment.v1";
#[cfg(feature = "hoen-mac-dev")]
const SERVICE: &str = "com.hoensolutions.remote.development.enrollment.v1";
const ITEM_NOT_FOUND: i32 = -25300;
const DUPLICATE_ITEM: i32 = -25299;

/// Separate entries for host and viewer. Keychain ACLs identify the executable, not its role:
/// these names alone do not isolate two processes running as the same user and executable.
pub(crate) struct MacStore {
    keychain: SecKeychain,
    purpose: Purpose,
}

impl MacStore {
    /// Use the interactive user's default keychain, never the system daemon's keychain.
    pub(crate) fn for_user(purpose: Purpose) -> Result<Self, StoreError> {
        extern "C" {
            fn geteuid() -> u32;
        }
        if unsafe { geteuid() } == 0 {
            return Err(StoreError::WrongIdentity);
        }
        let keychain = SecKeychain::default_for_domain(SecPreferencesDomain::User)
            .map_err(|_| StoreError::Unavailable)?;
        Ok(Self { keychain, purpose })
    }

    fn account(&self) -> &'static str {
        match self.purpose {
            Purpose::Viewer => "viewer",
            Purpose::HostService => "host",
        }
    }

    /// Provision only an absent identity; never replace an existing signing key.
    pub(crate) fn write_new(&self, secret: &Secret) -> Result<(), StoreError> {
        self.keychain
            .add_generic_password(SERVICE, self.account(), secret.expose())
            .map(|_| ())
            .map_err(|error| if error.code() == DUPLICATE_ITEM {
                StoreError::AlreadyExists
            } else {
                StoreError::Unavailable
            })
    }
}

impl CredentialStore for MacStore {
    fn read(&self) -> Result<Secret, StoreError> {
        let (value, _) = self
            .keychain
            .find_generic_password(SERVICE, self.account())
            .map_err(|_| StoreError::Unavailable)?;
        Secret::new(value.as_ref().to_vec()).map_err(|_| StoreError::CorruptOrWrongPurpose)
    }

    fn write(&self, secret: &Secret) -> Result<(), StoreError> {
        match self.keychain.find_generic_password(SERVICE, self.account()) {
            Ok((_, mut item)) => item.set_password(secret.expose()),
            Err(error) if error.code() == ITEM_NOT_FOUND => {
                self.keychain
                    .add_generic_password(SERVICE, self.account(), secret.expose())
            }
            Err(_) => return Err(StoreError::Unavailable),
        }
        .map_err(|_| StoreError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use security_framework::os::macos::keychain::CreateOptions;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn isolated_keychain_round_trip_and_roles() {
        let _interaction = SecKeychain::disable_user_interaction().expect("disable prompts");
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hoen-keychain-test-{}-{unique}",
            std::process::id()
        ));
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
                let _ = std::fs::remove_file(self.0.with_extension("keychain-db"));
            }
        }
        let _cleanup = Cleanup(path.clone());
        let keychain = CreateOptions::new()
            .password("test-only-password")
            .create(&path)
            .expect("create isolated test keychain");
        let host = MacStore {
            keychain: keychain.clone(),
            purpose: Purpose::HostService,
        };
        let viewer = MacStore {
            keychain,
            purpose: Purpose::Viewer,
        };
        let first = Secret::new(b"test-host".to_vec()).unwrap();
        let next = Secret::new(b"test-host-updated".to_vec()).unwrap();
        let other = Secret::new(b"test-viewer".to_vec()).unwrap();
        host.write(&first).expect("write host");
        viewer.write(&other).expect("write viewer");
        host.write(&next).expect("replace host");
        assert_eq!(host.read().unwrap().expose(), b"test-host-updated");
        assert_eq!(viewer.read().unwrap().expose(), b"test-viewer");
        assert!(matches!(viewer.write_new(&first), Err(StoreError::AlreadyExists)));
        assert_eq!(viewer.read().unwrap().expose(), b"test-viewer");
    }
}
