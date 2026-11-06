use super::{
    credentials::{CredentialStore, Purpose},
    history_worker::HistoryWorker,
    mailbox_worker::MailboxWorker,
    network,
    network_monitor::NetworkMonitor,
};
use hbb_common::{
    anyhow::{anyhow, bail},
    sodiumoxide::crypto::sign,
    tokio::{sync::OnceCell, task::spawn_blocking},
    ResultType,
};
use hoen_mailbox_auth::mailbox::{AccessToken, Endpoint, Fingerprint, Identity, Registration};
use hoen_mailbox_history::delivery::ApiToken;
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

pub(crate) struct Runtime {
    pub identity: Identity,
    pub mailbox: MailboxWorker,
    pub signing_key: sign::SecretKey,
    pub policy: network::Policy,
    pub listen_port: u16,
    pub history: Option<HistoryWorker>,
    pub monitor: Arc<NetworkMonitor>,
    registration: Registration,
}

impl Runtime {
    /// Called by the host only after the configured listener has successfully bound.
    pub async fn register_host(&self) -> ResultType<()> {
        if self.history.is_none() {
            bail!("viewer runtime cannot enable hosting");
        }
        let mut registration = self.registration.clone();
        registration.hosting_enabled = true;
        self.mailbox.register(registration).await?;
        Ok(())
    }
}

#[derive(serde_derive::Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    schema_version: u32,
    identity: String,
    display_name: String,
    mailbox_url: String,
    mailbox_ca_pem: String,
    access_token: String,
    signing_seed: [u8; 32],
    #[serde(default, rename = "adapter_id")]
    _legacy_adapter_id: Option<String>,
    #[serde(default, rename = "network_id")]
    _legacy_network_id: Option<String>,
    local_address: IpAddr,
    listen_port: u16,
    hosting_enabled: bool,
}
impl Drop for Enrollment {
    fn drop(&mut self) {
        // These fields are never logged or serialized back to ordinary files.
        unsafe {
            for byte in self.access_token.as_bytes_mut() {
                std::ptr::write_volatile(byte, 0);
            }
        }
        for byte in &mut self.signing_seed {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

fn parse(secret: &[u8]) -> ResultType<Enrollment> {
    let value: Enrollment = serde_json::from_slice(secret)
        .map_err(|_| anyhow!("invalid protected mailbox enrollment"))?;
    if value.schema_version != 1
        || value.listen_port == 0
        || value.display_name.is_empty()
        || value.display_name.len() > 128
        || value.display_name.trim() != value.display_name
        || value.display_name.chars().any(char::is_control)
        || value.signing_seed.iter().all(|byte| *byte == 0)
    {
        bail!("unsupported or incomplete mailbox enrollment");
    }
    Identity::new(&value.identity)?;
    AccessToken::from_encoded(&value.access_token)?;
    Endpoint::new(value.local_address, value.listen_port)?;
    let url =
        url::Url::parse(&value.mailbox_url).map_err(|_| anyhow!("invalid mailbox endpoint"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || value.mailbox_ca_pem.is_empty()
    {
        bail!("invalid mailbox endpoint or trust configuration");
    }
    Ok(value)
}

#[cfg(windows)]
fn directory(purpose: Purpose) -> ResultType<PathBuf> {
    let (variable, role) = match purpose {
        Purpose::Viewer => ("LOCALAPPDATA", "viewer"),
        Purpose::HostService => ("ProgramData", "host"),
    };
    let base =
        std::env::var_os(variable).ok_or_else(|| anyhow!("enrollment directory unavailable"))?;
    Ok(PathBuf::from(base).join("HoenRemote").join(role))
}

#[cfg(windows)]
fn load(purpose: Purpose) -> ResultType<(Enrollment, PathBuf)> {
    use super::credentials::{validate_inheritable_directory, ProtectedStore};
    let directory = directory(purpose)?;
    let store = ProtectedStore::open(&directory, purpose).map_err(|_| {
        anyhow!("mailbox enrollment is missing or not protected for this Windows identity")
    })?;
    let secret = store
        .read()
        .map_err(|_| anyhow!("mailbox enrollment cannot be decrypted by this Windows identity"))?;
    let enrollment = parse(secret.expose())?;
    let history = directory.join("history");
    if purpose == Purpose::HostService {
        validate_inheritable_directory(&history, purpose)
            .map_err(|_| anyhow!("history directory is not protected for the host service"))?;
    }
    Ok((enrollment, history.join("outbox.sqlite")))
}

/// Explicit installer/bootstrap entry point. The bundle never travels in argv,
/// ordinary configuration files or logs, and is sealed before any registration.
#[cfg(windows)]
pub(crate) fn import_enrollment(
    purpose: Purpose,
    secret: &super::credentials::Secret,
) -> ResultType<()> {
    use super::credentials::{provision_directory, ProtectedStore};
    let _validated = parse(secret.expose())?;
    let directory = directory(purpose)?;
    let parent = directory
        .parent()
        .ok_or_else(|| anyhow!("invalid enrollment path"))?;
    provision_directory(parent, purpose)
        .map_err(|_| anyhow!("cannot provision protected application directory"))?;
    provision_directory(&directory, purpose)
        .map_err(|_| anyhow!("cannot provision protected enrollment directory"))?;
    if purpose == Purpose::HostService {
        provision_directory(&directory.join("history"), purpose)
            .map_err(|_| anyhow!("cannot provision protected history directory"))?;
    }
    ProtectedStore::open(&directory, purpose)
        .and_then(|store| store.write(secret))
        .map_err(|_| anyhow!("cannot save enrollment for this Windows identity"))
}
#[cfg(not(windows))]
fn load(_: Purpose) -> ResultType<(Enrollment, PathBuf)> {
    bail!("protected mailbox enrollment is not implemented on this platform");
}

async fn initialize(purpose: Purpose) -> ResultType<Arc<Runtime>> {
    let (enrollment, history_path) = spawn_blocking(move || load(purpose)).await??;
    if purpose == Purpose::HostService && !enrollment.hosting_enabled {
        bail!("mailbox hosting is disabled");
    }
    let policy = network::Policy {
        local_address: enrollment.local_address,
    };
    let check_policy = policy.clone();
    let monitor = Arc::new(
        NetworkMonitor::start()
            .await
            .map_err(|_| anyhow!("network monitoring unavailable"))?,
    );
    let captured = monitor.state();
    let address = SocketAddr::new(policy.local_address, enrollment.listen_port);
    spawn_blocking(move || network::verify_binding(Some(&check_policy), address))
        .await?
        .map_err(|_| anyhow!("the configured bind address is not available"))?;
    if !monitor.is_current(captured) {
        bail!("network changed during enrollment validation");
    }
    let mailbox = MailboxWorker::start(
        enrollment.mailbox_url.clone(),
        enrollment.mailbox_ca_pem.as_bytes().to_vec(),
        AccessToken::from_encoded(&enrollment.access_token)?,
    )
    .await?;
    let identity = Identity::new(&enrollment.identity)?;
    let (public, signing_key) = sign::keypair_from_seed(&sign::Seed(enrollment.signing_seed));
    let fingerprint = Fingerprint::from_bytes(Sha256::digest(public.0).into());
    let history = if purpose == Purpose::HostService {
        let token = ApiToken::new(enrollment.access_token.clone())?;
        Some(
            HistoryWorker::start(
                history_path,
                4096,
                enrollment.mailbox_url.clone(),
                enrollment.mailbox_ca_pem.as_bytes().to_vec(),
                move || Ok(token),
            )
            .await?,
        )
    } else {
        None
    };
    let existing = mailbox
        .list()
        .await?
        .into_iter()
        .find(|m| m.identity == identity);
    if existing
        .as_ref()
        .map_or(false, |m| m.public_key_fingerprint != fingerprint)
    {
        bail!("enrolled device key does not match the mailbox registration");
    }
    let registration = Registration {
        identity: identity.clone(),
        display_name: enrollment.display_name.clone(),
        endpoint: Endpoint::new(enrollment.local_address, enrollment.listen_port)?,
        hosting_enabled: false,
        public_key_fingerprint: fingerprint,
    };
    // Viewer startup must never disable an existing host. A new host advertises
    // eligibility only after binding; the registry flag is not a liveness lease.
    if existing.is_none() {
        mailbox.register(registration.clone()).await?;
    }
    Ok(Arc::new(Runtime {
        identity,
        mailbox,
        signing_key,
        policy,
        listen_port: enrollment.listen_port,
        history,
        registration,
        monitor,
    }))
}

static VIEWER: OnceCell<Arc<Runtime>> = OnceCell::const_new();
static HOST: OnceCell<Arc<Runtime>> = OnceCell::const_new();

pub(crate) async fn viewer() -> ResultType<Arc<Runtime>> {
    Ok(VIEWER
        .get_or_try_init(|| initialize(Purpose::Viewer))
        .await?
        .clone())
}
pub(crate) async fn host() -> ResultType<Arc<Runtime>> {
    Ok(HOST
        .get_or_try_init(|| initialize(Purpose::HostService))
        .await?
        .clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1, "identity": "test-viewer", "display_name": "Test viewer",
            "mailbox_url": "https://192.168.1.2:42819/", "mailbox_ca_pem": "synthetic certificate",
            "access_token": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "signing_seed": vec![7u8; 32],
            "local_address": "192.168.1.3", "listen_port": 42830, "hosting_enabled": false
        })
    }
    #[test]
    fn enrollment_is_versioned_and_rejects_incomplete_or_untrusted_inputs() {
        let valid = fixture();
        assert!(parse(&serde_json::to_vec(&valid).unwrap()).is_ok());
        for (key, replacement) in [
            ("schema_version", serde_json::json!(2)),
            ("access_token", serde_json::json!("invalid")),
            ("mailbox_url", serde_json::json!("http://192.168.1.2/")),
            ("local_address", serde_json::json!("0.0.0.0")),
            ("listen_port", serde_json::json!(0)),
        ] {
            let mut bad = valid.clone();
            bad[key] = replacement;
            assert!(parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        let mut legacy = valid.clone();
        legacy["adapter_id"] = serde_json::json!("previous-network-id");
        legacy["network_id"] = serde_json::json!("previous-network-id");
        assert!(parse(&serde_json::to_vec(&legacy).unwrap()).is_ok());
        let mut unknown = valid;
        unknown["disable_authentication"] = serde_json::json!(true);
        assert!(parse(&serde_json::to_vec(&unknown).unwrap()).is_err());
    }
}
