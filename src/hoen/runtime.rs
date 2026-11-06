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
    /// Called by the host only after the approved listener has successfully bound.
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

#[derive(serde_derive::Serialize, serde_derive::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    schema_version: u32,
    identity: String,
    display_name: String,
    mailbox_url: String,
    mailbox_ca_pem: String,
    #[serde(default)]
    mailbox_leaf_fingerprint: Option<String>,
    access_token: String,
    signing_seed: [u8; 32],
    adapter_id: String,
    network_id: String,
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

// Exact machine-bootstrap schema; this is separate from the protected runtime format.
#[derive(serde_derive::Deserialize)]
#[serde(deny_unknown_fields)]
struct MachineBootstrap {
    schema_version: u32,
    client: BootstrapClient,
    config: BootstrapConfig,
}
#[derive(serde_derive::Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapClient {
    url: String,
    fingerprint: String,
    environment: String,
    token: String,
}
impl Drop for BootstrapClient {
    fn drop(&mut self) {
        unsafe { for byte in self.token.as_bytes_mut() { std::ptr::write_volatile(byte, 0); } }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
#[derive(serde_derive::Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapConfig {
    identity: String,
    display_name: String,
    mailbox_ca_pem: String,
    adapter_id: String,
    network_id: String,
    local_address: IpAddr,
    listen_port: u16,
}

fn bootstrap_certificate_fingerprint(pem: &str) -> ResultType<Fingerprint> {
    let text = pem.trim();
    let body = text.strip_prefix("-----BEGIN CERTIFICATE-----")
        .and_then(|v| v.strip_suffix("-----END CERTIFICATE-----"))
        .ok_or_else(|| anyhow!("invalid bootstrap certificate"))?;
    if !body.bytes().all(|b| b.is_ascii_whitespace() || b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=') {
        bail!("invalid bootstrap certificate");
    }
    let encoded: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let der = crate::decode64(encoded.as_bytes()).map_err(|_| anyhow!("invalid bootstrap certificate"))?;
    // Validate a single PEM certificate, then compare its exact DER fingerprint.
    reqwest::Certificate::from_pem(text.as_bytes()).map_err(|_| anyhow!("invalid bootstrap certificate"))?;
    Ok(Fingerprint::from_bytes(Sha256::digest(&der).into()))
}

fn transform_bootstrap(secret: &[u8], seed: [u8; 32]) -> ResultType<Enrollment> {
    let value: MachineBootstrap = serde_json::from_slice(secret)
        .map_err(|_| anyhow!("invalid protected machine bootstrap"))?;
    if value.schema_version != 1 || value.client.environment != "production" {
        bail!("unsupported machine bootstrap");
    }
    let pin = Fingerprint::parse(&value.client.fingerprint)?;
    if bootstrap_certificate_fingerprint(&value.config.mailbox_ca_pem)? != pin {
        bail!("bootstrap certificate does not match the existing mailbox pin");
    }
    let pin = pin.to_hex();
    let enrollment = Enrollment {
        schema_version: 1,
        identity: value.config.identity,
        display_name: value.config.display_name,
        mailbox_url: value.client.url.clone(),
        mailbox_ca_pem: value.config.mailbox_ca_pem,
        mailbox_leaf_fingerprint: Some(pin),
        access_token: value.client.token.clone(),
        signing_seed: seed,
        adapter_id: value.config.adapter_id,
        network_id: value.config.network_id,
        local_address: value.config.local_address,
        listen_port: value.config.listen_port,
        hosting_enabled: true,
    };
    let encoded = super::credentials::Secret::new(serde_json::to_vec(&enrollment)?)
        .map_err(|_| anyhow!("invalid protected machine bootstrap"))?;
    parse(encoded.expose())
}

fn opaque_id(value: &str) -> ResultType<u128> {
    if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid approved network identifier");
    }
    let value = u128::from_str_radix(value, 16)?;
    if value == 0 {
        bail!("missing approved network identifier");
    }
    Ok(value)
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
    if let Some(pin) = &value.mailbox_leaf_fingerprint { Fingerprint::parse(pin)?; }
    Endpoint::new(value.local_address, value.listen_port)?;
    opaque_id(&value.adapter_id)?;
    opaque_id(&value.network_id)?;
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
    use windows::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_LocalAppData, FOLDERID_ProgramData, KNOWN_FOLDER_FLAG, SHGetKnownFolderPath},
    };
    let (folder, product, role) = match purpose {
        Purpose::Viewer => (&FOLDERID_LocalAppData, "Remote Desktop Client", "viewer"),
        Purpose::HostService => (&FOLDERID_ProgramData, "Remote Desktop Service State", "host"),
    };
    let ptr = unsafe { SHGetKnownFolderPath(folder, KNOWN_FOLDER_FLAG(0), None) }
        .map_err(|_| anyhow!("enrollment directory unavailable"))?;
    let value = unsafe { ptr.to_string() }.map_err(|_| anyhow!("enrollment directory unavailable"));
    unsafe { CoTaskMemFree(Some(ptr.0.cast())); }
    Ok(PathBuf::from(value?).join(product).join(role))
}

#[cfg(windows)]
struct FreshSeed([u8; 32]);
#[cfg(windows)]
impl Drop for FreshSeed {
    fn drop(&mut self) {
        for byte in &mut self.0 { unsafe { std::ptr::write_volatile(byte, 0); } }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(windows)]
fn load_host_enrollment(directory: &std::path::Path) -> ResultType<Enrollment> {
    use super::{credentials::{provision_directory, ProtectedStore, Secret, StoreError}, machine_bootstrap};
    let parent = directory.parent().ok_or_else(|| anyhow!("invalid enrollment directory"))?;
    // Provision only protected directories; an existing credential is never replaced.
    provision_directory(parent, Purpose::HostService).map_err(|_| anyhow!("host enrollment directory unavailable"))?;
    provision_directory(directory, Purpose::HostService).map_err(|_| anyhow!("host enrollment directory unavailable"))?;
    provision_directory(&directory.join("history"), Purpose::HostService).map_err(|_| anyhow!("history directory unavailable"))?;
    super::credentials::validate_inheritable_directory(&directory.join("history"), Purpose::HostService)
        .map_err(|_| anyhow!("history directory inheritance is not protected"))?;
    let store = ProtectedStore::open(directory, Purpose::HostService)
        .map_err(|_| anyhow!("host enrollment store unavailable"))?;
    let existing = store.read_optional().map_err(|_| anyhow!("host enrollment cannot be safely read"))?;
    if let Some(secret) = existing {
        let enrollment = parse(secret.expose())?;
        // After a crash between write and finalization, remove only a bootstrap
        // matching the already persisted identity and all trust/network fields.
        match machine_bootstrap::load_pending() {
            Ok(Some(pending)) => {
                match transform_bootstrap(pending.secret().expose(), enrollment.signing_seed) {
                    Ok(candidate) if candidate == enrollment => {
                        pending.finalize(&store, &secret)
                            .map_err(|_| anyhow!("pending bootstrap cannot be finalized"))?;
                    }
                    _ => hbb_common::log::warn!("A different machine bootstrap was left pending; existing enrollment was preserved"),
                }
            }
            Ok(None) => {}
            Err(_) => hbb_common::log::warn!("Pending machine bootstrap could not be inspected; existing enrollment was preserved"),
        }
        return Ok(enrollment);
    }
    let pending = machine_bootstrap::load_pending()
        .map_err(|_| anyhow!("machine bootstrap cannot be safely read"))?
        .ok_or_else(|| anyhow!("host enrollment and machine bootstrap are missing"))?;
    let mut seed = FreshSeed([0; 32]);
    hbb_common::sodiumoxide::randombytes::randombytes_into(&mut seed.0);
    let enrollment = transform_bootstrap(pending.secret().expose(), seed.0)?;
    let encoded = Secret::new(serde_json::to_vec(&enrollment)?)
        .map_err(|_| anyhow!("invalid generated host enrollment"))?;
    match store.write_new(&encoded) {
        Ok(()) => {
            // finalize independently reads the protected store and compares
            // exact bytes before deleting the original bootstrap handle.
            pending.finalize(&store, &encoded)
                .map_err(|_| anyhow!("host enrollment read-back or bootstrap finalization failed"))?;
            let stored = store.read_optional().map_err(|_| anyhow!("host enrollment read-back failed"))?
                .ok_or_else(|| anyhow!("host enrollment disappeared"))?;
            parse(stored.expose())
        }
        Err(StoreError::AlreadyExists) => {
            // A concurrent creator won. Never replace its key or generate a
            // replacement for a failed read; its verified enrollment wins.
            let stored = store.read_optional().map_err(|_| anyhow!("host enrollment cannot be safely read"))?
                .ok_or_else(|| anyhow!("host enrollment race could not be resolved"))?;
            let existing = parse(stored.expose())?;
            match transform_bootstrap(pending.secret().expose(), existing.signing_seed) {
                Ok(candidate) if candidate == existing => {
                    pending.finalize(&store, &stored).map_err(|_| anyhow!("pending bootstrap cannot be finalized"))?;
                }
                _ => hbb_common::log::warn!("A different machine bootstrap was left pending; existing enrollment was preserved"),
            }
            Ok(existing)
        }
        Err(_) => Err(anyhow!("host enrollment could not be safely persisted")),
    }
}

#[cfg(windows)]
fn load(purpose: Purpose) -> ResultType<(Enrollment, PathBuf)> {
    use super::credentials::{validate_inheritable_directory, ProtectedStore};
    let directory = directory(purpose)?;
    let enrollment = if purpose == Purpose::HostService {
        load_host_enrollment(&directory)?
    } else {
        let store = ProtectedStore::open(&directory, purpose).map_err(|_| {
            anyhow!("mailbox enrollment is missing or not protected for this Windows identity")
        })?;
        let secret = store.read().map_err(|_| anyhow!("mailbox enrollment cannot be decrypted by this Windows identity"))?;
        parse(secret.expose())?
    };
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
        .and_then(|store| store.write_new(secret))
        .map_err(|_| anyhow!("cannot save enrollment for this Windows identity"))
}
#[cfg(not(windows))]
fn load(_: Purpose) -> ResultType<(Enrollment, PathBuf)> {
    bail!("protected mailbox enrollment is not implemented on this platform");
}

async fn initialize(purpose: Purpose, hosting: bool) -> ResultType<Arc<Runtime>> {
    let (enrollment, history_path) = spawn_blocking(move || load(purpose)).await??;
    let leaf_pin = enrollment.mailbox_leaf_fingerprint.as_deref()
        .map(Fingerprint::parse).transpose()?.map(|pin| *pin.as_bytes());
    if hosting && !enrollment.hosting_enabled {
        bail!("mailbox hosting is disabled");
    }
    let mut policy = network::Policy {
        adapter_id: opaque_id(&enrollment.adapter_id)?,
        network_id: opaque_id(&enrollment.network_id)?,
        local_address: enrollment.local_address,
    };
    let monitor = Arc::new(
        NetworkMonitor::start()
            .await
            .map_err(|_| anyhow!("network monitoring unavailable"))?,
    );
    let captured = monitor.state();
    let requested_policy = policy.clone();
    let current = spawn_blocking(move || network::resolve_current_ipv4(Some(&requested_policy)))
        .await?
        .map_err(|_| anyhow!("the approved home network has no unambiguous current IPv4 address"))?;
    if !monitor.is_current(captured) {
        bail!("network changed during enrollment validation");
    }
    policy.local_address = current;
    let check_policy = policy.clone();
    let address = SocketAddr::new(current, enrollment.listen_port);
    spawn_blocking(move || network::verify_binding(Some(&check_policy), address))
        .await?
        .map_err(|_| anyhow!("the approved home network is not available"))?;
    if !monitor.is_current(captured) {
        bail!("network changed during enrollment validation");
    }
    let mailbox = MailboxWorker::start_with_pin(
        enrollment.mailbox_url.clone(),
        enrollment.mailbox_ca_pem.as_bytes().to_vec(),
        AccessToken::from_encoded(&enrollment.access_token)?,
        leaf_pin,
    )
    .await?;
    let identity = Identity::new(&enrollment.identity)?;
    let (public, signing_key) = sign::keypair_from_seed(&sign::Seed(enrollment.signing_seed));
    let fingerprint = Fingerprint::from_bytes(Sha256::digest(public.0).into());
    let history = if hosting {
        let token = ApiToken::new(enrollment.access_token.clone())?;
        Some(
            HistoryWorker::start_with_pin(
                history_path,
                4096,
                enrollment.mailbox_url.clone(),
                enrollment.mailbox_ca_pem.as_bytes().to_vec(),
                move || Ok(token),
                leaf_pin,
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
        endpoint: Endpoint::new(policy.local_address, enrollment.listen_port)?,
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
#[cfg(windows)]
static MACHINE: OnceCell<Arc<Runtime>> = OnceCell::const_new();

pub(crate) async fn viewer() -> ResultType<Arc<Runtime>> {
    Ok(VIEWER
        .get_or_try_init(|| initialize(Purpose::Viewer, false))
        .await?
        .clone())
}
pub(crate) async fn host() -> ResultType<Arc<Runtime>> {
    Ok(HOST
        .get_or_try_init(|| initialize(Purpose::HostService, true))
        .await?
        .clone())
}

/// SCM broker uses the same protected identity without owning the host worker's outbox.
#[cfg(windows)]
pub(crate) async fn machine_for_service() -> ResultType<Arc<Runtime>> {
    Ok(MACHINE.get_or_try_init(|| initialize(Purpose::HostService, false)).await?.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1, "identity": "test-viewer", "display_name": "Test viewer",
            "mailbox_url": "https://192.168.1.2:42819/", "mailbox_ca_pem": "synthetic certificate",
            "access_token": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "signing_seed": vec![7u8; 32],
            "adapter_id": "00000000000000000000000000000001", "network_id": "00000000000000000000000000000002",
            "local_address": "192.168.1.3", "listen_port": 42830, "hosting_enabled": false
        })
    }
    #[test]
    fn machine_bootstrap_transform_preserves_identity_and_pin() {
        let certificate = include_str!("../../libs/hbb_common/tests/data/websocket-cert.pem");
        let pin = bootstrap_certificate_fingerprint(certificate).unwrap().to_hex();
        let input = serde_json::json!({
            "schema_version": 1,
            "client": {"url":"https://192.168.1.2:42819/", "fingerprint":pin.clone(), "environment":"production", "token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            "config": {"identity":"test-host", "display_name":"Test host", "mailbox_ca_pem":certificate, "adapter_id":"00000000000000000000000000000001", "network_id":"00000000000000000000000000000002", "local_address":"192.168.1.3", "listen_port":42830}
        });
        let encoded = serde_json::to_vec(&input).unwrap();
        let enrollment = transform_bootstrap(&encoded, [9;32]).unwrap();
        assert_eq!(enrollment.identity, "test-host");
        assert_eq!(enrollment.signing_seed, [9;32]);
        assert_eq!(enrollment.mailbox_leaf_fingerprint.as_deref(), Some(pin.as_str()));
        assert!(enrollment.hosting_enabled);
        let roundtrip = parse(&serde_json::to_vec(&enrollment).unwrap()).unwrap();
        assert!(roundtrip == enrollment);
        let mut wrong_pin = input.clone();
        wrong_pin["client"]["fingerprint"] = serde_json::json!("cd".repeat(32));
        assert!(transform_bootstrap(&serde_json::to_vec(&wrong_pin).unwrap(), [9;32]).is_err());
        let mut bad = input;
        bad["client"]["environment"] = serde_json::json!("development");
        assert!(transform_bootstrap(&serde_json::to_vec(&bad).unwrap(), [9;32]).is_err());
        assert!(transform_bootstrap(&encoded, [0;32]).is_err());
    }

    #[test]
    fn enrollment_is_versioned_and_rejects_incomplete_or_untrusted_inputs() {
        let valid = fixture();
        let legacy = parse(&serde_json::to_vec(&valid).unwrap()).unwrap();
        assert!(legacy.mailbox_leaf_fingerprint.is_none());
        for (key, replacement) in [
            ("schema_version", serde_json::json!(2)),
            ("access_token", serde_json::json!("invalid")),
            ("mailbox_url", serde_json::json!("http://192.168.1.2/")),
            (
                "adapter_id",
                serde_json::json!("00000000000000000000000000000000"),
            ),
            ("listen_port", serde_json::json!(0)),
        ] {
            let mut bad = valid.clone();
            bad[key] = replacement;
            assert!(parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        let mut unknown = valid;
        unknown["disable_authentication"] = serde_json::json!(true);
        assert!(parse(&serde_json::to_vec(&unknown).unwrap()).is_err());
    }
}
