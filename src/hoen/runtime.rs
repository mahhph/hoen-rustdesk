use super::{
    credentials::{CredentialStore, Purpose},
    history_worker::HistoryWorker,
    mailbox_worker::MailboxWorker,
    network,
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

#[derive(Clone)]
pub(crate) struct Runtime {
    pub identity: Identity,
    pub mailbox: MailboxWorker,
    pub signing_key: sign::SecretKey,
    pub policy: network::Policy,
    pub listen_port: u16,
    pub history: Option<Arc<OnceCell<HistoryWorker>>>,
    hosting: bool,
    registration: Registration,
    mailbox_url: url::Url,
}

impl Runtime {
    pub async fn current_host_address(&self) -> ResultType<Self> {
        let url = self.mailbox_url.clone();
        let address = hbb_common::tokio::time::timeout(
            std::time::Duration::from_secs(10),
            spawn_blocking(move || resolve_local_address(&url)),
        ).await???;
        let mut next = self.clone();
        next.policy.local_address = address;
        next.registration.endpoint = Endpoint::new(address, self.listen_port)?;
        Ok(next)
    }

    /// Called by the host only after the configured listener has successfully bound.
    pub async fn register_host(&self) -> ResultType<()> {
        if !self.hosting {
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
    #[serde(default, rename = "adapter_id")]
    _legacy_adapter_id: Option<String>,
    #[serde(default, rename = "network_id")]
    _legacy_network_id: Option<String>,
    #[serde(default)]
    local_address: Option<IpAddr>,
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
    #[serde(default, rename = "adapter_id")]
    legacy_adapter_id: Option<String>,
    #[serde(default, rename = "network_id")]
    legacy_network_id: Option<String>,
    #[serde(default)]
    local_address: Option<IpAddr>,
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
        _legacy_adapter_id: value.config.legacy_adapter_id,
        _legacy_network_id: value.config.legacy_network_id,
        local_address: value.config.local_address,
        listen_port: value.config.listen_port,
        hosting_enabled: true,
    };
    let encoded = super::credentials::Secret::new(serde_json::to_vec(&enrollment)?)
        .map_err(|_| anyhow!("invalid protected machine bootstrap"))?;
    parse(encoded.expose())
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
    if let Some(address) = value.local_address {
        Endpoint::new(address, value.listen_port)?;
    }
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
fn load(purpose: Purpose) -> ResultType<Enrollment> {
    use super::credentials::ProtectedStore;
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
    Ok(enrollment)
}

#[cfg(windows)]
fn prepare_history_path() -> ResultType<PathBuf> {
    use super::credentials::{provision_directory, validate_inheritable_directory};
    let history = directory(Purpose::HostService)?.join("history");
    provision_directory(&history, Purpose::HostService)
        .and_then(|_| validate_inheritable_directory(&history, Purpose::HostService))
        .map_err(|_| anyhow!("protected history directory unavailable"))?;
    Ok(history.join("outbox.sqlite"))
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
    ProtectedStore::open(&directory, purpose)
        .and_then(|store| store.write_new(secret))
        .map_err(|_| anyhow!("cannot save enrollment for this Windows identity"))
}
#[cfg(target_os = "macos")]
fn load(purpose: Purpose) -> ResultType<Enrollment> {
    use super::credentials::MacStore;
    let store = MacStore::for_user(purpose)
        .map_err(|_| anyhow!("user Keychain unavailable for mailbox enrollment"))?;
    let secret = store.read().map_err(|_| anyhow!("protected mailbox enrollment unavailable"))?;
    let enrollment = parse(secret.expose())?;
    Ok(enrollment)
}

#[cfg(target_os = "macos")]
fn prepare_history_path() -> ResultType<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("user home unavailable"))?;
    super::macos_private_dir::history(std::path::Path::new(&home))
}

#[cfg(target_os = "macos")]
pub(crate) fn import_enrollment(
    purpose: Purpose,
    secret: &super::credentials::Secret,
) -> ResultType<()> {
    use super::credentials::MacStore;
    let _validated = parse(secret.expose())?;
    let store = MacStore::for_user(purpose)
        .map_err(|_| anyhow!("user Keychain unavailable for mailbox enrollment"))?;
    store.write_new(secret).map_err(|_| anyhow!("cannot create protected mailbox enrollment; an existing enrollment is not replaced"))
}

#[cfg(target_os = "macos")]
fn host_secret_from_viewer(secret: &super::credentials::Secret) -> ResultType<super::credentials::Secret> {
    let mut enrollment = parse(secret.expose())?;
    enrollment.hosting_enabled = true;
    super::credentials::Secret::new(serde_json::to_vec(&enrollment)?)
        .map_err(|_| anyhow!("cannot prepare protected host enrollment"))
}

/// Reuse the viewer's existing identity and signing key; never replace a host entry.
#[cfg(target_os = "macos")]
pub(crate) fn provision_host_from_viewer() -> ResultType<()> {
    use super::credentials::{CredentialStore, MacStore};
    let viewer = MacStore::for_user(Purpose::Viewer)
        .and_then(|store| store.read())
        .map_err(|_| anyhow!("protected viewer enrollment unavailable"))?;
    let host = host_secret_from_viewer(&viewer)?;
    import_enrollment(Purpose::HostService, &host)
}

#[cfg(not(any(windows, target_os = "macos")))]
fn load(_: Purpose) -> ResultType<Enrollment> {
    bail!("protected mailbox enrollment is not implemented on this platform");
}

#[cfg(not(any(windows, target_os = "macos")))]
fn prepare_history_path() -> ResultType<PathBuf> {
    bail!("protected history is not implemented on this platform");
}

fn resolve_local_address(mailbox_url: &url::Url) -> ResultType<IpAddr> {
    mailbox_url
        .socket_addrs(|| None)?
        .into_iter()
        .filter_map(|remote| network::local_address_for(remote).ok())
        .find(|address| Endpoint::new(*address, 1).is_ok())
        .ok_or_else(|| anyhow!("no local address available for mailbox"))
}

async fn initialize(purpose: Purpose, hosting: bool) -> ResultType<Arc<Runtime>> {
    let enrollment = spawn_blocking(move || load(purpose)).await??;
    initialize_loaded(&enrollment, hosting).await
}

async fn initialize_loaded(enrollment: &Enrollment, hosting: bool) -> ResultType<Arc<Runtime>> {
    let leaf_pin = enrollment.mailbox_leaf_fingerprint.as_deref()
        .map(Fingerprint::parse).transpose()?.map(|pin| *pin.as_bytes());
    if hosting && !enrollment.hosting_enabled {
        bail!("mailbox hosting is disabled");
    }
    let mailbox_url = url::Url::parse(&enrollment.mailbox_url)?;
    let local_address = hbb_common::tokio::time::timeout(
        std::time::Duration::from_secs(10),
        spawn_blocking(move || resolve_local_address(&mailbox_url)),
    )
    .await???;
    let policy = network::Policy { local_address };
    let check_policy = policy.clone();
    let address = SocketAddr::new(policy.local_address, enrollment.listen_port);
    spawn_blocking(move || network::verify_binding(Some(&check_policy), address))
        .await?
        .map_err(|_| anyhow!("the configured bind address is not available"))?;
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
    // Start the durable worker only after fallible mailbox setup. Otherwise a
    // failed startup retry could overlap workers on the same outbox.
    let history = if hosting {
        Some({
            let cell = Arc::new(OnceCell::new());
            let target = cell.clone();
            let url = enrollment.mailbox_url.clone();
            let root = enrollment.mailbox_ca_pem.as_bytes().to_vec();
            let access_token = enrollment.access_token.clone();
            hbb_common::tokio::spawn(async move {
                let history_path = match spawn_blocking(prepare_history_path).await {
                    Ok(Ok(path)) => path,
                    _ => {
                        hbb_common::log::warn!("Session history unavailable: protected history directory unavailable");
                        return;
                    }
                };
                let result = match ApiToken::new(access_token) {
                    Ok(token) => HistoryWorker::start_with_pin(
                        history_path, 4096, url, root, move || Ok(token), leaf_pin,
                    ).await,
                    Err(error) => Err(super::history_worker::WorkerError::Delivery(error)),
                };
                match result {
                    Ok(worker) => { let _ = target.set(worker); }
                    Err(error) => hbb_common::log::warn!("Session history unavailable: {error}"),
                }
            });
            cell
        })
    } else { None };
    Ok(Arc::new(Runtime {
        identity,
        mailbox,
        signing_key,
        policy,
        listen_port: enrollment.listen_port,
        history,
        hosting,
        registration,
        mailbox_url: url::Url::parse(&enrollment.mailbox_url)?,
    }))
}

static VIEWER: OnceCell<Arc<Runtime>> = OnceCell::const_new();
static HOST: OnceCell<Arc<Runtime>> = OnceCell::const_new();
#[cfg(windows)]
static MACHINE: OnceCell<Arc<Runtime>> = OnceCell::const_new();

#[cfg(target_os = "macos")]
async fn retry_host_initialization<T, F, Fut>(mut attempt: F, delay: std::time::Duration) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ResultType<Option<T>>>,
{
    loop {
        match attempt().await {
            Ok(Some(value)) => return value,
            Ok(None) => {}, // Hosting is intentionally disabled.
            Err(error) => hbb_common::log::warn!("Mac host initialization unavailable; retrying: {error}"),
        }
        hbb_common::tokio::time::sleep(delay).await;
    }
}

pub(crate) async fn viewer() -> ResultType<Arc<Runtime>> {
    Ok(VIEWER
        .get_or_try_init(|| initialize(Purpose::Viewer, false))
        .await?
        .clone())
}
pub(crate) async fn host() -> ResultType<Arc<Runtime>> {
    Ok(HOST
        .get_or_try_init(|| async {
            #[cfg(target_os = "macos")]
            {
                // Load protected enrollment once: a temporary network outage
                // must not cause repeated Keychain prompts or lose the host.
                let enrollment = spawn_blocking(|| load(Purpose::HostService)).await??;
                if !enrollment.hosting_enabled { bail!("mailbox hosting is disabled"); }
                let enrollment = &enrollment;
                Ok(retry_host_initialization(|| async {
                    if super::host::disabled() { return Ok(None); }
                    initialize_loaded(enrollment, true).await.map(Some)
                }, std::time::Duration::from_secs(15)).await)
            }
            #[cfg(not(target_os = "macos"))]
            initialize(Purpose::HostService, true).await
        })
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

    #[cfg(target_os = "macos")]
    #[hbb_common::tokio::test]
    async fn host_initialization_retries_temporary_failure_and_disabled_state() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = AtomicUsize::new(0);
        let value = hbb_common::tokio::time::timeout(
            std::time::Duration::from_secs(1),
            retry_host_initialization(|| {
                let index = attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    match index {
                        0 => Err(anyhow!("temporary network failure")),
                        1 => Ok(None),
                        _ => Ok(Some(42)),
                    }
                }
            }, std::time::Duration::from_millis(1)),
        ).await.unwrap();
        assert_eq!(value, 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_enrollment_reuses_viewer_identity_without_changing_the_viewer() {
        let viewer = super::super::credentials::Secret::new(
            serde_json::to_vec(&fixture()).unwrap()
        ).unwrap();
        let before = parse(viewer.expose()).unwrap();
        assert!(!before.hosting_enabled);
        let host = host_secret_from_viewer(&viewer).unwrap();
        let after = parse(host.expose()).unwrap();
        assert_eq!(after.identity, before.identity);
        assert_eq!(after.signing_seed, before.signing_seed);
        assert_eq!(after.access_token, before.access_token);
        assert_eq!(after.mailbox_url, before.mailbox_url);
        assert_eq!(after.mailbox_leaf_fingerprint, before.mailbox_leaf_fingerprint);
        assert!(after.hosting_enabled);
        assert!(!parse(viewer.expose()).unwrap().hosting_enabled);
    }

    #[test]
    fn startup_resolves_current_address_instead_of_using_enrollment_address() {
        let enrollment = parse(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
        let mailbox = url::Url::parse("https://127.0.0.1:42819/").unwrap();
        let address = resolve_local_address(&mailbox).unwrap();
        assert_eq!(address, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_ne!(Some(address), enrollment.local_address);
    }
    fn fixture() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1, "identity": "test-viewer", "display_name": "Test viewer",
            "mailbox_url": "https://192.168.1.2:42819/", "mailbox_ca_pem": "synthetic certificate",
            "access_token": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "signing_seed": vec![7u8; 32],
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
            "config": {"identity":"test-host", "display_name":"Test host", "mailbox_ca_pem":certificate, "local_address":"192.168.1.3", "listen_port":42830}
        });
        let encoded = serde_json::to_vec(&input).unwrap();
        let enrollment = transform_bootstrap(&encoded, [9;32]).unwrap();
        assert_eq!(enrollment.identity, "test-host");
        assert_eq!(enrollment.signing_seed, [9;32]);
        assert_eq!(enrollment.mailbox_leaf_fingerprint.as_deref(), Some(pin.as_str()));
        assert!(enrollment.hosting_enabled);
        let roundtrip = parse(&serde_json::to_vec(&enrollment).unwrap()).unwrap();
        assert!(roundtrip == enrollment);
        let mut automatic = input.clone();
        automatic["config"].as_object_mut().unwrap().remove("local_address");
        assert!(transform_bootstrap(&serde_json::to_vec(&automatic).unwrap(), [9;32]).is_ok());
        let mut old = input.clone();
        old["config"]["adapter_id"] = serde_json::json!("legacy");
        old["config"]["network_id"] = serde_json::json!("legacy");
        assert!(transform_bootstrap(&serde_json::to_vec(&old).unwrap(), [9;32]).is_ok());
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
        let mut automatic = valid.clone();
        automatic.as_object_mut().unwrap().remove("local_address");
        assert!(parse(&serde_json::to_vec(&automatic).unwrap()).is_ok());
        let mut unknown = valid;
        unknown["disable_authentication"] = serde_json::json!(true);
        assert!(parse(&serde_json::to_vec(&unknown).unwrap()).is_err());
    }
}
