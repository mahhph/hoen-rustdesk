//! Blocking mailbox registry and grant client. Run on a dedicated worker.
//! Trust and authorization of the peer still require the separate handshake.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::{
    blocking::Client,
    header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    redirect::Policy,
    Certificate, Method, Url,
};
use serde::Deserialize;
use std::{fmt, io::Read, net::IpAddr, time::Duration};
use zeroize::Zeroize;

const MAX_BODY: u64 = 256 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    InvalidConfiguration,
    Unconfirmed,
    Rejected(u16),
    InvalidResponse,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => f.write_str("invalid mailbox request"),
            Self::InvalidConfiguration => f.write_str("invalid mailbox client configuration"),
            Self::Unconfirmed => f.write_str("mailbox request outcome is unconfirmed"),
            Self::Rejected(status) => write!(f, "mailbox request rejected with HTTP {status}"),
            Self::InvalidResponse => f.write_str("invalid mailbox response"),
        }
    }
}
impl std::error::Error for Error {}

fn decode_token(s: &str) -> Result<[u8; 32], Error> {
    if s.len() != 43 {
        return Err(Error::InvalidInput);
    }
    let bytes = URL_SAFE_NO_PAD.decode(s).map_err(|_| Error::InvalidInput)?;
    let token: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidInput)?;
    if URL_SAFE_NO_PAD.encode(token) != s {
        return Err(Error::InvalidInput);
    }
    Ok(token)
}
/// Caller-owned credential; deliberately not Debug, Clone, or Serialize.
pub struct AccessToken([u8; 32]);
impl AccessToken {
    pub fn from_encoded(s: &str) -> Result<Self, Error> {
        Ok(Self(decode_token(s)?))
    }
}
impl Drop for AccessToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
/// One-use token; deliberately not Debug, Clone, or Serialize.
pub struct GrantToken([u8; 32]);
impl GrantToken {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn from_encoded(s: &str) -> Result<Self, Error> {
        Ok(Self(decode_token(s)?))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Produce the protocol field explicitly; do not log or persist it.
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}
impl Drop for GrantToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity(String);
impl Identity {
    pub fn new(s: &str) -> Result<Self, Error> {
        if s.is_empty()
            || s.len() > 64
            || s == "operator"
            || !s.as_bytes()[0].is_ascii_lowercase()
            || !s
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self(s.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);
impl Fingerprint {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn parse(s: &str) -> Result<Self, Error> {
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::InvalidInput);
        }
        let mut out = [0; 32];
        for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
            let h = (pair[0] as char).to_digit(16).ok_or(Error::InvalidInput)?;
            let l = (pair[1] as char).to_digit(16).ok_or(Error::InvalidInput)?;
            out[i] = ((h << 4) | l) as u8;
        }
        Ok(Self(out))
    }
    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    address: IpAddr,
    port: u16,
}
impl Endpoint {
    pub fn address(&self) -> IpAddr {
        self.address
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn new(address: IpAddr, port: u16) -> Result<Self, Error> {
        let valid = match address {
            IpAddr::V4(v) => v.is_private(),
            IpAddr::V6(v) => (v.segments()[0] & 0xfe00) == 0xfc00,
        };
        if !valid || port == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self { address, port })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Machine {
    pub identity: Identity,
    pub display_name: String,
    pub endpoint: Endpoint,
    pub hosting_enabled: bool,
    pub public_key_fingerprint: Fingerprint,
    pub updated_at: String,
}
/// Validated registration values; server still independently authorizes the identity.
#[derive(Clone, Debug)]
pub struct Registration {
    pub identity: Identity,
    pub display_name: String,
    pub endpoint: Endpoint,
    pub hosting_enabled: bool,
    pub public_key_fingerprint: Fingerprint,
}
impl Registration {
    fn validate(&self) -> Result<(), Error> {
        validate_name(&self.display_name)?;
        Endpoint::new(self.endpoint.address, self.endpoint.port)?;
        Ok(())
    }
}
fn validate_name(s: &str) -> Result<(), Error> {
    if s.is_empty() || s.len() > 128 || s.trim() != s || s.chars().any(char::is_control) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
fn validate_timestamp(s: &str) -> Result<(), Error> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map(|_| ())
        .map_err(|_| Error::InvalidResponse)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireEndpoint {
    address: String,
    port: u16,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireMachine {
    identity: String,
    display_name: String,
    endpoint: WireEndpoint,
    hosting_enabled: bool,
    public_key_fingerprint: String,
    updated_at: String,
}
impl TryFrom<WireMachine> for Machine {
    type Error = Error;
    fn try_from(m: WireMachine) -> Result<Self, Error> {
        let convert = |_: Error| Error::InvalidResponse;
        validate_name(&m.display_name).map_err(convert)?;
        validate_timestamp(&m.updated_at)?;
        let address = m
            .endpoint
            .address
            .parse::<IpAddr>()
            .map_err(|_| Error::InvalidResponse)?;
        Ok(Self {
            identity: Identity::new(&m.identity).map_err(convert)?,
            display_name: m.display_name,
            endpoint: Endpoint::new(address, m.endpoint.port).map_err(convert)?,
            hosting_enabled: m.hosting_enabled,
            public_key_fingerprint: Fingerprint::parse(&m.public_key_fingerprint)
                .map_err(convert)?,
            updated_at: m.updated_at,
        })
    }
}
#[derive(Deserialize)]
struct OneMachine {
    machine: WireMachine,
}
#[derive(Deserialize)]
struct Machines {
    machines: Vec<WireMachine>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireGrant {
    token: String,
    expires_at: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireConsumed {
    viewer: String,
    host: String,
    viewer_fingerprint: String,
    host_fingerprint: String,
}
/// No Debug or Serialize because it contains a one-use bearer grant.
pub struct IssuedGrant {
    pub token: GrantToken,
    pub expires_at: String,
}
#[derive(Debug, PartialEq, Eq)]
pub struct ConsumedGrant {
    pub viewer: Identity,
    pub host: Identity,
    pub viewer_fingerprint: Fingerprint,
    pub host_fingerprint: Fingerprint,
}

/// Strict HTTPS with a caller-provided sole trust root, no redirect or proxy.
pub struct MailboxClient {
    client: Client,
    base: Url,
    token: AccessToken,
}
impl MailboxClient {
    pub fn new(base_url: &str, root_pem: &[u8], token: AccessToken) -> Result<Self, Error> {
        Self::new_inner(base_url, root_pem, token, None)
    }
    /// Require the exact SHA-256 leaf certificate pin in addition to normal TLS verification.
    pub fn new_pinned(
        base_url: &str,
        root_pem: &[u8],
        token: AccessToken,
        leaf_sha256: [u8; 32],
    ) -> Result<Self, Error> {
        Self::new_inner(base_url, root_pem, token, Some(leaf_sha256))
    }
    fn new_inner(
        base_url: &str,
        root_pem: &[u8],
        token: AccessToken,
        leaf_sha256: Option<[u8; 32]>,
    ) -> Result<Self, Error> {
        let base = Url::parse(base_url).map_err(|_| Error::InvalidConfiguration)?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.path() != "/"
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(Error::InvalidConfiguration);
        }
        let cert = Certificate::from_pem(root_pem).map_err(|_| Error::InvalidConfiguration)?;
        let builder = Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15));
        let builder = match leaf_sha256 {
            Some(pin) => builder.use_preconfigured_tls(
                crate::tls_pin::pinned_config(root_pem, pin)
                    .map_err(|_| Error::InvalidConfiguration)?,
            ),
            None => builder.add_root_certificate(cert),
        };
        let client = builder.build().map_err(|_| Error::InvalidConfiguration)?;
        Ok(Self {
            client,
            base,
            token,
        })
    }
    fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        expected: u16,
    ) -> Result<T, Error> {
        let url = self.base.join(path).map_err(|_| Error::InvalidInput)?;
        let mut auth =
            HeaderValue::from_str(&format!("Bearer {}", URL_SAFE_NO_PAD.encode(self.token.0)))
                .map_err(|_| Error::InvalidConfiguration)?;
        auth.set_sensitive(true);
        let mut req = self.client.request(method, url).header(AUTHORIZATION, auth);
        if let Some(body) = body {
            req = req.header(CONTENT_TYPE, "application/json").body(body);
        }
        let response = req.send().map_err(|_| Error::Unconfirmed)?;
        let status = response.status().as_u16();
        if status != expected {
            return match status {
                408 | 429 | 500..=599 | 200..=299 => Err(Error::Unconfirmed),
                _ => Err(Error::Rejected(status)),
            };
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_BODY + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Unconfirmed)?;
        if bytes.len() as u64 > MAX_BODY {
            return Err(Error::InvalidResponse);
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse)
    }
    pub fn register(&self, value: &Registration) -> Result<Machine, Error> {
        value.validate()?;
        let body = serde_json::json!({"identity":value.identity.as_str(),"displayName":value.display_name,"endpoint":{"address":value.endpoint.address.to_string(),"port":value.endpoint.port},"hostingEnabled":value.hosting_enabled,"publicKeyFingerprint":value.public_key_fingerprint.to_hex()});
        let row: OneMachine = self.request(
            Method::PUT,
            "/v1/remote-machines",
            Some(serde_json::to_vec(&body).map_err(|_| Error::InvalidInput)?),
            200,
        )?;
        let machine = Machine::try_from(row.machine)?;
        if machine.identity != value.identity
            || machine.public_key_fingerprint != value.public_key_fingerprint
            || machine.endpoint != value.endpoint
            || machine.hosting_enabled != value.hosting_enabled
            || machine.display_name != value.display_name
        {
            return Err(Error::InvalidResponse);
        }
        Ok(machine)
    }
    pub fn list(&self) -> Result<Vec<Machine>, Error> {
        let rows: Machines = self.request(Method::GET, "/v1/remote-machines", None, 200)?;
        rows.machines.into_iter().map(Machine::try_from).collect()
    }
    pub fn lookup(&self, host: &Identity) -> Result<Machine, Error> {
        let row: OneMachine = self.request(
            Method::GET,
            &format!("/v1/remote-machines/{}", host.as_str()),
            None,
            200,
        )?;
        let machine = Machine::try_from(row.machine)?;
        if &machine.identity != host || !machine.hosting_enabled {
            return Err(Error::InvalidResponse);
        }
        Ok(machine)
    }
    /// Issuance is not idempotent. Never blindly replay an ambiguous result.
    pub fn request_grant(&self, host: &Identity, binding: &[u8; 32]) -> Result<IssuedGrant, Error> {
        let body = serde_json::json!({"host":host.as_str(),"channelBinding":Fingerprint::from_bytes(*binding).to_hex()});
        let mut row: WireGrant = self.request(
            Method::POST,
            "/v1/remote-grants",
            Some(serde_json::to_vec(&body).map_err(|_| Error::InvalidInput)?),
            201,
        )?;
        validate_timestamp(&row.expires_at)?;
        let token = GrantToken::from_encoded(&row.token).map_err(|_| Error::InvalidResponse);
        row.token.zeroize();
        Ok(IssuedGrant {
            token: token?,
            expires_at: row.expires_at,
        })
    }
    /// A grant is single-use: on *any* ambiguous result close the connection and obtain a fresh grant.
    /// Caller must verify the returned fingerprints and viewer proof before admission.
    pub fn consume_grant(
        &self,
        token: GrantToken,
        binding: &[u8; 32],
        expected_host: &Identity,
    ) -> Result<ConsumedGrant, Error> {
        let body = serde_json::json!({"token":token.encode(),"channelBinding":Fingerprint::from_bytes(*binding).to_hex()});
        let row: WireConsumed = self.request(
            Method::POST,
            "/v1/remote-grants/consume",
            Some(serde_json::to_vec(&body).map_err(|_| Error::InvalidInput)?),
            200,
        )?;
        let convert = |_: Error| Error::InvalidResponse;
        let grant = ConsumedGrant {
            viewer: Identity::new(&row.viewer).map_err(convert)?,
            host: Identity::new(&row.host).map_err(convert)?,
            viewer_fingerprint: Fingerprint::parse(&row.viewer_fingerprint).map_err(convert)?,
            host_fingerprint: Fingerprint::parse(&row.host_fingerprint).map_err(convert)?,
        };
        if &grant.host != expected_host {
            return Err(Error::InvalidResponse);
        }
        Ok(grant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::Arc,
        thread,
    };

    // Local TLS only: the server returns a single explicitly supplied response.
    fn mock(status: u16, json: Vec<u8>) -> (u16, Vec<u8>, thread::JoinHandle<Vec<u8>>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.serialize_der().unwrap();
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(&der)
        )
        .into_bytes();
        let tls = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::Certificate(der)],
                rustls::PrivateKey(cert.serialize_private_key_der()),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let thread = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut stream = rustls::StreamOwned::new(
                rustls::ServerConnection::new(Arc::new(tls)).unwrap(),
                socket,
            );
            let mut request = Vec::new();
            loop {
                let mut chunk = [0; 4096];
                let n = match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => return request,
                    Ok(n) => n,
                };
                request.extend_from_slice(&chunk[..n]);
                if request.len() > 8192 {
                    return request;
                }
                if let Some(pos) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let hdr = String::from_utf8_lossy(&request[..pos]);
                    let n = hdr
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if request.len() >= pos + 4 + n {
                        break;
                    }
                }
            }
            let hdr=format!("HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",json.len());
            let _ = stream.write_all(hdr.as_bytes());
            let _ = stream.write_all(&json);
            let _ = stream.flush();
            request
        });
        (port, pem, thread)
    }
    fn setup(status: u16, json: serde_json::Value) -> (MailboxClient, thread::JoinHandle<Vec<u8>>) {
        let (port, pem, thread) = mock(status, serde_json::to_vec(&json).unwrap());
        (
            MailboxClient::new(
                &format!("https://localhost:{port}"),
                &pem,
                AccessToken::from_encoded(&URL_SAFE_NO_PAD.encode([3; 32])).unwrap(),
            )
            .unwrap(),
            thread,
        )
    }
    #[test]
    fn pinned_tls_requires_exact_leaf_and_hostname_before_sending_authorization() {
        use sha2::{Digest, Sha256};
        for mode in ["correct", "wrong-pin", "wrong-name", "wrong-ca"] {
            let (port, pem, server) = mock(200, br#"{"machines":[]}"#.to_vec());
            let der = rustls_pemfile::certs(&mut &pem[..]).unwrap().remove(0);
            let mut pin: [u8; 32] = Sha256::digest(&der).into();
            if mode == "wrong-pin" {
                pin[0] ^= 1;
            }
            let host = if mode == "wrong-name" {
                "127.0.0.1"
            } else {
                "localhost"
            };
            let root = if mode == "wrong-ca" {
                rcgen::generate_simple_self_signed(vec!["localhost".into()])
                    .unwrap()
                    .serialize_pem()
                    .unwrap()
                    .into_bytes()
            } else {
                pem.clone()
            };
            let client = MailboxClient::new_pinned(
                &format!("https://{host}:{port}"),
                &root,
                AccessToken::from_encoded(&URL_SAFE_NO_PAD.encode([3; 32])).unwrap(),
                pin,
            )
            .unwrap();
            let result = client.list();
            let received = server.join().unwrap();
            if mode == "correct" {
                assert!(result.is_ok());
                assert!(!received.is_empty());
            } else {
                assert!(result.is_err());
                assert!(
                    received.is_empty(),
                    "TLS failure must occur before any HTTP request"
                );
            }
        }
    }
    fn record() -> serde_json::Value {
        serde_json::json!({"identity":"host-one","displayName":"Home Host","endpoint":{"address":"192.168.1.4","port":21118},"hostingEnabled":true,"publicKeyFingerprint":"ab".repeat(32),"updatedAt":"2026-11-05T18:00:00.000Z"})
    }
    fn expect_request(bytes: Vec<u8>, method: &str, path: &str) -> serde_json::Value {
        let data = String::from_utf8(bytes).unwrap();
        let (head, body) = data.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with(&format!("{method} {path} HTTP/1.1")));
        assert!(head.to_ascii_lowercase().contains("authorization: bearer "));
        if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(body).unwrap()
        }
    }
    #[test]
    fn registry_and_grants_use_expected_contract_over_tls() {
        let host = Identity::new("host-one").unwrap();
        let pin = Fingerprint::parse(&"ab".repeat(32)).unwrap();
        let registration = Registration {
            identity: host.clone(),
            display_name: "Home Host".into(),
            endpoint: Endpoint::new("192.168.1.4".parse().unwrap(), 21118).unwrap(),
            hosting_enabled: true,
            public_key_fingerprint: pin,
        };
        let (client, thread) = setup(200, serde_json::json!({"machine":record()}));
        assert_eq!(client.register(&registration).unwrap().identity, host);
        let req = expect_request(thread.join().unwrap(), "PUT", "/v1/remote-machines");
        assert_eq!(req["identity"], "host-one");
        assert_eq!(req["publicKeyFingerprint"], "ab".repeat(32));
        let (client, thread) = setup(200, serde_json::json!({"machines":[record()]}));
        assert_eq!(client.list().unwrap().len(), 1);
        expect_request(thread.join().unwrap(), "GET", "/v1/remote-machines");
        let (client, thread) = setup(200, serde_json::json!({"machine":record()}));
        assert_eq!(
            client.lookup(&host).unwrap().endpoint,
            registration.endpoint
        );
        expect_request(
            thread.join().unwrap(),
            "GET",
            "/v1/remote-machines/host-one",
        );
        let token_string = URL_SAFE_NO_PAD.encode([7; 32]);
        let (client, thread) = setup(
            201,
            serde_json::json!({"token":token_string,"expiresAt":"2026-11-05T18:01:00.000Z"}),
        );
        let grant = client.request_grant(&host, &[9; 32]).unwrap();
        assert_eq!(grant.token.as_bytes(), &[7; 32]);
        let req = expect_request(thread.join().unwrap(), "POST", "/v1/remote-grants");
        assert_eq!(req["channelBinding"], "09".repeat(32));
        let (client, thread) = setup(
            200,
            serde_json::json!({"viewer":"viewer-one","host":"host-one","viewerFingerprint":"cd".repeat(32),"hostFingerprint":"ab".repeat(32)}),
        );
        let accepted = client.consume_grant(grant.token, &[9; 32], &host).unwrap();
        assert_eq!(accepted.host_fingerprint, pin);
        assert_eq!(accepted.viewer.as_str(), "viewer-one");
        let req = expect_request(thread.join().unwrap(), "POST", "/v1/remote-grants/consume");
        assert_eq!(req["token"], token_string);
    }
    #[test]
    fn reject_invalid_tokens_identifiers_endpoints_and_false_response() {
        assert!(GrantToken::from_encoded("bad").is_err());
        assert!(GrantToken::from_encoded(&format!("{}B", "A".repeat(42))).is_err());
        assert!(Identity::new("operator").is_err());
        assert!(Identity::new("bad/name").is_err());
        assert!(Endpoint::new("8.8.8.8".parse().unwrap(), 12).is_err());
        assert!(Endpoint::new("192.168.1.2".parse().unwrap(), 0).is_err());
        let (client, thread) = setup(200, serde_json::json!({"machine":record()}));
        assert!(matches!(
            client.lookup(&Identity::new("different").unwrap()),
            Err(Error::InvalidResponse)
        ));
        thread.join().unwrap();
        let (client, thread) = setup(
            200,
            serde_json::json!({"viewer":"viewer-one","host":"wrong-host","viewerFingerprint":"cd".repeat(32),"hostFingerprint":"ab".repeat(32)}),
        );
        assert!(matches!(
            client.consume_grant(
                GrantToken::from_encoded(&URL_SAFE_NO_PAD.encode([7; 32])).unwrap(),
                &[9; 32],
                &Identity::new("host-one").unwrap()
            ),
            Err(Error::InvalidResponse)
        ));
        thread.join().unwrap();
        let (client, thread) = setup(302, serde_json::json!({}));
        assert!(matches!(client.list(), Err(Error::Rejected(302))));
        thread.join().unwrap();
    }
    #[test]
    fn oversized_response_and_transient_failure_are_not_accepted() {
        let (port, pem, thread) = mock(200, vec![b' '; MAX_BODY as usize + 1]);
        let client = MailboxClient::new(
            &format!("https://localhost:{port}"),
            &pem,
            AccessToken::from_encoded(&URL_SAFE_NO_PAD.encode([3; 32])).unwrap(),
        )
        .unwrap();
        assert!(matches!(client.list(), Err(Error::InvalidResponse)));
        thread.join().unwrap();
        let (client, thread) = setup(503, serde_json::json!({}));
        assert!(matches!(
            client.request_grant(&Identity::new("host-one").unwrap(), &[1; 32]),
            Err(Error::Unconfirmed)
        ));
        thread.join().unwrap();
    }
    #[test]
    fn self_view_is_permitted_by_grant_response() {
        let (client, thread) = setup(
            200,
            serde_json::json!({"viewer":"host-one","host":"host-one","viewerFingerprint":"ab".repeat(32),"hostFingerprint":"ab".repeat(32)}),
        );
        let result = client
            .consume_grant(
                GrantToken::from_bytes([7; 32]),
                &[9; 32],
                &Identity::new("host-one").unwrap(),
            )
            .unwrap();
        assert_eq!(result.viewer, result.host);
        thread.join().unwrap();
    }
    #[test]
    fn strict_hostname_and_certificate_rejections() {
        let (port, pem, thread) = mock(200, b"{}".to_vec());
        let client = MailboxClient::new(
            &format!("https://127.0.0.1:{port}"),
            &pem,
            AccessToken::from_encoded(&URL_SAFE_NO_PAD.encode([3; 32])).unwrap(),
        )
        .unwrap();
        assert!(matches!(client.list(), Err(Error::Unconfirmed)));
        thread.join().unwrap();
        let (port, _, thread) = mock(200, b"{}".to_vec());
        let other = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .unwrap()
            .serialize_pem()
            .unwrap();
        let client = MailboxClient::new(
            &format!("https://localhost:{port}"),
            other.as_bytes(),
            AccessToken::from_encoded(&URL_SAFE_NO_PAD.encode([3; 32])).unwrap(),
        )
        .unwrap();
        assert!(matches!(client.list(), Err(Error::Unconfirmed)));
        thread.join().unwrap();
    }
}
