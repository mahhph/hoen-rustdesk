//! Blocking HTTPS delivery for persisted history requests. Run on a dedicated worker.
//! Credentials are supplied by the caller and are never persisted or logged here.
use std::{fmt, io::Read, time::Duration};

use reqwest::{
    blocking::Client,
    header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    redirect::Policy,
    Certificate, Url,
};
use uuid::Uuid;

use crate::{Error as OutboxError, Outbox, PendingRequest};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: u64 = 16 * 1024;

/// Mailbox bearer token. Deliberately has no Debug, Display, Clone, or serialization implementation.
pub struct ApiToken(String);
impl ApiToken {
    pub fn new(value: String) -> Result<Self, DeliveryError> {
        if value.len() != 43
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(DeliveryError::InvalidConfiguration);
        }
        Ok(Self(value))
    }
}

#[derive(Debug)]
pub enum DeliveryError {
    InvalidConfiguration,
    InvalidPendingRequest,
    /// Network or transient server failure, or an ambiguous response; retry the same event.
    Retryable,
    /// Do not automatically retry this HTTP status without intervention.
    Permanent(u16),
    /// The server accepted the request, but local state could not be updated.
    Storage(OutboxError),
}
impl fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => f.write_str("invalid mailbox delivery configuration"),
            Self::InvalidPendingRequest => f.write_str("invalid pending history request"),
            Self::Retryable => f.write_str("mailbox delivery is unconfirmed; retry the same event"),
            Self::Permanent(status) => {
                write!(f, "mailbox rejected history delivery with HTTP {status}")
            }
            Self::Storage(_) => f.write_str("history outbox update failed"),
        }
    }
}
impl std::error::Error for DeliveryError {}

/// HTTPS client trusting only the supplied PEM certificate and checking its hostname.
/// Redirects and environment-configured proxies are disabled.
pub struct MailboxDelivery {
    client: Client,
    base: Url,
    token: ApiToken,
}
impl MailboxDelivery {
    pub fn new(base_url: &str, root_pem: &[u8], token: ApiToken) -> Result<Self, DeliveryError> {
        let base = Url::parse(base_url).map_err(|_| DeliveryError::InvalidConfiguration)?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.path() != "/"
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(DeliveryError::InvalidConfiguration);
        }
        let certificate =
            Certificate::from_pem(root_pem).map_err(|_| DeliveryError::InvalidConfiguration)?;
        let client = Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(certificate)
            .redirect(Policy::none())
            .no_proxy()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| DeliveryError::InvalidConfiguration)?;
        Ok(Self {
            client,
            base,
            token,
        })
    }

    /// Submit the session's oldest persisted request. An accepted event is removed
    /// only after validating the response; a failed acknowledgement can be retried.
    pub fn deliver_next(
        &self,
        outbox: &mut Outbox,
        session_id: Uuid,
    ) -> Result<bool, DeliveryError> {
        let Some(pending) = outbox
            .next_request_for_session(session_id)
            .map_err(DeliveryError::Storage)?
        else {
            return Ok(false);
        };
        self.submit(&pending)?;
        outbox
            .acknowledge(session_id, pending.event.event_id())
            .map_err(DeliveryError::Storage)?;
        Ok(true)
    }

    fn submit(&self, pending: &PendingRequest) -> Result<(), DeliveryError> {
        validate_pending(pending)?;
        let url = self
            .base
            .join(&pending.endpoint)
            .map_err(|_| DeliveryError::InvalidPendingRequest)?;
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", self.token.0))
            .map_err(|_| DeliveryError::InvalidConfiguration)?;
        authorization.set_sensitive(true);
        let response = self
            .client
            .post(url)
            .header(AUTHORIZATION, authorization)
            .header(CONTENT_TYPE, "application/json")
            .body(pending.body.clone())
            .send()
            .map_err(|_| DeliveryError::Retryable)?;
        let status = response.status().as_u16();
        classify_status(status)?;
        let mut body = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| DeliveryError::Retryable)?;
        validate_response(status, &body, pending.event.session_id())
    }
}

fn validate_pending(pending: &PendingRequest) -> Result<(), DeliveryError> {
    if pending.endpoint != pending.event.endpoint() || pending.body.len() > 4096 {
        return Err(DeliveryError::InvalidPendingRequest);
    }
    let stored: serde_json::Value =
        serde_json::from_str(&pending.body).map_err(|_| DeliveryError::InvalidPendingRequest)?;
    let expected: serde_json::Value = serde_json::from_str(
        &pending
            .event
            .body()
            .map_err(|_| DeliveryError::InvalidPendingRequest)?,
    )
    .map_err(|_| DeliveryError::InvalidPendingRequest)?;
    if stored != expected {
        return Err(DeliveryError::InvalidPendingRequest);
    }
    Ok(())
}

fn classify_status(status: u16) -> Result<(), DeliveryError> {
    match status {
        200 | 201 => Ok(()),
        408 | 429 | 500..=599 | 200..=299 => Err(DeliveryError::Retryable),
        _ => Err(DeliveryError::Permanent(status)),
    }
}

fn validate_response(status: u16, body: &[u8], session_id: Uuid) -> Result<(), DeliveryError> {
    classify_status(status)?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(DeliveryError::Retryable);
    }
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| DeliveryError::Retryable)?;
    let duplicate = value
        .get("duplicate")
        .and_then(|v| v.as_bool())
        .ok_or(DeliveryError::Retryable)?;
    let reported = value
        .get("session")
        .and_then(|v| v.get("session_id"))
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(DeliveryError::Retryable)?;
    if reported != session_id || duplicate != (status == 200) {
        return Err(DeliveryError::Retryable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Event, MailboxIdentity};

    fn response(id: Uuid, duplicate: bool) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"duplicate":duplicate,"session":{"session_id":id}}))
            .unwrap()
    }
    #[test]
    fn accepts_only_correlated_new_or_duplicate_response() {
        let id = Uuid::new_v4();
        assert!(validate_response(201, &response(id, false), id).is_ok());
        assert!(validate_response(200, &response(id, true), id).is_ok());
        assert!(matches!(
            validate_response(201, &response(id, true), id),
            Err(DeliveryError::Retryable)
        ));
        assert!(matches!(
            validate_response(200, &response(id, false), id),
            Err(DeliveryError::Retryable)
        ));
        assert!(matches!(
            validate_response(200, &response(Uuid::new_v4(), true), id),
            Err(DeliveryError::Retryable)
        ));
        assert!(matches!(
            validate_response(200, b"not json", id),
            Err(DeliveryError::Retryable)
        ));
        assert!(matches!(
            validate_response(200, &vec![b' '; MAX_RESPONSE_BYTES as usize + 1], id),
            Err(DeliveryError::Retryable)
        ));
    }
    #[test]
    fn classifies_responses_and_never_accepts_redirects() {
        for s in [408, 429, 500, 503, 204] {
            assert!(matches!(classify_status(s), Err(DeliveryError::Retryable)));
        }
        for s in [301, 302, 400, 401, 403, 409] {
            assert!(matches!(classify_status(s),Err(DeliveryError::Permanent(n)) if n==s));
        }
    }
    #[test]
    fn rejects_mismatched_request_without_acknowledging() {
        let dir = tempfile::tempdir().unwrap();
        let mut outbox = Outbox::open(&dir.path().join("outbox.db"), 4).unwrap();
        let e = Event::create(MailboxIdentity::new("windows-hoenlenovo").unwrap());
        outbox.enqueue(&e).unwrap();
        let mut p = outbox
            .next_request_for_session(e.session_id())
            .unwrap()
            .unwrap();
        assert!(validate_pending(&p).is_ok());
        p.endpoint = "//elsewhere".into();
        assert!(matches!(
            validate_pending(&p),
            Err(DeliveryError::InvalidPendingRequest)
        ));
        assert_eq!(outbox.pending_count().unwrap(), 1);
    }
    #[test]
    fn configuration_rejects_plain_http_and_invalid_tokens() {
        assert!(ApiToken::new("bad".into()).is_err());
        let token = ApiToken::new("a".repeat(43)).unwrap();
        assert!(matches!(
            MailboxDelivery::new("http://localhost", b"invalid", token),
            Err(DeliveryError::InvalidConfiguration)
        ));
    }
    fn mock_tls(body: Vec<u8>) -> (u16, Vec<u8>, std::thread::JoinHandle<()>) {
        use std::{io::Write, net::TcpListener, sync::Arc};
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = cert.serialize_pem().unwrap().into_bytes();
        let tls = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::Certificate(cert.serialize_der().unwrap())],
                rustls::PrivateKey(cert.serialize_private_key_der()),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let thread = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let conn = rustls::ServerConnection::new(Arc::new(tls)).unwrap();
            let mut stream = rustls::StreamOwned::new(conn, socket);
            let mut request = Vec::new();
            loop {
                let mut chunk = [0; 4096];
                let n = match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                request.extend_from_slice(&chunk[..n]);
                if request.len() > 8192 {
                    return;
                }
                if let Some(pos) = request.windows(4).position(|x| x == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..pos]);
                    let size = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|s| s.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if request.len() >= pos + 4 + size {
                        break;
                    }
                }
            }
            let header = format!("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        });
        (port, pem, thread)
    }
    #[test]
    fn local_tls_requires_matching_name_and_acknowledges_only_correlated_response() {
        let dir = tempfile::tempdir().unwrap();
        let mut outbox = Outbox::open(&dir.path().join("outbox.db"), 4).unwrap();
        let event = Event::create(MailboxIdentity::new("windows-hoenlenovo").unwrap());
        outbox.enqueue(&event).unwrap();
        let (port, pem, server) = mock_tls(response(Uuid::new_v4(), false));
        let client = MailboxDelivery::new(
            &format!("https://localhost:{port}"),
            &pem,
            ApiToken::new("a".repeat(43)).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            client.deliver_next(&mut outbox, event.session_id()),
            Err(DeliveryError::Retryable)
        ));
        server.join().unwrap();
        assert_eq!(outbox.pending_count().unwrap(), 1);
        let (port, pem, server) = mock_tls(response(event.session_id(), false));
        let client = MailboxDelivery::new(
            &format!("https://127.0.0.1:{port}"),
            &pem,
            ApiToken::new("a".repeat(43)).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            client.deliver_next(&mut outbox, event.session_id()),
            Err(DeliveryError::Retryable)
        ));
        server.join().unwrap();
        assert_eq!(outbox.pending_count().unwrap(), 1);
        let (port, _actual_pem, server) = mock_tls(response(event.session_id(), false));
        let other_pem = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .unwrap()
            .serialize_pem()
            .unwrap();
        let client = MailboxDelivery::new(
            &format!("https://localhost:{port}"),
            other_pem.as_bytes(),
            ApiToken::new("a".repeat(43)).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            client.deliver_next(&mut outbox, event.session_id()),
            Err(DeliveryError::Retryable)
        ));
        server.join().unwrap();
        assert_eq!(outbox.pending_count().unwrap(), 1);
        let (port, pem, server) = mock_tls(response(event.session_id(), false));
        let client = MailboxDelivery::new(
            &format!("https://localhost:{port}"),
            &pem,
            ApiToken::new("a".repeat(43)).unwrap(),
        )
        .unwrap();
        assert!(client
            .deliver_next(&mut outbox, event.session_id())
            .unwrap());
        server.join().unwrap();
        assert_eq!(outbox.pending_count().unwrap(), 0);
    }
}
