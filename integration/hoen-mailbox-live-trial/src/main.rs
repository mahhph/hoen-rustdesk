//! Opt-in, hard-scoped disposable mailbox trial. Never use a live credential.
use hoen_mailbox_auth::mailbox::{AccessToken, Fingerprint, GrantToken, Identity, MailboxClient};
use hoen_mailbox_history::{
    delivery::{ApiToken, MailboxDelivery},
    Event, MailboxIdentity, Outbox, Reason,
};
use reqwest::{
    blocking::Client,
    header::{HeaderValue, AUTHORIZATION},
    redirect::Policy,
    Certificate,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{self, Read},
    time::Duration,
};
use zeroize::Zeroizing;

const TRIAL_URL: &str = "https://192.168.1.24:42829";
const TRIAL_ID: &str = "windows-hoenlenovo";
const CA_SHA256: &str = "65c80becee8b9ef3cbb00baeb96cf4ee524206017f21a5338072e97083c83696";

fn ca_check(pem: &[u8]) -> Result<(), &'static str> {
    let mut reader = io::Cursor::new(pem);
    let certs = rustls_pemfile::certs(&mut reader).map_err(|_| "invalid trial CA")?;
    if certs.len() != 1 {
        return Err("invalid trial CA");
    }
    let digest = Sha256::digest(&certs[0]);
    let hex: String = digest.iter().map(|x| format!("{x:02x}")).collect();
    if hex != CA_SHA256 {
        return Err("trial CA fingerprint mismatch");
    }
    Ok(())
}
fn event_ids(events: &Value, expected: &[(&str, String)]) -> Result<(), &'static str> {
    let rows = events
        .get("events")
        .and_then(Value::as_array)
        .ok_or("invalid history response")?;
    if rows.len() != expected.len() {
        return Err("unexpected history event count");
    }
    for (row, (kind, id)) in rows.iter().zip(expected) {
        if row.get("type").and_then(Value::as_str) != Some(*kind)
            || row.get("event_id").and_then(Value::as_str) != Some(id.as_str())
            || row.get("actor").and_then(Value::as_str) != Some(TRIAL_ID)
        {
            return Err("history event mismatch");
        }
    }
    Ok(())
}
fn history(client: &Client, token: &str, session: &str) -> Result<Value, &'static str> {
    let mut authorization =
        HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| "invalid credential")?;
    authorization.set_sensitive(true);
    let response = client
        .get(format!(
            "{TRIAL_URL}/v1/remote-sessions/{session}/events?limit=10"
        ))
        .header(AUTHORIZATION, authorization)
        .send()
        .map_err(|_| "history request failed")?;
    if response.status().as_u16() != 200 {
        return Err("history request rejected");
    }
    let mut bytes = Vec::new();
    response
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "history read failed")?;
    if bytes.len() > 65536 {
        return Err("history response too large");
    }
    serde_json::from_slice(&bytes).map_err(|_| "invalid history response")
}
fn run(url: &str, ca: &[u8], bearer: &str) -> Result<(), &'static str> {
    if url.trim_end_matches('/') != TRIAL_URL {
        return Err("endpoint is not the isolated trial");
    }
    ca_check(ca)?;
    let auth = AccessToken::from_encoded(bearer).map_err(|_| "invalid trial credential")?;
    let mailbox =
        MailboxClient::new(TRIAL_URL, ca, auth).map_err(|_| "mailbox client setup failed")?;
    let actor = Identity::new(TRIAL_ID).map_err(|_| "invalid trial identity")?;
    let machines = mailbox
        .list()
        .map_err(|_| "authenticated registry listing failed")?;
    let own = machines
        .iter()
        .find(|m| m.identity == actor)
        .ok_or("synthetic trial registry row missing")?;
    if own.public_key_fingerprint
        != Fingerprint::parse(&"c".repeat(64)).map_err(|_| "invalid fixture")?
        || own.endpoint.address().to_string() != "192.168.1.24"
        || own.endpoint.port() != 49999
    {
        return Err("synthetic trial registry row mismatch");
    }
    println!("Authenticated registry listing and synthetic row verified.");
    // This tests only the synthetic mailbox API; no desktop key proof or network session exists.
    let binding = [0xa5; 32];
    let grant = mailbox
        .request_grant(&actor, &binding)
        .map_err(|_| "synthetic grant issuance failed")?;
    let mut raw = Zeroizing::new(*grant.token.as_bytes());
    let result = mailbox
        .consume_grant(grant.token, &binding, &actor)
        .map_err(|_| "synthetic grant consumption failed")?;
    if result.viewer != actor
        || result.host != actor
        || result.viewer_fingerprint != own.public_key_fingerprint
        || result.host_fingerprint != own.public_key_fingerprint
    {
        return Err("synthetic grant metadata mismatch");
    }
    if !matches!(
        mailbox.consume_grant(GrantToken::from_bytes(*raw), &binding, &actor),
        Err(hoen_mailbox_auth::mailbox::Error::Rejected(403))
    ) {
        return Err("synthetic grant replay was not rejected");
    }
    raw.fill(0);
    println!("Synthetic grant consumption and replay rejection verified; no desktop authentication was tested.");
    let delivery = MailboxDelivery::new(
        TRIAL_URL,
        ca,
        ApiToken::new(bearer.to_owned()).map_err(|_| "invalid trial credential")?,
    )
    .map_err(|_| "history client setup failed")?;
    let dir = tempfile::tempdir().map_err(|_| "temporary outbox unavailable")?;
    let mut first = Outbox::open(&dir.path().join("first.sqlite"), 8)
        .map_err(|_| "temporary outbox unavailable")?;
    let mut retry = Outbox::open(&dir.path().join("retry.sqlite"), 8)
        .map_err(|_| "temporary outbox unavailable")?;
    let start =
        Event::create(MailboxIdentity::new(TRIAL_ID).map_err(|_| "invalid trial identity")?);
    let beat = Event::heartbeat(start.session_id());
    let end = Event::ended(start.session_id(), Reason::Normal);
    let session = start.session_id().to_string();
    println!("Synthetic trial session: {session}");
    let mut start_confirmed = false;
    let result = (|| -> Result<(), &'static str> {
        for event in [&start, &beat, &end] {
            first
                .enqueue(event)
                .map_err(|_| "first outbox enqueue failed")?;
            retry
                .enqueue(event)
                .map_err(|_| "retry outbox enqueue failed")?;
            delivery
                .deliver_next(&mut first, event.session_id())
                .map_err(|_| "first history delivery unconfirmed")?;
            if event.event_id() == start.event_id() {
                start_confirmed = true;
            }
            delivery
                .deliver_next(&mut retry, event.session_id())
                .map_err(|_| "retry history delivery unconfirmed")?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        // A lost create response may still mean the create committed. Retry its
        // identical local intent once, then make a best-effort terminal report.
        if !start_confirmed
            && matches!(first.next_for_session(start.session_id()), Ok(Some(ref event)) if event.event_id() == start.event_id())
        {
            start_confirmed = matches!(
                delivery.deliver_next(&mut first, start.session_id()),
                Ok(true)
            );
        }
        if start_confirmed {
            while matches!(first.next_for_session(start.session_id()), Ok(Some(_))) {
                if !matches!(
                    delivery.deliver_next(&mut first, start.session_id()),
                    Ok(true)
                ) {
                    break;
                }
            }
            let failed = Event::failed(start.session_id(), Reason::HostError);
            if first.enqueue(&failed).is_ok() {
                let _ = delivery.deliver_next(&mut first, start.session_id());
            }
        }
        eprintln!(
            "Synthetic session {session} may need reconciliation; a missing end remains unknown."
        );
        return Err(error);
    }
    let cert = Certificate::from_pem(ca).map_err(|_| "invalid trial CA")?;
    let get = Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(cert)
        .redirect(Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| "history reader setup failed")?;
    let events = history(&get, bearer, &session)?;
    event_ids(
        &events,
        &[
            ("connected", start.event_id().to_string()),
            ("heartbeat", beat.event_id().to_string()),
            ("ended", end.event_id().to_string()),
        ],
    )?;
    println!("Synthetic history create, heartbeat, end and identical-ID retries verified; exactly three events stored.");
    Ok(())
}
fn main() {
    let args: Vec<_> = env::args_os().collect();
    if args.len() != 3 {
        eprintln!(
            "Usage: hoen-mailbox-live-trial TRIAL_HTTPS_URL PUBLIC_CA_PEM < protected-token-stream"
        );
        std::process::exit(2);
    }
    let Some(url) = args[1].to_str() else {
        eprintln!("invalid endpoint");
        std::process::exit(2)
    };
    let ca = match fs::read(&args[2]) {
        Ok(v) if v.len() <= 16384 => v,
        _ => {
            eprintln!("invalid CA file");
            std::process::exit(2)
        }
    };
    // Validate the target and CA before receiving a credential or making requests.
    if url.trim_end_matches('/') != TRIAL_URL || ca_check(&ca).is_err() {
        eprintln!("trial endpoint or CA verification failed");
        std::process::exit(2);
    }
    let mut input = Zeroizing::new(String::new());
    if io::stdin().take(257).read_to_string(&mut input).is_err() || input.len() > 256 {
        eprintln!("invalid credential input");
        std::process::exit(2)
    }
    let bearer = input.trim_end_matches(['\r', '\n']);
    if let Err(error) = run(url, &ca, bearer) {
        eprintln!("Trial failed: {error}");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_requires_exact_ids_types_and_no_duplicates() {
        let rows = serde_json::json!({"events":[{"type":"connected","event_id":"a","actor":TRIAL_ID},{"type":"ended","event_id":"b","actor":TRIAL_ID}]});
        assert!(event_ids(&rows, &[("connected", "a".into()), ("ended", "b".into())]).is_ok());
        assert!(event_ids(&rows, &[("connected", "a".into())]).is_err());
        assert!(event_ids(
            &rows,
            &[("connected", "a".into()), ("ended", "wrong".into())]
        )
        .is_err());
    }
    #[test]
    fn untrusted_ca_and_wrong_target_are_rejected_before_input() {
        assert!(ca_check(b"not a certificate").is_err());
        assert!(run("https://localhost:42829", b"bad", "bad").is_err());
    }
}
