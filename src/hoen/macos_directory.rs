//! Public machine-picker data from the protected macOS viewer enrollment.
use hbb_common::ResultType;
use hoen_mailbox_auth::mailbox::Machine;

#[derive(serde_derive::Serialize)]
struct MachineSummary {
    identity: String,
    display_name: String,
    hosting_enabled: bool,
}

fn response(identity: &str, machines: Vec<Machine>) -> serde_json::Value {
    let machines: Vec<_> = machines.into_iter().map(|machine| MachineSummary {
        identity: machine.identity.as_str().to_owned(),
        display_name: machine.display_name,
        hosting_enabled: machine.hosting_enabled,
    }).collect();
    serde_json::json!({"service_available": true, "identity": identity, "machines": machines})
}

/// This confirms the registry responded, not that a registered host is online.
pub(crate) async fn directory() -> ResultType<String> {
    let runtime = super::runtime::viewer().await?;
    let machines = runtime.mailbox.list().await?;
    Ok(response(runtime.identity.as_str(), machines).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hoen_mailbox_auth::mailbox::{Endpoint, Fingerprint, Identity};

    #[test]
    fn picker_response_contains_only_public_display_fields() {
        let machine = Machine {
            identity: Identity::new("windows").unwrap(),
            display_name: "Area51".into(),
            endpoint: Endpoint::new("192.0.2.4".parse().unwrap(), 42830).unwrap(),
            hosting_enabled: true,
            public_key_fingerprint: Fingerprint::from_bytes([42; 32]),
            updated_at: "2026-11-06T00:00:00Z".into(),
        };
        assert_eq!(response("mac", vec![machine]), serde_json::json!({
            "service_available": true,
            "identity": "mac",
            "machines": [{"identity": "windows", "display_name": "Area51", "hosting_enabled": true}]
        }));
        assert_eq!(response("mac", vec![])["machines"], serde_json::json!([]));
    }
}
