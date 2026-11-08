//! Public configuration metadata. Parsing does not authorize activation or resolve secrets.
use super::lan_contract::{ErrorCode, Role, Validate, MAX_COUNTER};
use hoen_mailbox_auth::mailbox::Identity;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct MachineConfig {
    pub schema_version: u32,
    pub revision: u64,
    pub identity: String,
    pub alias: String,
    pub role: Role,
    pub mailbox_url: String,
    pub trust: Trust,
    pub credential_ref: String,
    pub signing_key_ref: String,
    pub listen_port: u16,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "mode", deny_unknown_fields)]
pub(crate) enum Trust {
    #[serde(rename = "leaf_pin")]
    LeafPin {
        #[serde(rename = "bundleRef")]
        bundle_ref: String,
        #[serde(rename = "leafSha256")]
        leaf_sha256: String,
    },
    #[serde(rename = "application_ca")]
    ApplicationCa {
        #[serde(rename = "bundleRef")]
        bundle_ref: String,
        #[serde(rename = "bundleSha256")]
        bundle_sha256: String,
    },
}

fn reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Validate for MachineConfig {
    fn validate(&self) -> Result<(), ErrorCode> {
        if self.schema_version != 1 {
            return Err(ErrorCode::UnsupportedVersion);
        }
        let url = url::Url::parse(&self.mailbox_url).map_err(|_| ErrorCode::InvalidRequest)?;
        let trust_valid = match &self.trust {
            Trust::LeafPin {
                bundle_ref,
                leaf_sha256,
            } => reference(bundle_ref) && digest(leaf_sha256),
            Trust::ApplicationCa {
                bundle_ref,
                bundle_sha256,
            } => reference(bundle_ref) && digest(bundle_sha256),
        };
        if !(1..=MAX_COUNTER).contains(&self.revision)
            || Identity::new(&self.identity).is_err()
            || self.alias.is_empty()
            || self.alias.len() > 64
            || self.alias.trim() != self.alias
            || !self.alias.bytes().all(|b| (0x20..=0x7e).contains(&b))
            || self.mailbox_url.len() > 512
            || self.mailbox_url.trim() != self.mailbox_url
            || self.mailbox_url.chars().any(char::is_control)
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || self.mailbox_url.contains('\\')
            || url.port_or_known_default() == Some(0)
            || !reference(&self.credential_ref)
            || !reference(&self.signing_key_ref)
            || self.listen_port == 0
            || !trust_valid
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::lan_contract::parse;
    use super::*;
    use serde_json::{json, Value};

    fn fixture() -> Value {
        serde_json::from_str::<Value>(include_str!(
            "../../contracts/lan-v2/config-and-migration.json"
        ))
        .unwrap()["configuration"]
            .clone()
    }

    #[test]
    fn metadata_roundtrips_both_explicit_trust_modes() {
        let mut value = fixture();
        for trust in [
            value["trust"].clone(),
            json!({"mode":"leaf_pin", "bundleRef":"legacy-cert", "leafSha256":"a".repeat(64)}),
        ] {
            value["trust"] = trust;
            let parsed: MachineConfig = parse(&serde_json::to_vec(&value).unwrap()).unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), value);
        }
    }

    #[test]
    fn rejects_ambiguous_or_credential_bearing_configuration_without_echoing_input() {
        for (key, bad) in [
            ("schemaVersion", json!(2)),
            ("revision", json!(0)),
            ("revision", json!(MAX_COUNTER + 1)),
            ("role", json!("admin")),
            ("identity", json!("bad/identity")),
            ("alias", json!(" Lenovo")),
            ("credentialRef", json!("../credential")),
            ("signingKeyRef", json!("C:\\key")),
            ("accessToken", json!("secret-marker")),
            ("listenPort", json!(0)),
            ("mailboxUrl", json!("http://192.168.1.9:42819")),
            (
                "mailboxUrl",
                json!("https://user:secret-marker@192.168.1.9:42819"),
            ),
            ("mailboxUrl", json!("https://192.168.1.9/path")),
            (
                "mailboxUrl",
                json!("https://192.168.1.9/?token=secret-marker"),
            ),
            ("mailboxUrl", json!("https://192.168.1.9/#secret-marker")),
            ("trust", json!({"mode":"insecure"})),
            (
                "trust",
                json!({"mode":"application_ca","bundleRef":"root","bundleSha256":"a".repeat(64),"leafSha256":"a".repeat(64)}),
            ),
        ] {
            let mut value = fixture();
            value[key] = bad;
            let result = parse::<MachineConfig>(&serde_json::to_vec(&value).unwrap());
            assert!(result.is_err(), "accepted invalid field {key}");
            let error = result.err().unwrap();
            assert!(!format!("{error:?}").contains("secret-marker"));
        }
    }
}
