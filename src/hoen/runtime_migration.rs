//! Migration preparation is separate from activation. Never write or re-enroll on read.
use super::{parse, Enrollment};
use crate::hoen::{
    credentials::Secret,
    lan_contract::{self, Role, MAX_COUNTER},
    machine_config::{MachineConfig, Trust},
};
use hbb_common::{
    anyhow::{anyhow, bail},
    ResultType,
};
use sha2::{Digest, Sha256};

const CREDENTIAL: &str = "existing-machine-credential";
const SIGNING_KEY: &str = "existing-machine-key";
const BUNDLE: &str = "mailbox-trust-v1";

fn metadata(enrollment: &Enrollment, revision: u64) -> ResultType<MachineConfig> {
    if enrollment.display_name.is_empty()
        || enrollment.display_name.len() > 64
        || enrollment.display_name.trim() != enrollment.display_name
        || !enrollment
            .display_name
            .bytes()
            .all(|b| (0x20..=0x7e).contains(&b))
    {
        bail!("existing alias requires manual review before migration");
    }
    let trust = match &enrollment.mailbox_leaf_fingerprint {
        Some(pin) => Trust::LeafPin {
            bundle_ref: BUNDLE.into(),
            leaf_sha256: super::Fingerprint::parse(pin)?.to_hex(),
        },
        None => Trust::ApplicationCa {
            bundle_ref: BUNDLE.into(),
            bundle_sha256: super::Fingerprint::from_bytes(
                Sha256::digest(enrollment.mailbox_ca_pem.as_bytes()).into(),
            )
            .to_hex(),
        },
    };
    Ok(MachineConfig {
        schema_version: 1,
        revision,
        identity: enrollment.identity.clone(),
        alias: enrollment.display_name.clone(),
        role: if enrollment.hosting_enabled {
            Role::Both
        } else {
            Role::Client
        },
        mailbox_url: enrollment.mailbox_url.clone(),
        trust,
        credential_ref: CREDENTIAL.into(),
        signing_key_ref: SIGNING_KEY.into(),
        listen_port: enrollment.listen_port,
    })
}

pub(super) fn validate_binding(enrollment: &Enrollment, config: &MachineConfig) -> ResultType<()> {
    // Use the same bounded parser as an external metadata request; no raw values in errors.
    let bytes = serde_json::to_vec(config).map_err(|_| anyhow!("invalid machine configuration"))?;
    let _: MachineConfig =
        lan_contract::parse(&bytes).map_err(|_| anyhow!("invalid machine configuration"))?;
    if *config != metadata(enrollment, config.revision)? {
        bail!("machine configuration conflicts with protected enrollment");
    }
    reqwest::Certificate::from_pem(enrollment.mailbox_ca_pem.as_bytes())
        .map_err(|_| anyhow!("invalid protected trust material"))?;
    if let Some(pin) = &enrollment.mailbox_leaf_fingerprint {
        if super::bootstrap_certificate_fingerprint(&enrollment.mailbox_ca_pem)?
            != super::Fingerprint::parse(pin)?
        {
            bail!("protected certificate does not match its pin");
        }
    }
    Ok(())
}

/// Return a sealed-store input, never plaintext output or a new identity. Caller owns
/// backup, exclusive activation, trust probes, read-back verification and rollback.
pub(crate) fn prepare(secret: &Secret, expected_revision: u64) -> ResultType<Secret> {
    let mut enrollment = parse(secret.expose())?;
    let current = enrollment
        .machine_config
        .as_ref()
        .map_or(0, |config| config.revision);
    if current != expected_revision || current >= MAX_COUNTER {
        bail!("machine configuration revision conflict");
    }
    let config = metadata(&enrollment, current + 1)?;
    validate_binding(&enrollment, &config)?;
    enrollment.machine_config = Some(config);
    Secret::new(serde_json::to_vec(&enrollment)?)
        .map_err(|_| anyhow!("prepared enrollment exceeds protected-store limits"))
}

/// Read the existing role entry only. No provisioning, store write, or activation.
#[cfg(target_os = "macos")]
pub(crate) fn preflight_mac(
    purpose: crate::hoen::credentials::Purpose,
    expected_revision: u64,
) -> ResultType<String> {
    use crate::hoen::credentials::{CredentialStore, MacStore};
    let store = MacStore::for_user(purpose)
        .map_err(|_| anyhow!("user Keychain unavailable for configuration preflight"))?;
    let original = store.read()
        .map_err(|_| anyhow!("protected enrollment unavailable for configuration preflight"))?;
    let prepared = prepare(&original, expected_revision)?;
    let candidate = parse(prepared.expose())?;
    if purpose == crate::hoen::credentials::Purpose::HostService && !candidate.hosting_enabled {
        bail!("protected host enrollment has incompatible role");
    }
    let (public, _) = super::sign::keypair_from_seed(&super::sign::Seed(candidate.signing_seed));
    let fingerprint = super::Fingerprint::from_bytes(Sha256::digest(public.0).into()).to_hex();
    Ok(serde_json::json!({
        "status":"prepared_in_memory_only", "currentRevision":expected_revision,
        "proposedConfiguration":candidate.machine_config.as_ref(),
        "publicKeyFingerprint":fingerprint,
        "activationReady":false, "authenticatedMailboxVerified":false
    }).to_string())
}

#[cfg(windows)]
pub(crate) fn preflight_host() -> ResultType<String> {
    use crate::hoen::credentials::{CredentialStore, ProtectedStore, Purpose};
    // Deliberately avoid load_host_enrollment: it can provision/finalize bootstrap.
    let store = ProtectedStore::open(
        &super::directory(Purpose::HostService)?,
        Purpose::HostService,
    )
    .map_err(|_| anyhow!("protected service enrollment unavailable"))?;
    let original = store
        .read()
        .map_err(|_| anyhow!("protected service enrollment cannot be read"))?;
    let enrollment = parse(original.expose())?;
    let current = enrollment
        .machine_config
        .as_ref()
        .map_or(0, |config| config.revision);
    let prepared = prepare(&original, current)?;
    let candidate = parse(prepared.expose())?;
    let (public, _) = super::sign::keypair_from_seed(&super::sign::Seed(enrollment.signing_seed));
    let fingerprint = super::Fingerprint::from_bytes(Sha256::digest(public.0).into()).to_hex();
    Ok(serde_json::json!({
        "status":"prepared_in_memory_only", "currentRevision":current,
        "proposedConfiguration":candidate.machine_config.as_ref(),
        "publicKeyFingerprint":fingerprint,
        "activationReady":false, "authenticatedMailboxVerified":false
    })
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn original() -> Secret {
        let mut value = serde_json::json!({
            "schema_version":1,"identity":"test-viewer","display_name":"Test viewer",
            "mailbox_url":"https://192.168.1.2:42819/",
            "access_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "signing_seed":vec![7u8;32],"local_address":"192.168.1.3",
            "listen_port":42830,"hosting_enabled":false
        });
        let certificate = include_str!("../../libs/hbb_common/tests/data/websocket-cert.pem");
        value["mailbox_ca_pem"] = certificate.into();
        value["mailbox_leaf_fingerprint"] =
            super::super::bootstrap_certificate_fingerprint(certificate)
                .unwrap()
                .to_hex()
                .into();
        Secret::new(serde_json::to_vec(&value).unwrap()).unwrap()
    }
    #[test]
    fn preparation_preserves_credentials_and_original_and_is_deterministic() {
        let original = original();
        let before = parse(original.expose()).unwrap();
        let prepared = prepare(&original, 0).unwrap();
        let mut after = parse(prepared.expose()).unwrap();
        assert_eq!(after.machine_config.take().unwrap().revision, 1);
        assert!(after == before);
        assert!(parse(original.expose()).unwrap().machine_config.is_none());
        assert_eq!(prepare(&original, 0).unwrap().expose(), prepared.expose());
        assert!(prepare(&prepared, 0).is_err());
        assert_eq!(
            parse(prepare(&prepared, 1).unwrap().expose())
                .unwrap()
                .machine_config
                .as_ref()
                .unwrap()
                .revision,
            2
        );
    }
    #[test]
    fn runtime_rejects_conflicting_metadata_instead_of_using_a_second_authority() {
        let prepared = prepare(&original(), 0).unwrap();
        let value: serde_json::Value = serde_json::from_slice(prepared.expose()).unwrap();
        for (field, replacement) in [
            ("identity", serde_json::json!("different-machine")),
            (
                "mailboxUrl",
                serde_json::json!("https://192.168.1.8:42819/"),
            ),
            ("credentialRef", serde_json::json!("other-credential")),
            ("role", serde_json::json!("both")),
            ("alias", serde_json::json!("Other alias")),
            ("revision", serde_json::json!(0)),
        ] {
            let mut changed = value.clone();
            changed["machine_config"][field] = replacement;
            assert!(parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let mut changed = value;
        changed["machine_config"]["trust"]["mode"] = "application_ca".into();
        assert!(parse(&serde_json::to_vec(&changed).unwrap()).is_err());
    }

    #[test]
    fn migration_preserves_existing_ca_mode_and_rejects_changed_trust() {
        let original = original();
        let mut value: serde_json::Value = serde_json::from_slice(original.expose()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("mailbox_leaf_fingerprint");
        let ca_original = Secret::new(serde_json::to_vec(&value).unwrap()).unwrap();
        let prepared = prepare(&ca_original, 0).unwrap();
        let migrated = parse(prepared.expose()).unwrap();
        assert!(migrated.mailbox_leaf_fingerprint.is_none());
        assert!(matches!(
            migrated.machine_config.as_ref().unwrap().trust,
            Trust::ApplicationCa { .. }
        ));
        let mut changed: serde_json::Value = serde_json::from_slice(prepared.expose()).unwrap();
        changed["machine_config"]["trust"]["bundleSha256"] = "a".repeat(64).into();
        assert!(parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        value["mailbox_ca_pem"] = "not a certificate".into();
        let invalid = Secret::new(serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(prepare(&invalid, 0).is_err());
    }

    #[test]
    fn migration_rejects_a_leaf_that_no_longer_matches_its_existing_pin() {
        let original = original();
        let mut value: serde_json::Value = serde_json::from_slice(original.expose()).unwrap();
        value["mailbox_leaf_fingerprint"] = "b".repeat(64).into();
        let mismatched = Secret::new(serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(prepare(&mismatched, 0).is_err());
    }

    #[test]
    fn unsupported_legacy_alias_reports_review_without_changing_enrollment() {
        let original = original();
        let mut value: serde_json::Value = serde_json::from_slice(original.expose()).unwrap();
        for name in ["Mac é".to_owned(), "x".repeat(65)] {
            value["display_name"] = name.into();
            let legacy = Secret::new(serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(parse(legacy.expose()).is_ok());
            let result = prepare(&legacy, 0);
            assert_eq!(
                result.err().unwrap().to_string(),
                "existing alias requires manual review before migration"
            );
            assert!(parse(legacy.expose()).unwrap().machine_config.is_none());
        }
    }
}
