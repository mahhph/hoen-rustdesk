//! Narrow service-side viewer proof construction. The caller must authenticate
//! a local IPC peer and bound requests before calling this module.
use super::runtime::Runtime;
use hbb_common::{anyhow::bail, sodiumoxide::crypto::sign, ResultType};
use hoen_mailbox_auth::{mailbox::Identity, viewer_proof_message};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

#[derive(Clone, Debug, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSummary {
    pub identity: String,
    pub display_name: String,
    pub hosting_enabled: bool,
}

#[derive(Clone, Debug, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryResponse {
    pub identity: String,
    pub machines: Vec<MachineSummary>,
}

pub(crate) async fn directory(runtime: Arc<Runtime>) -> ResultType<DirectoryResponse> {
    let machines = runtime
        .mailbox
        .list()
        .await?
        .into_iter()
        .map(|machine| MachineSummary {
            identity: machine.identity.as_str().to_owned(),
            display_name: machine.display_name,
            hosting_enabled: machine.hosting_enabled,
        })
        .collect();
    Ok(DirectoryResponse {
        identity: runtime.identity.as_str().to_owned(),
        machines,
    })
}

/// A successful response confirms the authenticated broker and registry responded.
/// It does not establish whether any registered host is currently online.
pub(crate) async fn directory_for_viewer() -> ResultType<DirectoryResponse> {
    use crate::ipc::Data;
    use hbb_common::{
        anyhow::anyhow,
        tokio::time::{timeout, Duration},
    };

    let mut connection = crate::ipc::connect_service(3_000).await?;
    // Registry responses are bounded by the mailbox client; allow room for the
    // JSON IPC envelope while still bounding allocation before deserialization.
    connection.set_max_packet_length(256 * 1024);
    timeout(
        Duration::from_secs(3),
        connection.send(&Data::HoenDirectoryRequest),
    )
    .await??;
    match connection.next_timeout(35_000).await? {
        Some(Data::HoenDirectoryResponse(Some(response))) => Ok(response),
        _ => Err(anyhow!("mailbox service directory unavailable")),
    }
}

#[derive(Clone, Debug, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupRequest {
    pub host: String,
}

/// Public registry and socket values only; no mailbox credentials.
#[derive(Clone, Debug, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupResponse {
    pub endpoint: SocketAddr,
    pub host_fingerprint: [u8; 32],
    pub local_address: IpAddr,
    pub viewer_key: [u8; 32],
}

pub(crate) async fn lookup(
    runtime: Arc<Runtime>,
    request: LookupRequest,
) -> ResultType<LookupResponse> {
    let host = Identity::new(&request.host)?;
    let machine = runtime.mailbox.lookup(host.clone()).await?;
    if machine.identity != host || !machine.hosting_enabled {
        bail!("mailbox host unavailable");
    }
    Ok(LookupResponse {
        endpoint: SocketAddr::new(machine.endpoint.address(), machine.endpoint.port()),
        host_fingerprint: *machine.public_key_fingerprint.as_bytes(),
        local_address: runtime.policy.local_address,
        viewer_key: runtime.signing_key.public_key().0,
    })
}

/// An authenticated local caller selects only a registered host and channel binding.
#[derive(Clone, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofRequest {
    pub host: String,
    pub binding: [u8; 32],
}

impl std::fmt::Debug for ProofRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProofRequest([redacted])")
    }
}

/// A one-use grant is sensitive even though the public key and signature are not.
#[derive(Clone, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofResponse {
    pub viewer_key: [u8; 32],
    pub grant_token: [u8; 32],
    // serde does not support arrays of 64 bytes on the project's serde version.
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for ProofResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProofResponse([redacted])")
    }
}

/// This does not authenticate the IPC peer or establish that the binding came
/// from a verified socket. The host independently checks the binding and grant.
pub(crate) async fn issue(
    runtime: Arc<Runtime>,
    request: ProofRequest,
) -> ResultType<ProofResponse> {
    let host = Identity::new(&request.host)?;
    let machine = runtime.mailbox.lookup(host.clone()).await?;
    if machine.identity != host || !machine.hosting_enabled {
        bail!("mailbox host unavailable");
    }
    let grant = runtime.mailbox.issue(host, request.binding).await?;
    let signature = sign::sign_detached(
        &viewer_proof_message(&request.binding, grant.token.as_bytes()),
        &runtime.signing_key,
    );
    Ok(ProofResponse {
        viewer_key: runtime.signing_key.public_key().0,
        grant_token: *grant.token.as_bytes(),
        signature: signature.as_ref().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_ipc_retains_registered_status_and_identity() {
        let response = DirectoryResponse {
            identity: "this-machine".into(),
            machines: vec![MachineSummary {
                identity: "other-machine".into(),
                display_name: "Other machine".into(),
                hosting_enabled: false,
            }],
        };
        let encoded =
            serde_json::to_vec(&crate::ipc::Data::HoenDirectoryResponse(Some(response))).unwrap();
        let decoded: crate::ipc::Data = serde_json::from_slice(&encoded).unwrap();
        match decoded {
            crate::ipc::Data::HoenDirectoryResponse(Some(value)) => {
                assert_eq!(value.identity, "this-machine");
                assert_eq!(value.machines[0].identity, "other-machine");
                assert!(!value.machines[0].hosting_enabled);
            }
            _ => panic!("unexpected IPC response"),
        }
    }

    #[test]
    fn debug_redacts_request_and_proof() {
        let request = ProofRequest {
            host: "sensitive-host".into(),
            binding: [12; 32],
        };
        let proof = ProofResponse {
            viewer_key: [1; 32],
            grant_token: [23; 32],
            signature: vec![42; 64],
        };
        assert_eq!(format!("{request:?}"), "ProofRequest([redacted])");
        assert_eq!(format!("{proof:?}"), "ProofResponse([redacted])");
    }

    #[test]
    fn request_requires_exact_binding_and_no_extra_fields() {
        let valid = serde_json::json!({"host": "test-host", "binding": vec![7; 32]});
        assert!(serde_json::from_value::<ProofRequest>(valid.clone()).is_ok());
        let mut short = valid.clone();
        short["binding"] = serde_json::json!(vec![7; 31]);
        assert!(serde_json::from_value::<ProofRequest>(short).is_err());
        let mut extra = valid;
        extra["viewer"] = serde_json::json!("untrusted-identity");
        assert!(serde_json::from_value::<ProofRequest>(extra).is_err());
    }

    #[test]
    fn lookup_response_roundtrips_in_ipc() {
        let response = LookupResponse {
            endpoint: "192.168.1.2:1234".parse().unwrap(),
            host_fingerprint: [1; 32],
            local_address: "192.168.1.3".parse().unwrap(),
            viewer_key: [2; 32],
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        let decoded: LookupResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.local_address, response.local_address);
        let envelope = crate::ipc::Data::HoenLookupResponse(Some(response));
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let decoded: crate::ipc::Data = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            crate::ipc::Data::HoenLookupResponse(Some(value)) => {
                assert_eq!(value.local_address, "192.168.1.3".parse::<IpAddr>().unwrap());
            }
            _ => panic!("unexpected IPC response"),
        }
    }
}
