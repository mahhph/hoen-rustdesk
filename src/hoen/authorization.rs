use super::{handshake::VerifiedChannel, mailbox_worker::MailboxWorker};
use base::message_proto::{login_request, HoenProof, LoginRequest};
use hbb_common::{anyhow::bail, sodiumoxide::crypto::sign, ResultType};
use hoen_mailbox_auth::{
    mailbox::{ConsumedGrant, GrantToken, Identity},
    verify_viewer_proof, viewer_proof_message,
};
use sha2::{Digest, Sha256};

/// A proof has no authority on the legacy connection path. Only a connection
/// carrying its own verified Hoen transport may consume one.
pub(crate) fn reject_legacy_proof(login: &LoginRequest) -> ResultType<()> {
    if login.hoen_proof.is_some() {
        bail!("mailbox proof requires an authenticated mailbox transport");
    }
    Ok(())
}

/// Session kinds supported by the authenticated Hoen transport. File access
/// still requires the host's existing effective file-transfer permission.
pub(crate) fn login_scope_allowed(login: &LoginRequest, file_permission: bool) -> bool {
    match login.union.as_ref() {
        None => true,
        Some(login_request::Union::FileTransfer(_)) => file_permission,
        Some(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_login_allows_desktop_and_permitted_files_only() {
        use base::message_proto::{FileTransfer, PortForward, Terminal, ViewCamera};
        let mut login = LoginRequest::new();
        assert!(login_scope_allowed(&login, false));
        login.set_file_transfer(FileTransfer::new());
        assert!(login_scope_allowed(&login, true));
        assert!(!login_scope_allowed(&login, false));
        login.set_view_camera(ViewCamera::new());
        assert!(!login_scope_allowed(&login, true));
        login.set_terminal(Terminal::new());
        assert!(!login_scope_allowed(&login, true));
        login.set_port_forward(PortForward::new());
        assert!(!login_scope_allowed(&login, true));
    }

    #[test]
    fn legacy_login_rejects_mailbox_proof_even_with_password() {
        let mut login = LoginRequest::new();
        login.password = vec![1, 2, 3].into();
        login.hoen_proof = Some(HoenProof::new()).into();
        assert!(reject_legacy_proof(&login).is_err());

        login.hoen_proof = None.into();
        assert!(reject_legacy_proof(&login).is_ok());
    }
}

/// Called after the viewer verifies the host handshake and key confirmation.
pub(crate) async fn issue_proof(
    mailbox: &MailboxWorker,
    host: &Identity,
    channel: &VerifiedChannel,
    key: &sign::SecretKey,
) -> ResultType<HoenProof> {
    let grant = mailbox.issue(host.clone(), channel.binding).await?;
    let signature = sign::sign_detached(
        &viewer_proof_message(&channel.binding, grant.token.as_bytes()),
        key,
    );
    Ok(HoenProof {
        viewer_key: key.public_key().0.to_vec().into(),
        grant_token: grant.token.as_bytes().to_vec().into(),
        signature: signature.as_ref().to_vec().into(),
        ..Default::default()
    })
}

/// Runs once for this encrypted connection. Callers must
/// cache only success on that connection and close it on any error/ambiguity.
/// The return value establishes identity, not successful desktop initialization.
pub(crate) async fn consume_proof(
    mailbox: &MailboxWorker,
    local_identity: &Identity,
    channel: &VerifiedChannel,
    proof: &HoenProof,
) -> ResultType<ConsumedGrant> {
    let viewer_key: [u8; 32] = proof.viewer_key.as_ref().try_into()?;
    let token: [u8; 32] = proof.grant_token.as_ref().try_into()?;
    let signature: [u8; 64] = proof.signature.as_ref().try_into()?;
    let viewer_pin: [u8; 32] = Sha256::digest(viewer_key).into();
    // Check possession before spending a grant; trust in this pin comes only
    // from the independent mailbox consumption response below.
    verify_viewer_proof(
        &viewer_key,
        &signature,
        &channel.binding,
        &token,
        &viewer_pin,
    )?;
    let consumed = mailbox
        .consume(
            local_identity.clone(),
            GrantToken::from_bytes(token),
            channel.binding,
        )
        .await?;
    let host_pin: [u8; 32] = Sha256::digest(channel.host_key).into();
    if consumed.host != *local_identity
        || consumed.host_fingerprint.as_bytes() != &host_pin
        || consumed.viewer_fingerprint.as_bytes() != &viewer_pin
    {
        bail!("mailbox grant identity mismatch");
    }
    Ok(consumed)
}
