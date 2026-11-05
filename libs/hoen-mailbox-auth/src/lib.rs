//! Cryptographic encodings from the proposed Hoen mailbox authentication contract.
//!
//! This library does not authenticate a transport or grant. Callers must obtain
//! the inputs from a successfully verified native TCP handshake, verify the host
//! key against the mailbox pin, and perform the separate grant-consumption checks.
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const CHANNEL_DOMAIN: &[u8] = b"hoen-mailbox-channel/v1";
const PROOF_DOMAIN: &[u8] = b"hoen-mailbox-viewer-proof/v1";
pub const PROOF_MESSAGE_BYTES: usize = PROOF_DOMAIN.len() + 1 + 32 + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedVersion,
    InvalidViewerKey,
    ViewerPinMismatch,
    InvalidSignature,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnsupportedVersion => "unsupported key exchange version",
            Self::InvalidViewerKey => "invalid viewer public key",
            Self::ViewerPinMismatch => "viewer public key does not match enrolled pin",
            Self::InvalidSignature => "invalid viewer proof signature",
        })
    }
}
impl std::error::Error for Error {}

/// Compute the binary channel binding from the two verified handshake views.
/// This checks version encoding only; it does not prove that the host key,
/// ephemeral keys or underlying transport were authenticated.
pub fn channel_binding(
    host_key: &[u8; 32],
    initiator_key: &[u8; 32],
    responder_key: &[u8; 32],
    advertised: u32,
    selected: u32,
) -> Result<[u8; 32], Error> {
    if advertised != 1 || selected != 1 {
        return Err(Error::UnsupportedVersion);
    }
    let mut hash = Sha256::new();
    hash.update(CHANNEL_DOMAIN);
    hash.update([0]);
    hash.update(host_key);
    hash.update(initiator_key);
    hash.update(responder_key);
    hash.update(advertised.to_be_bytes());
    hash.update(selected.to_be_bytes());
    Ok(hash.finalize().into())
}

/// The exact binary message signed by the viewer. Token must already be decoded
/// from canonical unpadded base64url into 32 bytes by the caller. Never log it.
pub fn viewer_proof_message(binding: &[u8; 32], token: &[u8; 32]) -> [u8; PROOF_MESSAGE_BYTES] {
    let mut out = [0; PROOF_MESSAGE_BYTES];
    let start = PROOF_DOMAIN.len();
    out[..start].copy_from_slice(PROOF_DOMAIN);
    // The zero initialized byte at `start` is the domain separator.
    out[start + 1..start + 33].copy_from_slice(binding);
    out[start + 33..].copy_from_slice(&Sha256::digest(token));
    out
}

/// Verify the detached viewer proof and its enrolled SHA-256 public-key pin.
/// This does not consume a grant or establish that the supplied pin is trusted.
pub fn verify_viewer_proof(
    viewer_key: &[u8; 32],
    signature: &[u8; 64],
    binding: &[u8; 32],
    token: &[u8; 32],
    expected_pin: &[u8; 32],
) -> Result<(), Error> {
    let actual_pin: [u8; 32] = Sha256::digest(viewer_key).into();
    if &actual_pin != expected_pin {
        return Err(Error::ViewerPinMismatch);
    }
    let key = VerifyingKey::from_bytes(viewer_key).map_err(|_| Error::InvalidViewerKey)?;
    let signature = Signature::from_bytes(signature);
    key.verify_strict(&viewer_proof_message(binding, token), &signature)
        .map_err(|_| Error::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // Independently calculated with Node's crypto.createHash over explicit buffers.
    const BINDING: [u8; 32] = [
        0xf6, 0x93, 0x5b, 0x12, 0xfd, 0x0e, 0x89, 0xae, 0xea, 0x83, 0x2a, 0x54, 0xc8, 0x1e, 0x55,
        0x23, 0x1a, 0xda, 0xe3, 0x0d, 0x47, 0x85, 0x1b, 0x99, 0x08, 0x46, 0x30, 0x3a, 0x16, 0x82,
        0x37, 0xfd,
    ];
    #[test]
    fn canonical_encoding_and_version_checks() {
        assert_eq!(
            channel_binding(&[1; 32], &[2; 32], &[3; 32], 1, 1),
            Ok(BINDING)
        );
        let expected = b"hoen-mailbox-viewer-proof/v1\0";
        let msg = viewer_proof_message(&BINDING, &[4; 32]);
        assert_eq!(&msg[..expected.len()], expected);
        assert_eq!(&msg[expected.len()..expected.len() + 32], &BINDING);
        assert_eq!(
            &msg[expected.len() + 32..],
            &[
                0x9f, 0x4f, 0xb6, 0x8f, 0x3e, 0x1d, 0xac, 0x82, 0x20, 0x2f, 0x9a, 0xa5, 0x81, 0xce,
                0x0b, 0xbf, 0x1f, 0x76, 0x5d, 0xf0, 0xe9, 0xac, 0x3c, 0x8c, 0x57, 0xe2, 0x0f, 0x68,
                0x5a, 0xba, 0xb8, 0xed
            ]
        );
        assert_ne!(
            channel_binding(&[1; 32], &[3; 32], &[2; 32], 1, 1).unwrap(),
            BINDING
        );
        assert_ne!(
            channel_binding(&[9; 32], &[2; 32], &[3; 32], 1, 1).unwrap(),
            BINDING
        );
        for (a, s) in [(0, 1), (1, 0), (2, 1), (1, 2), (2, 2)] {
            assert_eq!(
                channel_binding(&[1; 32], &[2; 32], &[3; 32], a, s),
                Err(Error::UnsupportedVersion)
            );
        }
    }
    #[test]
    fn proof_requires_matching_key_pin_token_and_binding() {
        // Deterministic seed is exclusively a test fixture, not a production key.
        let signing = SigningKey::from_bytes(&[7; 32]);
        let key = signing.verifying_key().to_bytes();
        let pin: [u8; 32] = Sha256::digest(key).into();
        let token = [4; 32];
        let sig = signing
            .sign(&viewer_proof_message(&BINDING, &token))
            .to_bytes();
        assert_eq!(
            verify_viewer_proof(&key, &sig, &BINDING, &token, &pin),
            Ok(())
        );
        assert_eq!(
            verify_viewer_proof(&key, &sig, &[0; 32], &token, &pin),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            verify_viewer_proof(&key, &sig, &BINDING, &[5; 32], &pin),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            verify_viewer_proof(&key, &sig, &BINDING, &token, &[0; 32]),
            Err(Error::ViewerPinMismatch)
        );
        let other = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        assert_eq!(
            verify_viewer_proof(&other, &sig, &BINDING, &token, &pin),
            Err(Error::ViewerPinMismatch)
        );
        let other_pin: [u8; 32] = Sha256::digest(other).into();
        assert_eq!(
            verify_viewer_proof(&other, &sig, &BINDING, &token, &other_pin),
            Err(Error::InvalidSignature)
        );
        let mut bad = sig;
        bad[0] ^= 1;
        assert_eq!(
            verify_viewer_proof(&key, &bad, &BINDING, &token, &pin),
            Err(Error::InvalidSignature)
        );
    }
}
