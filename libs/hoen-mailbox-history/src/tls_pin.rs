//! Adds an exact leaf pin after normal WebPKI chain and hostname verification.
use rustls::{
    client::{ServerCertVerified, ServerCertVerifier, WebPkiVerifier},
    Certificate, ClientConfig, RootCertStore, ServerName,
};
use sha2::{Digest, Sha256};
use std::{io::BufReader, sync::Arc, time::SystemTime};

struct PinnedVerifier {
    webpki: WebPkiVerifier,
    leaf_sha256: [u8; 32],
}
impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified =
            self.webpki
                .verify_server_cert(end_entity, intermediates, name, scts, ocsp, now)?;
        let digest: [u8; 32] = Sha256::digest(&end_entity.0).into();
        if digest != self.leaf_sha256 {
            return Err(rustls::Error::General(
                "mailbox leaf certificate pin mismatch".into(),
            ));
        }
        Ok(verified)
    }
}

pub(crate) fn pinned_config(root_pem: &[u8], leaf_sha256: [u8; 32]) -> Result<ClientConfig, ()> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(root_pem)).map_err(|_| ())?;
    if certs.len() != 1 {
        return Err(());
    }
    let mut roots = RootCertStore::empty();
    roots
        .add(&Certificate(certs.into_iter().next().ok_or(())?))
        .map_err(|_| ())?;
    let verifier = PinnedVerifier {
        webpki: WebPkiVerifier::new(roots, None),
        leaf_sha256,
    };
    Ok(ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}
