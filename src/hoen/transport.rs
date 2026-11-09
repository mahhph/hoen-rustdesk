use super::{
    authorization, handshake,
    mailbox_worker::MailboxWorker,
    network,
};
use base::message_proto::HoenProof;
use hbb_common::{
    anyhow::{anyhow, bail},
    sodiumoxide::crypto::sign,
    stream::Stream,
    tokio::{
        net::{TcpSocket, TcpStream},
        task::spawn_blocking,
        time::{timeout, Duration},
    },
    ResultType,
};
use hoen_mailbox_auth::mailbox::{ConsumedGrant, Identity};
use std::net::SocketAddr;

fn tcp_failure(kind: std::io::ErrorKind) -> &'static str {
    match kind {
        std::io::ErrorKind::ConnectionRefused => "connection refused",
        std::io::ErrorKind::TimedOut => "connection timed out",
        _ => "network connection failed",
    }
}

/// A real direct socket, admitted using its OS-reported addresses. No public
/// discovery, DNS, proxy, relay, KCP or WebRTC fallback exists in this path.
pub(crate) struct Transport {
    pub stream: Stream,
    pub channel: handshake::VerifiedChannel,
}

/// Owned by one live connection; never indexed or cached by peer identity.
pub(crate) struct NetworkGuard {
    pub channel: handshake::VerifiedChannel,
}

impl NetworkGuard {
    pub async fn authenticate(
        &self,
        mailbox: &MailboxWorker,
        identity: &Identity,
        proof: &HoenProof,
    ) -> ResultType<ConsumedGrant> {
        authorization::consume_proof(mailbox, identity, &self.channel, proof).await
    }
}

pub(crate) fn validate_decrypted_frame(bytes: &[u8]) -> ResultType<()> {
    if bytes.len() <= 1 {
        bail!("empty mailbox session frame");
    }
    Ok(())
}

async fn admit(policy: network::Policy, local: SocketAddr, peer: SocketAddr) -> ResultType<()> {
    spawn_blocking(move || network::admit_socket(Some(&policy), local, peer))
        .await?
        .map_err(|_| anyhow!("socket local address does not match configured bind address"))
}

impl Transport {
    pub fn into_parts(self) -> (Stream, NetworkGuard) {
        (
            self.stream,
            NetworkGuard {
                channel: self.channel,
            },
        )
    }
    pub async fn connect(
        mailbox: &MailboxWorker,
        host: Identity,
        signing_key: &sign::SecretKey,
    ) -> ResultType<(Self, HoenProof)> {
        let mut retried = false;
        let (socket, machine) = loop {
            let machine = mailbox.lookup(host.clone()).await
                .map_err(|error| anyhow!("Mailbox could not find or authorize the selected computer: {error}"))?;
            if machine.identity != host || !machine.hosting_enabled {
                bail!("mailbox host is unavailable");
            }
            let remote = SocketAddr::new(machine.endpoint.address(), machine.endpoint.port());
            let socket = if remote.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            let connected = timeout(Duration::from_secs(10), socket.connect(remote)).await
                .map_err(|_| anyhow!("Could not reach the selected computer: connection timed out"))
                .and_then(|result| result.map_err(|error| anyhow!("Could not reach the selected computer: {}", tcp_failure(error.kind()))));
            match connected {
                Ok(socket) => break (socket, machine),
                Err(_) if !retried => { retried = true; }
                Err(error) => return Err(error),
            }
        };
        let local = socket.local_addr()?;
        let peer = socket.peer_addr()?;
        let policy = network::Policy {
            local_address: local.ip(),
        };
        admit(policy.clone(), local, peer).await?;
        let mut stream = Stream::from(socket, local);
        let channel =
            handshake::viewer(&mut stream, machine.public_key_fingerprint.as_bytes()).await
                .map_err(|_| anyhow!("Secure connection to the selected computer failed verification"))?;
        let transport = Self {
            stream,
            channel,
        };
        let proof =
            authorization::issue_proof(mailbox, &host, &transport.channel, signing_key).await
                .map_err(|_| anyhow!("Mailbox authorization for the selected computer failed"))?;
        Ok((transport, proof))
    }

    /// Windows viewer path: the SYSTEM-owned service supplies the selected
    /// host's registered pin and signs a grant for the verified channel. The
    /// viewer verifies the host handshake.
    #[cfg(windows)]
    pub async fn connect_via_service(host: Identity) -> ResultType<(Self, HoenProof)> {
        use super::local_proof::{LookupRequest, ProofRequest};
        use crate::ipc::Data;
        use hoen_mailbox_auth::mailbox::Endpoint;

        let mut retried = false;
        let (socket, lookup) = loop {
            let lookup = match service_request(Data::HoenLookupRequest(LookupRequest {
                host: host.as_str().to_owned(),
            }))
            .await?
            {
                Data::HoenLookupResponse(Some(value)) => value,
                _ => bail!("mailbox service host lookup unavailable"),
            };
            // Only the service's response to this validated request selects the
            // endpoint; never accept arbitrary peer-supplied routing information.
            Endpoint::new(lookup.endpoint.ip(), lookup.endpoint.port())?;
            let remote = lookup.endpoint;
            let socket = if remote.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            match timeout(Duration::from_secs(10), socket.connect(remote)).await {
                Ok(Ok(socket)) => break (socket, lookup),
                _ if !retried => { retried = true; }
                Ok(Err(error)) => return Err(error.into()),
                Err(error) => return Err(error.into()),
            }
        };
        let remote = lookup.endpoint;
        let local = socket.local_addr()?;
        let peer = socket.peer_addr()?;
        let policy = network::Policy {
            local_address: local.ip(),
        };
        if peer != remote {
            bail!("mailbox peer address changed");
        }
        admit(policy.clone(), local, peer).await?;
        let mut stream = Stream::from(socket, local);
        let channel = handshake::viewer(&mut stream, &lookup.host_fingerprint).await?;
        let transport = Self {
            stream,
            channel,
        };
        let response = match service_request(Data::HoenProofRequest(ProofRequest {
            host: host.as_str().to_owned(),
            binding: transport.channel.binding,
        }))
        .await?
        {
            Data::HoenProofResponse(Some(value)) => value,
            _ => bail!("mailbox service could not issue proof"),
        };
        let proof =
            checked_service_proof(response, &lookup.viewer_key, &transport.channel.binding)?;
        Ok((transport, proof))
    }

    /// The caller must validate the selected local address before opening its listener.
    pub async fn accept(
        socket: TcpStream,
        peer: SocketAddr,
        policy: network::Policy,
        signing_key: &sign::SecretKey,
    ) -> ResultType<Self> {
        let local = socket.local_addr().map_err(|e| anyhow!("host socket local address: {e}"))?;
        admit(policy.clone(), local, peer).await.map_err(|e| anyhow!("host socket admission: {e}"))?;
        let mut stream = Stream::from(socket, local);
        let channel = handshake::host(&mut stream, signing_key, &signing_key.public_key()).await.map_err(|e| anyhow!("host handshake: {e}"))?;
        let transport = Self {
            stream,
            channel,
        };
        Ok(transport)
    }

    /// Invoke exactly once, before any desktop side effects or final authorization.
    pub async fn authenticate(
        &self,
        mailbox: &MailboxWorker,
        local_identity: &Identity,
        proof: &HoenProof,
    ) -> ResultType<ConsumedGrant> {
        authorization::consume_proof(mailbox, local_identity, &self.channel, proof).await
    }
}

/// `connect_service` validates the SYSTEM-owned, restricted service pipe
/// before returning. Each service request uses one bounded connection.
#[cfg(windows)]
async fn service_request(request: crate::ipc::Data) -> ResultType<crate::ipc::Data> {
    let mut connection = crate::ipc::connect_service(3_000).await?;
    connection.set_max_packet_length(4096);
    timeout(Duration::from_secs(3), connection.send(&request)).await??;
    connection
        .next_timeout(35_000)
        .await?
        .ok_or_else(|| anyhow!("mailbox service returned an invalid response"))
}

#[cfg(windows)]
fn checked_service_proof(
    response: super::local_proof::ProofResponse,
    expected_key: &[u8; 32],
    binding: &[u8; 32],
) -> ResultType<HoenProof> {
    use sha2::{Digest, Sha256};
    if &response.viewer_key != expected_key {
        bail!("mailbox service viewer key changed");
    }
    let signature: [u8; 64] = response
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid mailbox service proof"))?;
    let pin: [u8; 32] = Sha256::digest(expected_key).into();
    hoen_mailbox_auth::verify_viewer_proof(
        expected_key,
        &signature,
        binding,
        &response.grant_token,
        &pin,
    )?;
    Ok(HoenProof {
        viewer_key: response.viewer_key.to_vec().into(),
        grant_token: response.grant_token.to_vec().into(),
        signature: response.signature.into(),
        ..Default::default()
    })
}

#[cfg(all(windows, test))]
mod service_tests {
    use super::super::local_proof::ProofResponse;
    use super::*;
    use hoen_mailbox_auth::viewer_proof_message;

    #[test]
    fn service_proof_requires_lookup_key_signature_and_connection_binding() {
        let (public, secret) = sign::gen_keypair();
        let binding = [17u8; 32];
        let grant_token = [9u8; 32];
        let signature = sign::sign_detached(&viewer_proof_message(&binding, &grant_token), &secret);
        let response = ProofResponse {
            viewer_key: public.0,
            grant_token,
            signature: signature.as_ref().to_vec(),
        };
        let proof = checked_service_proof(response.clone(), &public.0, &binding).unwrap();
        assert_eq!(proof.viewer_key.as_ref(), &public.0);
        assert!(checked_service_proof(response.clone(), &[1; 32], &binding).is_err());
        assert!(checked_service_proof(response.clone(), &public.0, &[2; 32]).is_err());
        let mut bad = response.clone();
        bad.signature.pop();
        assert!(checked_service_proof(bad, &public.0, &binding).is_err());
        let mut bad = response;
        bad.grant_token[0] ^= 1;
        assert!(checked_service_proof(bad, &public.0, &binding).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_errors_identify_the_tcp_failure_stage() {
        assert_eq!(tcp_failure(std::io::ErrorKind::ConnectionRefused), "connection refused");
        assert_eq!(tcp_failure(std::io::ErrorKind::TimedOut), "connection timed out");
        assert_eq!(tcp_failure(std::io::ErrorKind::Other), "network connection failed");
    }
    use hbb_common::tokio::net::TcpListener;

    #[hbb_common::tokio::test]
    async fn outgoing_socket_uses_current_route_without_saved_bind_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = listener.local_addr().unwrap();
        let socket = TcpSocket::new_v4().unwrap();
        let (client, accepted) = hbb_common::tokio::join!(socket.connect(remote), listener.accept());
        let client = client.unwrap();
        assert_eq!(client.local_addr().unwrap().ip(), remote.ip());
        assert!(accepted.is_ok());
    }

    #[hbb_common::tokio::test]
    async fn host_transport_establishes_verified_encrypted_channel() {
        use sha2::{Digest, Sha256};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (public, secret) = sign::gen_keypair();
        let fingerprint: [u8; 32] = Sha256::digest(public.0).into();
        let host = hbb_common::tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            let policy = network::Policy { local_address: address.ip() };
            Transport::accept(socket, peer, policy, &secret).await.unwrap()
        });
        let socket = TcpStream::connect(address).await.unwrap();
        let mut viewer = Stream::from(socket, address);
        let channel = handshake::viewer(&mut viewer, &fingerprint).await.unwrap();
        let host = host.await.unwrap();
        assert_eq!(channel.binding, host.channel.binding);
        assert!(viewer.is_secured());
        assert!(host.stream.is_secured());
    }

    #[hbb_common::tokio::test]
    async fn mismatched_binding_closes_before_host_greeting() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, accepted) =
            hbb_common::tokio::join!(TcpStream::connect(address), listener.accept(),);
        let (socket, peer) = accepted.unwrap();
        let (_, signing_key) = sign::gen_keypair();
        let policy = network::Policy {
            local_address: "127.0.0.2".parse().unwrap(),
        };
        assert!(Transport::accept(socket, peer, policy, &signing_key)
            .await
            .is_err());

        let mut peer = Stream::from(client.unwrap(), address);
        let received = timeout(Duration::from_secs(1), peer.next()).await.unwrap();
        assert!(!matches!(received, Some(Ok(_))));
    }
}
