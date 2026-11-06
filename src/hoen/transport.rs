use super::{
    authorization, handshake,
    mailbox_worker::MailboxWorker,
    network,
    network_monitor::{NetworkMonitor, State},
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
use std::{net::SocketAddr, sync::Arc};

/// A real direct socket, admitted using its OS-reported addresses. No public
/// discovery, DNS, proxy, relay, KCP or WebRTC fallback exists in this path.
pub(crate) struct Transport {
    pub stream: Stream,
    pub channel: handshake::VerifiedChannel,
    policy: network::Policy,
    local: SocketAddr,
    peer: SocketAddr,
    monitor: Arc<NetworkMonitor>,
    captured: State,
}

/// Owned by one live connection; never indexed or cached by peer identity.
pub(crate) struct NetworkGuard {
    pub channel: handshake::VerifiedChannel,
    policy: network::Policy,
    local: SocketAddr,
    peer: SocketAddr,
    monitor: Arc<NetworkMonitor>,
    captured: State,
}

impl NetworkGuard {
    pub fn is_current(&self) -> bool {
        self.monitor.is_current(self.captured)
    }
    pub fn subscribe(&self) -> hbb_common::tokio::sync::watch::Receiver<()> {
        self.monitor.subscribe()
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
    pub async fn recheck(&self) -> ResultType<()> {
        if !self.is_current() {
            bail!("network changed during mailbox session");
        }
        admit(self.policy.clone(), self.local, self.peer).await?;
        if !self.is_current() {
            bail!("network changed during mailbox session");
        }
        Ok(())
    }
    pub async fn authenticate(
        &self,
        mailbox: &MailboxWorker,
        identity: &Identity,
        proof: &HoenProof,
    ) -> ResultType<ConsumedGrant> {
        self.recheck().await?;
        let grant = authorization::consume_proof(mailbox, identity, &self.channel, proof).await?;
        self.recheck().await?;
        Ok(grant)
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
        .map_err(|_| anyhow!("connection is outside the approved home network"))
}

impl Transport {
    pub fn into_parts(self) -> (Stream, NetworkGuard) {
        (
            self.stream,
            NetworkGuard {
                channel: self.channel,
                policy: self.policy,
                local: self.local,
                peer: self.peer,
                monitor: self.monitor,
                captured: self.captured,
            },
        )
    }
    /// Call again on network notifications and before session admission. The
    /// connection loop must close on failure; the snapshot is not a lease.
    pub async fn recheck(&self) -> ResultType<()> {
        if !self.monitor.is_current(self.captured) {
            bail!("network changed during mailbox connection");
        }
        admit(self.policy.clone(), self.local, self.peer).await?;
        if !self.monitor.is_current(self.captured) {
            bail!("network changed during mailbox connection");
        }
        Ok(())
    }

    pub async fn connect(
        policy: network::Policy,
        mailbox: &MailboxWorker,
        host: Identity,
        signing_key: &sign::SecretKey,
        monitor: Arc<NetworkMonitor>,
    ) -> ResultType<(Self, HoenProof)> {
        let captured = monitor.state();
        if captured.closed {
            bail!("network monitoring unavailable");
        }
        let machine = mailbox.lookup(host.clone()).await?;
        if machine.identity != host || !machine.hosting_enabled {
            bail!("mailbox host is unavailable");
        }
        let remote = SocketAddr::new(machine.endpoint.address(), machine.endpoint.port());
        let bind = SocketAddr::new(policy.local_address, 0);
        admit(policy.clone(), bind, remote).await?;
        if !monitor.is_current(captured) {
            bail!("network changed before mailbox connection");
        }
        let socket = if bind.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.bind(bind)?;
        let socket = timeout(Duration::from_secs(10), socket.connect(remote)).await??;
        let local = socket.local_addr()?;
        let peer = socket.peer_addr()?;
        admit(policy.clone(), local, peer).await?;
        let mut stream = Stream::from(socket, local);
        let channel =
            handshake::viewer(&mut stream, machine.public_key_fingerprint.as_bytes()).await?;
        let transport = Self {
            stream,
            channel,
            policy,
            local,
            peer,
            monitor,
            captured,
        };
        transport.recheck().await?;
        let proof =
            authorization::issue_proof(mailbox, &host, &transport.channel, signing_key).await?;
        transport.recheck().await?;
        Ok((transport, proof))
    }

    /// Windows viewer path: the SYSTEM-owned service supplies the selected
    /// host's registered pin and signs a grant for the verified channel. The
    /// viewer still enforces its own live network policy and host handshake.
    #[cfg(windows)]
    pub async fn connect_via_service(host: Identity) -> ResultType<(Self, HoenProof)> {
        use super::local_proof::{LookupRequest, ProofRequest};
        use crate::ipc::Data;
        use hoen_mailbox_auth::mailbox::Endpoint;

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
        let policy = network::Policy {
            adapter_id: lookup.adapter_id,
            network_id: lookup.network_id,
            local_address: lookup.local_address,
        };
        let monitor = Arc::new(
            NetworkMonitor::start()
                .await
                .map_err(|_| anyhow!("network monitoring unavailable"))?,
        );
        let captured = monitor.state();
        if captured.closed {
            bail!("network monitoring unavailable");
        }
        let remote = lookup.endpoint;
        let bind = SocketAddr::new(policy.local_address, 0);
        admit(policy.clone(), bind, remote).await?;
        if !monitor.is_current(captured) {
            bail!("network changed before mailbox connection");
        }
        let socket = if bind.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.bind(bind)?;
        let socket = timeout(Duration::from_secs(10), socket.connect(remote)).await??;
        let local = socket.local_addr()?;
        let peer = socket.peer_addr()?;
        if peer != remote {
            bail!("mailbox peer address changed");
        }
        admit(policy.clone(), local, peer).await?;
        if !monitor.is_current(captured) {
            bail!("network changed before mailbox handshake");
        }
        let mut stream = Stream::from(socket, local);
        let channel = handshake::viewer(&mut stream, &lookup.host_fingerprint).await?;
        let transport = Self {
            stream,
            channel,
            policy,
            local,
            peer,
            monitor,
            captured,
        };
        transport.recheck().await?;
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
        transport.recheck().await?;
        Ok((transport, proof))
    }

    /// The caller must also validate the approved address before opening its listener.
    pub async fn accept(
        socket: TcpStream,
        policy: network::Policy,
        signing_key: &sign::SecretKey,
        monitor: Arc<NetworkMonitor>,
    ) -> ResultType<Self> {
        let captured = monitor.state();
        if captured.closed {
            bail!("network monitoring unavailable");
        }
        let local = socket.local_addr()?;
        let peer = socket.peer_addr()?;
        admit(policy.clone(), local, peer).await?;
        if !monitor.is_current(captured) {
            bail!("network changed before mailbox handshake");
        }
        let mut stream = Stream::from(socket, local);
        let channel = handshake::host(&mut stream, signing_key, &signing_key.public_key()).await?;
        let transport = Self {
            stream,
            channel,
            policy,
            local,
            peer,
            monitor,
            captured,
        };
        transport.recheck().await?;
        Ok(transport)
    }

    /// Invoke exactly once, before any desktop side effects or final authorization.
    pub async fn authenticate(
        &self,
        mailbox: &MailboxWorker,
        local_identity: &Identity,
        proof: &HoenProof,
    ) -> ResultType<ConsumedGrant> {
        self.recheck().await?;
        let result =
            authorization::consume_proof(mailbox, local_identity, &self.channel, proof).await?;
        self.recheck().await?;
        Ok(result)
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
