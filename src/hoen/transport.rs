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
