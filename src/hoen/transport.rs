use super::{authorization, handshake, mailbox_worker::MailboxWorker, network};
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

/// A real direct socket, admitted using its OS-reported addresses. No public
/// discovery, DNS, proxy, relay, KCP or WebRTC fallback exists in this path.
pub(crate) struct Transport {
    pub stream: Stream,
    pub channel: handshake::VerifiedChannel,
    policy: network::Policy,
    local: SocketAddr,
    peer: SocketAddr,
}

async fn admit(policy: network::Policy, local: SocketAddr, peer: SocketAddr) -> ResultType<()> {
    spawn_blocking(move || network::admit_socket(Some(&policy), local, peer))
        .await?
        .map_err(|_| anyhow!("connection is outside the current local-network scope"))
}

impl Transport {
    /// Call again on network notifications and before session admission. The
    /// connection loop must close on failure; the snapshot is not a lease.
    pub async fn recheck(&self) -> ResultType<()> {
        admit(self.policy.clone(), self.local, self.peer).await
    }

    pub async fn connect(
        policy: network::Policy,
        mailbox: &MailboxWorker,
        host: Identity,
        signing_key: &sign::SecretKey,
    ) -> ResultType<(Self, HoenProof)> {
        let machine = mailbox.lookup(host.clone()).await?;
        if machine.identity != host || !machine.hosting_enabled {
            bail!("mailbox host is unavailable");
        }
        let remote = SocketAddr::new(machine.endpoint.address(), machine.endpoint.port());
        let bind = SocketAddr::new(policy.local_address, 0);
        admit(policy.clone(), bind, remote).await?;
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
        };
        let proof =
            authorization::issue_proof(mailbox, &host, &transport.channel, signing_key).await?;
        transport.recheck().await?;
        Ok((transport, proof))
    }

    /// The caller must also validate the selected local address before opening its listener.
    pub async fn accept(
        socket: TcpStream,
        policy: network::Policy,
        signing_key: &sign::SecretKey,
    ) -> ResultType<Self> {
        let local = socket.local_addr()?;
        let peer = socket.peer_addr()?;
        admit(policy.clone(), local, peer).await?;
        let mut stream = Stream::from(socket, local);
        let channel = handshake::host(&mut stream, signing_key, &signing_key.public_key()).await?;
        Ok(Self {
            stream,
            channel,
            policy,
            local,
            peer,
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio::net::TcpListener;

    #[hbb_common::tokio::test]
    async fn unapproved_socket_closes_before_host_greeting() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, accepted) =
            hbb_common::tokio::join!(TcpStream::connect(address), listener.accept(),);
        let (socket, _) = accepted.unwrap();
        let (_, signing_key) = sign::gen_keypair();
        let policy = network::Policy {
            local_address: address.ip(),
        };
        assert!(Transport::accept(socket, policy, &signing_key)
            .await
            .is_err());

        let mut peer = Stream::from(client.unwrap(), address);
        let received = timeout(Duration::from_secs(1), peer.next()).await.unwrap();
        assert!(!matches!(received, Some(Ok(_))));
    }
}
