use base::message_proto::{message, HoenKeyConfirmation, Message, PublicKey, SignedId};
use hbb_common::{
    anyhow::{anyhow, bail},
    protobuf::Message as _,
    rendezvous_proto::IdPk,
    sodiumoxide::crypto::{box_, sign},
    stream::Stream,
    tcp,
    tokio::time::{timeout, Duration},
    ResultType,
};
use sha2::{Digest, Sha256};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HANDSHAKE_BYTES: usize = 4096;

/// Only constructed after key installation succeeds. Not evidence of LAN admission.
pub(crate) struct VerifiedChannel {
    pub binding: [u8; 32],
    pub host_key: [u8; 32],
}

async fn receive(stream: &mut Stream) -> ResultType<Message> {
    let bytes = timeout(HANDSHAKE_TIMEOUT, stream.next())
        .await?
        .ok_or_else(|| anyhow!("mailbox handshake closed"))??;
    if bytes.len() <= 1 {
        bail!("empty mailbox handshake frame");
    }
    Ok(Message::parse_from_bytes(&bytes)?)
}

fn verify_host(identity: &SignedId, pin: &[u8; 32]) -> ResultType<([u8; 32], [u8; 32])> {
    let host: [u8; 32] = identity.hoen_host_key.as_ref().try_into()?;
    let actual: [u8; 32] = Sha256::digest(host).into();
    if &actual != pin {
        bail!("mailbox host key mismatch");
    }
    let signed = sign::verify(&identity.id, &sign::PublicKey(host))
        .map_err(|_| anyhow!("invalid mailbox host signature"))?;
    let transcript = IdPk::parse_from_bytes(&signed)?;
    if transcript.kx_version != 1 || !transcript.dtls_fingerprint.is_empty() {
        bail!("unsupported mailbox handshake");
    }
    Ok((host, transcript.pk.as_ref().try_into()?))
}

/// Call only for a freshly opened, explicitly admitted direct TCP socket.
/// The caller must retain this result on that connection, never by peer ID.
pub(crate) async fn viewer(
    stream: &mut Stream,
    host_pin: &[u8; 32],
) -> ResultType<VerifiedChannel> {
    if !matches!(stream, Stream::Tcp(_)) {
        bail!("mailbox handshake requires native TCP");
    }
    stream.set_max_packet_length(MAX_HANDSHAKE_BYTES);
    let identity = match receive(stream).await?.union {
        Some(message::Union::SignedId(identity)) => identity,
        _ => bail!("missing mailbox host identity"),
    };
    let (host, responder) = verify_host(&identity, host_pin)?;
    let (initiator, encrypted_key, key) = crate::common::create_symmetric_key_msg(responder);
    let initiator_bytes: [u8; 32] = initiator.as_ref().try_into()?;
    let binding = hoen_mailbox_auth::channel_binding(&host, &initiator_bytes, &responder, 1, 1)?;
    let mut reply = Message::new();
    reply.set_public_key(PublicKey {
        asymmetric_value: initiator,
        symmetric_value: encrypted_key,
        kx_version: 1,
        ..Default::default()
    });
    timeout(HANDSHAKE_TIMEOUT, stream.send(&reply)).await??;
    stream.set_negotiated_key(
        key,
        true,
        &tcp::KxTranscript {
            initiator_pk: &initiator_bytes,
            responder_pk: &responder,
            advertised: 1,
            picked: 1,
        },
    )?;
    match receive(stream).await?.union {
        Some(message::Union::HoenKeyConfirmation(confirmation))
            if confirmation.channel_binding.as_ref() == binding => {}
        _ => bail!("missing mailbox host key confirmation"),
    }
    // The host is authenticated here; its next packets may contain full video
    // or clipboard payloads. The host-side cap stays until final admission.
    stream.set_max_packet_length(hbb_common::bytes_codec::MAX_FRAME_LENGTH);
    Ok(VerifiedChannel {
        binding,
        host_key: host,
    })
}

/// Call only on a freshly accepted, explicitly admitted direct TCP socket.
pub(crate) async fn host(
    stream: &mut Stream,
    signing_key: &sign::SecretKey,
    public_key: &sign::PublicKey,
) -> ResultType<VerifiedChannel> {
    if !matches!(stream, Stream::Tcp(_)) {
        bail!("mailbox handshake requires native TCP");
    }
    if signing_key.public_key() != *public_key {
        bail!("mailbox device key pair mismatch");
    }
    stream.set_max_packet_length(MAX_HANDSHAKE_BYTES);
    let (responder, secret) = box_::gen_keypair();
    let transcript = IdPk {
        pk: responder.0.to_vec().into(),
        kx_version: 1,
        ..Default::default()
    }
    .write_to_bytes()?;
    let mut identity = Message::new();
    identity.set_signed_id(SignedId {
        id: sign::sign(&transcript, signing_key).into(),
        hoen_host_key: public_key.0.to_vec().into(),
        ..Default::default()
    });
    timeout(HANDSHAKE_TIMEOUT, stream.send(&identity)).await??;
    let reply = match receive(stream).await?.union {
        Some(message::Union::PublicKey(key)) => key,
        _ => bail!("missing mailbox key exchange"),
    };
    if reply.kx_version != 1 {
        bail!("unsupported mailbox key exchange version");
    }
    let initiator: [u8; 32] = reply.asymmetric_value.as_ref().try_into()?;
    let key = tcp::Encrypt::decode(&reply.symmetric_value, &initiator, &secret)?;
    let binding =
        hoen_mailbox_auth::channel_binding(&public_key.0, &initiator, &responder.0, 1, 1)?;
    stream.set_negotiated_key(
        key,
        false,
        &tcp::KxTranscript {
            initiator_pk: &initiator,
            responder_pk: &responder.0,
            advertised: 1,
            picked: 1,
        },
    )?;
    let mut confirmation = Message::new();
    confirmation.set_hoen_key_confirmation(HoenKeyConfirmation {
        channel_binding: binding.to_vec().into(),
        ..Default::default()
    });
    timeout(HANDSHAKE_TIMEOUT, stream.send(&confirmation)).await??;
    Ok(VerifiedChannel {
        binding,
        host_key: public_key.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[hbb_common::tokio::test]
    async fn native_tcp_peers_bind_same_channel_and_exchange_encrypted_messages() {
        use hbb_common::tokio::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (public, secret) = sign::gen_keypair();
        let pin: [u8; 32] = Sha256::digest(public.0).into();
        let server = hbb_common::tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            let mut stream = Stream::from(socket, peer);
            let channel = host(&mut stream, &secret, &public).await.unwrap();
            let incoming = receive(&mut stream).await.unwrap();
            assert!(matches!(incoming.union, Some(message::Union::PublicKey(_))));
            let mut reply = Message::new();
            reply.set_public_key(PublicKey {
                asymmetric_value: vec![9; 8192].into(),
                ..Default::default()
            });
            stream.send(&reply).await.unwrap();
            channel
        });
        let socket = TcpStream::connect(address).await.unwrap();
        let mut stream = Stream::from(socket, address);
        let channel = viewer(&mut stream, &pin).await.unwrap();
        let mut message = Message::new();
        message.set_public_key(PublicKey::new());
        stream.send(&message).await.unwrap();
        match receive(&mut stream).await.unwrap().union {
            Some(message::Union::PublicKey(key)) => assert_eq!(key.asymmetric_value.len(), 8192),
            _ => panic!("missing encrypted application payload"),
        }
        let server_channel = server.await.unwrap();
        assert_eq!(channel.binding, server_channel.binding);
        assert_eq!(channel.host_key, server_channel.host_key);
    }

    #[hbb_common::tokio::test]
    async fn host_rejects_empty_and_downgraded_exchange() {
        use hbb_common::tokio::net::{TcpListener, TcpStream};
        for response in [Message::new(), {
            let mut message = Message::new();
            message.set_public_key(PublicKey {
                kx_version: 0,
                ..Default::default()
            });
            message
        }] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (public, secret) = sign::gen_keypair();
            let server = hbb_common::tokio::spawn(async move {
                let (socket, peer) = listener.accept().await.unwrap();
                let mut stream = Stream::from(socket, peer);
                host(&mut stream, &secret, &public).await.is_err()
            });
            let mut stream = Stream::from(TcpStream::connect(address).await.unwrap(), address);
            receive(&mut stream).await.unwrap();
            stream.send(&response).await.unwrap();
            assert!(server.await.unwrap());
        }
    }

    #[hbb_common::tokio::test]
    async fn replayed_greeting_without_encrypted_confirmation_is_rejected() {
        use hbb_common::tokio::net::{TcpListener, TcpStream};
        for fake_confirmation in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (public, secret) = sign::gen_keypair();
            let pin: [u8; 32] = Sha256::digest(public.0).into();
            let captured = SignedId {
                id: sign::sign(
                    &IdPk {
                        pk: vec![7; 32].into(),
                        kx_version: 1,
                        ..Default::default()
                    }
                    .write_to_bytes()
                    .unwrap(),
                    &secret,
                )
                .into(),
                hoen_host_key: public.0.to_vec().into(),
                ..Default::default()
            };
            let server = hbb_common::tokio::spawn(async move {
                let (socket, peer) = listener.accept().await.unwrap();
                let mut stream = Stream::from(socket, peer);
                let mut greeting = Message::new();
                greeting.set_signed_id(captured);
                stream.send(&greeting).await.unwrap();
                receive(&mut stream).await.unwrap();
                if fake_confirmation {
                    let mut fake = Message::new();
                    fake.set_hoen_key_confirmation(HoenKeyConfirmation {
                        channel_binding: vec![0; 32].into(),
                        ..Default::default()
                    });
                    stream.send(&fake).await.unwrap();
                }
            });
            let mut stream = Stream::from(TcpStream::connect(address).await.unwrap(), address);
            assert!(viewer(&mut stream, &pin).await.is_err());
            server.await.unwrap();
        }
    }

    #[test]
    fn host_identity_requires_pin_signature_and_version() {
        let (public, secret) = sign::gen_keypair();
        let pin: [u8; 32] = Sha256::digest(public.0).into();
        let identity = |version| SignedId {
            id: sign::sign(
                &IdPk {
                    pk: vec![7; 32].into(),
                    kx_version: version,
                    ..Default::default()
                }
                .write_to_bytes()
                .unwrap(),
                &secret,
            )
            .into(),
            hoen_host_key: public.0.to_vec().into(),
            ..Default::default()
        };
        assert_eq!(
            verify_host(&identity(1), &pin).unwrap(),
            (public.0, [7; 32])
        );
        assert!(verify_host(&identity(1), &[0; 32]).is_err());
        assert!(verify_host(&identity(0), &pin).is_err());
        assert!(verify_host(&identity(2), &pin).is_err());
        let mut corrupt = identity(1);
        let mut bytes = corrupt.id.to_vec();
        bytes[0] ^= 1;
        corrupt.id = bytes.into();
        assert!(verify_host(&corrupt, &pin).is_err());
    }
}
