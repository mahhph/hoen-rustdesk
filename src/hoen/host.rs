//! Feature-gated host listener; never starts rendezvous, relay or LAN discovery.
use super::{network, runtime::Runtime, transport::NetworkGuard};
use hbb_common::{
    anyhow::anyhow,
    config::Config,
    tokio::{
        net::TcpListener,
        task::{spawn_blocking, JoinSet},
        time,
    },
    ResultType,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};

pub(crate) struct HostContext {
    pub runtime: Arc<Runtime>,
    pub guard: Arc<NetworkGuard>,
}
pub(crate) fn disabled() -> bool {
    hbb_common::config::is_outgoing_only()
        || hbb_common::config::option2bool("stop-service", &Config::get_option("stop-service"))
}
pub(crate) async fn run() -> ResultType<()> {
    if disabled() {
        return Ok(());
    }
    let mut runtime = Arc::new(super::runtime::host().await?.current_host_address().await?);
    #[cfg(target_os = "macos")]
    hbb_common::log::warn!("Mac host permissions: accessibility={}, screen_recording={}",
        crate::platform::macos::is_process_trusted(false),
        crate::platform::macos::is_can_screen_recording(false));
    let addr = SocketAddr::new(runtime.policy.local_address, runtime.listen_port);
    let policy = runtime.policy.clone();
    spawn_blocking(move || network::verify_binding(Some(&policy), addr))
        .await?
        .map_err(|_| anyhow!("configured bind address unavailable"))?;
    let mut listener = TcpListener::bind(addr).await?;
    if disabled() {
        return Ok(());
    }
    runtime.register_host().await?;
    let slots = Arc::new(hbb_common::tokio::sync::Semaphore::new(64));
    let server = crate::server::new();
    let mut tasks = JoinSet::new();
    let mut check = time::interval(Duration::from_secs(3));
    let mut address_check = time::interval(Duration::from_secs(15));
    address_check.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut recovery = JoinSet::new();
    let result = loop {
        hbb_common::tokio::select! {
            _ = check.tick() => {
                if disabled() { break Ok(()); }
            }
            _ = address_check.tick(), if recovery.is_empty() => {
                let current = runtime.clone();
                recovery.spawn(async move {
                    let next = Arc::new(current.current_host_address().await?);
                    if next.policy.local_address == current.policy.local_address {
                        return Ok::<_, hbb_common::anyhow::Error>(None);
                    }
                    let address = SocketAddr::new(next.policy.local_address, next.listen_port);
                    let replacement = bind_registered(address, || next.register_host()).await?;
                    Ok(Some((replacement, next)))
                });
            }
            Some(recovered) = recovery.join_next(), if !recovery.is_empty() => {
                match recovered {
                    Ok(Ok(Some((replacement, next)))) => {
                        listener = replacement;
                        runtime = next;
                        hbb_common::log::info!("Host listener address refreshed");
                    }
                    Ok(Ok(None)) => {}
                    _ => hbb_common::log::trace!("Host address refresh unavailable; retrying"),
                }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let (socket, peer) = match accepted { Ok(pair) => pair, Err(error) => break Err(error.into()) };
                if disabled() { break Ok(()); }
                let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
                let server = server.clone();
                let runtime = runtime.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = crate::server::create_hoen_connection(server, socket, peer, runtime).await {
                        hbb_common::log::trace!("Mailbox connection ended: {error}");
                    }
                });
            }
        }
    };
    drop(listener);
    recovery.abort_all();
    server.write().unwrap().close_connections();
    let _ = time::timeout(Duration::from_secs(5), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.abort_all();
    result
}

async fn bind_registered<F, Fut>(address: SocketAddr, register: F) -> ResultType<TcpListener>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ResultType<()>>,
{
    let listener = TcpListener::bind(address).await?;
    register().await?;
    Ok(listener)
}

#[cfg(test)]
mod address_tests {
    use super::*;
    use hbb_common::tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};

    #[hbb_common::tokio::test]
    async fn replacement_preserves_established_connection_and_accepts_new_connections() {
        let old = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(old.local_addr().unwrap()).await.unwrap();
        let (mut established, _) = old.accept().await.unwrap();
        let replacement = bind_registered("127.0.0.2:0".parse().unwrap(), || async { Ok(()) }).await.unwrap();
        drop(old);
        client.write_all(b"ok").await.unwrap();
        let mut bytes = [0; 2];
        established.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ok");
        let _new_client = TcpStream::connect(replacement.local_addr().unwrap()).await.unwrap();
        assert!(replacement.accept().await.is_ok());
    }

    #[hbb_common::tokio::test]
    async fn bind_failure_does_not_publish_and_registration_failure_releases_candidate() {
        let old = TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(bind_registered(old.local_addr().unwrap(), || async { panic!("must not advertise failed bind") }).await.is_err());
        let candidate = TcpListener::bind("127.0.0.2:0").await.unwrap();
        let address = candidate.local_addr().unwrap();
        drop(candidate);
        assert!(bind_registered(address, || async { Err(anyhow!("mailbox offline")) }).await.is_err());
        assert!(TcpListener::bind(address).await.is_ok());
        let _client = TcpStream::connect(old.local_addr().unwrap()).await.unwrap();
        assert!(old.accept().await.is_ok());
    }
}
