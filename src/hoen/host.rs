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
    let runtime = super::runtime::host().await?;
    #[cfg(target_os = "macos")]
    hbb_common::log::warn!("Mac host permissions: accessibility={}, screen_recording={}",
        crate::platform::macos::is_process_trusted(false),
        crate::platform::macos::is_can_screen_recording(false));
    let mut network_changes = runtime.monitor.subscribe();
    let captured = runtime.monitor.state();
    if captured.closed {
        return Err(anyhow!("network monitoring unavailable"));
    }
    let addr = SocketAddr::new(runtime.policy.local_address, runtime.listen_port);
    let policy = runtime.policy.clone();
    spawn_blocking(move || network::verify_binding(Some(&policy), addr))
        .await?
        .map_err(|_| anyhow!("configured bind address unavailable"))?;
    if !runtime.monitor.is_current(captured) {
        return Err(anyhow!("network changed before listening"));
    }
    let listener = TcpListener::bind(addr).await?;
    if disabled() {
        return Ok(());
    }
    runtime.register_host().await?;
    if !runtime.monitor.is_current(captured) {
        return Err(anyhow!("network changed before hosting"));
    }
    let slots = Arc::new(hbb_common::tokio::sync::Semaphore::new(64));
    let server = crate::server::new();
    let mut tasks = JoinSet::new();
    let mut check = time::interval(Duration::from_secs(3));
    let result = loop {
        hbb_common::tokio::select! {
            _ = network_changes.changed() => { break Err(anyhow!("network changed; hosting suspended")); }
            _ = check.tick() => {
                if disabled() { break Ok(()); }
                if !runtime.monitor.is_current(captured) { break Err(anyhow!("network changed; hosting suspended")); }
                let policy = runtime.policy.clone();
                let result = spawn_blocking(move || network::verify_binding(Some(&policy), addr)).await;
                if !matches!(result, Ok(Ok(()))) { break Err(anyhow!("configured bind address unavailable")); }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let (socket, peer) = match accepted { Ok(pair) => pair, Err(error) => break Err(error.into()) };
                if disabled() { break Ok(()); }
                if !runtime.monitor.is_current(captured) { break Err(anyhow!("network changed; hosting suspended")); }
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
    server.write().unwrap().close_connections();
    let _ = time::timeout(Duration::from_secs(5), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.abort_all();
    result
}
