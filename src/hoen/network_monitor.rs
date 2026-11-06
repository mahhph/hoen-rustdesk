//! Opt-in invalidation monitor. A notification never approves a network: callers must close
//! existing listeners/sessions and obtain a fresh approved snapshot before reconnecting.
//! Subscribe before a snapshot, compare the returned state after it, and keep watching afterward.
use hbb_common::tokio::{
    self,
    sync::{oneshot, watch},
};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub generation: u64,
    pub closed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonitorError {
    Unavailable,
    Unsupported,
}
const CLOSED: u64 = 1 << 63;
const MAX_GENERATION: u64 = CLOSED - 1;
struct Shared {
    state: std::sync::atomic::AtomicU64,
    tx: watch::Sender<()>,
}
impl Shared {
    fn new() -> Arc<Self> {
        let (tx, _) = watch::channel(());
        Arc::new(Self {
            state: std::sync::atomic::AtomicU64::new(0),
            tx,
        })
    }
    fn state(&self) -> State {
        let bits = self.state.load(std::sync::atomic::Ordering::SeqCst);
        State {
            generation: bits & MAX_GENERATION,
            closed: bits & CLOSED != 0,
        }
    }
    fn invalidate(&self) {
        let _ = self.state.fetch_update(
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
            |s| {
                if s & CLOSED != 0 {
                    None
                } else if s == MAX_GENERATION {
                    Some(s | CLOSED)
                } else {
                    Some(s + 1)
                }
            },
        );
        self.tx.send_replace(());
    }
    // Called from async/drop paths: no watch lock or blocking OS work here.
    fn close_fast(&self) {
        self.state
            .fetch_or(CLOSED, std::sync::atomic::Ordering::SeqCst);
    }
    fn close_and_notify(&self) {
        self.close_fast();
        self.tx.send_replace(());
    }
}
/// Own this while the listener/session is active. Dropping it invalidates its watchers immediately.
pub struct NetworkMonitor {
    shared: Arc<Shared>,
    stop: Option<std::sync::mpsc::Sender<()>>,
    done: Option<oneshot::Receiver<Result<(), MonitorError>>>,
}
impl NetworkMonitor {
    /// Starts all required subscriptions on a dedicated worker. No blocking OS setup runs on the async executor.
    pub async fn start() -> Result<Self, MonitorError> {
        tokio::task::spawn_blocking(start_blocking)
            .await
            .map_err(|_| MonitorError::Unavailable)?
    }
    /// Stop subscriptions and wait for teardown without blocking an async executor.
    pub async fn shutdown(mut self) -> Result<(), MonitorError> {
        self.shared.close_fast();
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        match self.done.take() {
            Some(done) => tokio::time::timeout(std::time::Duration::from_secs(10), done)
                .await
                .map_err(|_| MonitorError::Unavailable)?
                .map_err(|_| MonitorError::Unavailable)?,
            None => Err(MonitorError::Unavailable),
        }
    }
    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.shared.tx.subscribe()
    }
    pub fn state(&self) -> State {
        self.shared.state()
    }
    pub fn is_current(&self, captured: State) -> bool {
        let current = self.state();
        !captured.closed && !current.closed && current == captured
    }
}
impl Drop for NetworkMonitor {
    fn drop(&mut self) {
        self.shared.close_fast();
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
    }
}
#[cfg(not(any(windows, target_os = "macos")))]
fn start_blocking() -> Result<NetworkMonitor, MonitorError> {
    Err(MonitorError::Unsupported)
}
#[cfg(target_os = "macos")]
fn start_blocking() -> Result<NetworkMonitor, MonitorError> {
    macos_monitor::start()
}
#[cfg(windows)]
fn start_blocking() -> Result<NetworkMonitor, MonitorError> {
    windows_monitor::start()
}

#[cfg(target_os = "macos")]
#[path = "macos_network_monitor.rs"]
mod macos_monitor;

#[cfg(windows)]
mod windows_monitor {
    use super::*;
    use std::{
        collections::HashMap,
        ffi::c_void,
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc, Mutex, OnceLock, Weak,
        },
        time::Duration,
    };
    use windows::{
        core::{implement, IUnknown, Interface, GUID},
        Win32::{
            Foundation::{ERROR_SUCCESS, HANDLE},
            NetworkManagement::{IpHelper::*, WiFi::*},
            Networking::{NetworkListManager::*, WinSock::AF_UNSPEC},
            System::Com::{
                CoCreateInstance, CoInitializeEx, CoUninitialize, IConnectionPoint,
                IConnectionPointContainer, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
            },
        },
    };
    static NEXT: AtomicUsize = AtomicUsize::new(1);
    static CONTEXTS: OnceLock<Mutex<HashMap<usize, Weak<Shared>>>> = OnceLock::new();
    fn contexts() -> &'static Mutex<HashMap<usize, Weak<Shared>>> {
        CONTEXTS.get_or_init(|| Mutex::new(HashMap::new()))
    }
    fn context_id(shared: &Arc<Shared>) -> Result<usize, MonitorError> {
        let id = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| MonitorError::Unavailable)?;
        contexts()
            .lock()
            .map_err(|_| MonitorError::Unavailable)?
            .insert(id, Arc::downgrade(shared));
        Ok(id)
    }
    fn notify(raw: *const c_void) {
        // The callback receives an opaque integer, never an address to dereference. If unregistration
        // fails or a late callback arrives, a removed context cannot become a dangling pointer.
        let shared = contexts()
            .lock()
            .ok()
            .and_then(|m| m.get(&(raw as usize)).and_then(Weak::upgrade));
        if let Some(shared) = shared {
            shared.invalidate();
        }
    }
    unsafe extern "system" fn interface_cb(
        ctx: *const c_void,
        _: *const MIB_IPINTERFACE_ROW,
        _: MIB_NOTIFICATION_TYPE,
    ) {
        let _ = std::panic::catch_unwind(|| notify(ctx));
    }
    unsafe extern "system" fn route_cb(
        ctx: *const c_void,
        _: *const MIB_IPFORWARD_ROW2,
        _: MIB_NOTIFICATION_TYPE,
    ) {
        let _ = std::panic::catch_unwind(|| notify(ctx));
    }
    unsafe extern "system" fn address_cb(
        ctx: *const c_void,
        _: *const MIB_UNICASTIPADDRESS_ROW,
        _: MIB_NOTIFICATION_TYPE,
    ) {
        let _ = std::panic::catch_unwind(|| notify(ctx));
    }
    fn wifi_relevant(source: u32, code: u32) -> bool {
        // Ignore routine scan and signal-quality reports; invalidate for connections, profiles,
        // adapter changes, authentication, roaming and unknown events from either source.
        if source == WLAN_NOTIFICATION_SOURCE_ACM.0 {
            !matches!(code, 3 | 4 | 7 | 8 | 26)
        } else if source == WLAN_NOTIFICATION_SOURCE_MSM.0 {
            !matches!(code, 8 | 15 | 16)
        } else {
            true
        }
    }
    unsafe extern "system" fn wlan_cb(data: *mut L2_NOTIFICATION_DATA, ctx: *mut c_void) {
        let _ = std::panic::catch_unwind(|| {
            if data.is_null()
                || unsafe { wifi_relevant((*data).NotificationSource.0, (*data).NotificationCode) }
            {
                notify(ctx.cast_const());
            }
        });
    }
    #[implement(INetworkEvents, INetworkConnectionEvents)]
    struct Events {
        shared: Arc<Shared>,
    }
    #[allow(non_snake_case)]
    impl INetworkEvents_Impl for Events_Impl {
        fn NetworkAdded(&self, _: &GUID) -> windows::core::Result<()> {
            self.shared.invalidate();
            Ok(())
        }
        fn NetworkDeleted(&self, _: &GUID) -> windows::core::Result<()> {
            self.shared.invalidate();
            Ok(())
        }
        fn NetworkConnectivityChanged(
            &self,
            _: &GUID,
            _: NLM_CONNECTIVITY,
        ) -> windows::core::Result<()> {
            self.shared.invalidate();
            Ok(())
        }
        fn NetworkPropertyChanged(
            &self,
            _: &GUID,
            _: NLM_NETWORK_PROPERTY_CHANGE,
        ) -> windows::core::Result<()> {
            self.shared.invalidate();
            Ok(())
        }
    }
    #[allow(non_snake_case)]
    impl INetworkConnectionEvents_Impl for Events_Impl {
        fn NetworkConnectionConnectivityChanged(
            &self,
            _: &GUID,
            _: NLM_CONNECTIVITY,
        ) -> windows::core::Result<()> {
            self.shared.invalidate();
            Ok(())
        }
        fn NetworkConnectionPropertyChanged(
            &self,
            _: &GUID,
            _: NLM_CONNECTION_PROPERTY_CHANGE,
        ) -> windows::core::Result<()> {
            self.shared.invalidate();
            Ok(())
        }
    }
    struct Com;
    impl Drop for Com {
        fn drop(&mut self) {
            unsafe {
                CoUninitialize();
            }
        }
    }
    struct Registrations {
        id: usize,
        handles: Vec<HANDLE>,
        wlan: Option<HANDLE>,
        points: Vec<(IConnectionPoint, u32)>,
        shared: Arc<Shared>,
    }
    impl Drop for Registrations {
        fn drop(&mut self) {
            self.shared.close_and_notify();
            // All teardown occurs on the dedicated worker, never in a callback or on the async runtime.
            // On an OS deregistration failure retain the handle and retry; never free callback state
            // while Windows may still use it. Persistent OS failure may keep this closed worker alive.
            for (point, cookie) in self.points.drain(..) {
                while unsafe { point.Unadvise(cookie) }.is_err() {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            if let Some(wlan) = self.wlan.take() {
                while unsafe { WlanCloseHandle(wlan, None) } != ERROR_SUCCESS.0 {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            for handle in self.handles.drain(..) {
                while unsafe { CancelMibChangeNotify2(handle) } != ERROR_SUCCESS {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            if let Ok(mut map) = contexts().lock() {
                map.remove(&self.id);
            }
        }
    }
    fn subscribe(shared: Arc<Shared>, id: usize) -> Result<Registrations, MonitorError> {
        let mut reg = Registrations {
            id,
            handles: Vec::new(),
            wlan: None,
            points: Vec::new(),
            shared: shared.clone(),
        };
        unsafe {
            let ctx = id as *const c_void;
            let mut h = HANDLE::default();
            if NotifyIpInterfaceChange(AF_UNSPEC, Some(interface_cb), Some(ctx), false, &mut h)
                != ERROR_SUCCESS
            {
                return Err(MonitorError::Unavailable);
            }
            reg.handles.push(h);
            h = HANDLE::default();
            if NotifyUnicastIpAddressChange(AF_UNSPEC, Some(address_cb), Some(ctx), false, &mut h)
                != ERROR_SUCCESS
            {
                return Err(MonitorError::Unavailable);
            }
            reg.handles.push(h);
            h = HANDLE::default();
            if NotifyRouteChange2(AF_UNSPEC, Some(route_cb), ctx, false, &mut h) != ERROR_SUCCESS {
                return Err(MonitorError::Unavailable);
            }
            reg.handles.push(h);
            let mut version = 0;
            h = HANDLE::default();
            if WlanOpenHandle(2, None, &mut version, &mut h) != ERROR_SUCCESS.0 {
                return Err(MonitorError::Unavailable);
            }
            reg.wlan = Some(h);
            if WlanRegisterNotification(
                h,
                WLAN_NOTIFICATION_SOURCE_ACM | WLAN_NOTIFICATION_SOURCE_MSM,
                false,
                Some(wlan_cb),
                Some(ctx),
                None,
                None,
            ) != ERROR_SUCCESS.0
            {
                return Err(MonitorError::Unavailable);
            }
            let manager: INetworkListManager =
                CoCreateInstance(&NetworkListManager, None, CLSCTX_INPROC_SERVER)
                    .map_err(|_| MonitorError::Unavailable)?;
            let container: IConnectionPointContainer =
                manager.cast().map_err(|_| MonitorError::Unavailable)?;
            let point = container
                .FindConnectionPoint(&INetworkEvents::IID)
                .map_err(|_| MonitorError::Unavailable)?;
            let sink: INetworkEvents = Events { shared }.into();
            let unknown: IUnknown = sink.cast().map_err(|_| MonitorError::Unavailable)?;
            let cookie = point
                .Advise(&unknown)
                .map_err(|_| MonitorError::Unavailable)?;
            reg.points.push((point, cookie));
            let point = container
                .FindConnectionPoint(&INetworkConnectionEvents::IID)
                .map_err(|_| MonitorError::Unavailable)?;
            let connection_sink: INetworkConnectionEvents =
                unknown.cast().map_err(|_| MonitorError::Unavailable)?;
            let connection_unknown: IUnknown = connection_sink
                .cast()
                .map_err(|_| MonitorError::Unavailable)?;
            let cookie = point
                .Advise(&connection_unknown)
                .map_err(|_| MonitorError::Unavailable)?;
            reg.points.push((point, cookie));
        }
        Ok(reg)
    }
    pub fn start() -> Result<NetworkMonitor, MonitorError> {
        let shared = Shared::new();
        let (stop_tx, stop_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (done_tx, done_rx) = oneshot::channel();
        let worker = shared.clone();
        std::thread::Builder::new()
            .name("hoen-network-watch".into())
            .spawn(move || {
                struct Done {
                    tx: Option<oneshot::Sender<Result<(), MonitorError>>>,
                    ok: bool,
                }
                impl Drop for Done {
                    fn drop(&mut self) {
                        if let Some(tx) = self.tx.take() {
                            let _ = tx.send(if self.ok {
                                Ok(())
                            } else {
                                Err(MonitorError::Unavailable)
                            });
                        }
                    }
                }
                let mut done = Done {
                    tx: Some(done_tx),
                    ok: false,
                };
                struct Close(Arc<Shared>);
                impl Drop for Close {
                    fn drop(&mut self) {
                        self.0.close_and_notify();
                    }
                }
                let _closed = Close(worker.clone());
                if unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_err() {
                    let _ = ready_tx.send(Err(MonitorError::Unavailable));
                    return;
                }
                let _com = Com;
                let id = match context_id(&worker) {
                    Ok(x) => x,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                match subscribe(worker.clone(), id) {
                    Ok(_registration) => {
                        if ready_tx.send(Ok(())).is_ok() {
                            let _ = stop_rx.recv();
                        }
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                }
                done.ok = true;
            })
            .map_err(|_| MonitorError::Unavailable)?;
        ready_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| MonitorError::Unavailable)??;
        if shared.state().closed {
            return Err(MonitorError::Unavailable);
        }
        Ok(NetworkMonitor {
            shared,
            stop: Some(stop_tx),
            done: Some(done_rx),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generation_and_closed_state_are_monotonic() {
        let s = Shared::new();
        let initial = s.state();
        let mut rx = s.tx.subscribe();
        s.invalidate();
        assert!(rx.has_changed().unwrap());
        rx.borrow_and_update();
        assert_eq!(
            s.state(),
            State {
                generation: 1,
                closed: false
            }
        );
        s.invalidate();
        assert_ne!(initial, s.state());
        s.close_fast();
        let closed = s.state();
        assert!(closed.closed);
        s.invalidate();
        assert_eq!(s.state(), closed);
    }
    #[test]
    fn overflow_closes_instead_of_reusing_a_generation() {
        let s = Shared::new();
        s.state
            .store(MAX_GENERATION, std::sync::atomic::Ordering::SeqCst);
        s.invalidate();
        assert_eq!(
            s.state(),
            State {
                generation: MAX_GENERATION,
                closed: true
            }
        );
    }
    #[test]
    fn dropped_monitor_invalidates_state_without_waiting_for_watch_borrow() {
        let s = Shared::new();
        let rx = s.tx.subscribe();
        let borrowed = rx.borrow();
        let monitor = NetworkMonitor {
            shared: s.clone(),
            stop: None,
            done: None,
        };
        let initial = monitor.state();
        assert!(monitor.is_current(initial));
        drop(monitor);
        assert!(s.state().closed);
        drop(borrowed);
    }
}
