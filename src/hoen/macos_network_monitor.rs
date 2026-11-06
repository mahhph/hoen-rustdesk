//! macOS change notifications. Notifications only invalidate; they never approve a network.
//! A dynamic-store subscription covers interface and configuration changes; a routing socket
//! also invalidates for route changes that do not necessarily update the dynamic store.
use super::{MonitorError, NetworkMonitor, Shared};
use core_foundation::{
    array::{CFArray, CFArrayRef},
    base::{kCFAllocatorDefault, Boolean, CFAllocatorRef, CFIndex, CFRelease, TCFType},
    runloop::{
        kCFRunLoopDefaultMode, CFRunLoopAddSource, CFRunLoopGetCurrent, CFRunLoopRemoveSource,
        CFRunLoopRunInMode, CFRunLoopSourceRef,
    },
    string::{CFString, CFStringRef},
};
use hbb_common::tokio::sync::oneshot;
use std::{
    ffi::c_void,
    io, ptr,
    sync::{mpsc, Arc},
    time::Duration,
};

type Store = *const c_void;
#[repr(C)]
struct Context {
    version: CFIndex,
    info: *mut c_void,
    retain: Option<unsafe extern "C" fn(*const c_void) -> *const c_void>,
    release: Option<unsafe extern "C" fn(*const c_void)>,
    description: Option<unsafe extern "C" fn(*const c_void) -> CFStringRef>,
}
#[link(name = "SystemConfiguration", kind = "framework")]
extern "C" {
    fn SCDynamicStoreCreate(
        allocator: CFAllocatorRef,
        name: CFStringRef,
        callback: Option<unsafe extern "C" fn(Store, CFArrayRef, *mut c_void)>,
        context: *mut Context,
    ) -> Store;
    fn SCDynamicStoreSetNotificationKeys(
        store: Store,
        keys: CFArrayRef,
        patterns: CFArrayRef,
    ) -> Boolean;
    fn SCDynamicStoreCreateRunLoopSource(
        allocator: CFAllocatorRef,
        store: Store,
        order: CFIndex,
    ) -> CFRunLoopSourceRef;
}
extern "C" {
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn read(fd: i32, buffer: *mut c_void, length: usize) -> isize;
    fn close(fd: i32) -> i32;
}
unsafe extern "C" fn changed(_: Store, _: CFArrayRef, info: *mut c_void) {
    // The run-loop source is removed and the store released before this borrowed pointer expires.
    let shared = &*(info as *const Arc<Shared>);
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| shared.invalidate())).is_err() {
        shared.close_fast();
    }
}
struct Route(i32);
impl Route {
    fn open() -> Result<Self, MonitorError> {
        // Darwin PF_ROUTE, SOCK_RAW, AF_UNSPEC. Nonblocking reads let the run loop and stop
        // channel make progress on the same worker thread.
        let fd = unsafe { socket(17, 3, 0) };
        if fd < 0 {
            return Err(MonitorError::Unavailable);
        }
        let route = Self(fd);
        let flags = unsafe { fcntl(fd, 3) }; // F_GETFL
        if flags < 0 || unsafe { fcntl(fd, 4, flags | 4) } < 0 {
            // F_SETFL, O_NONBLOCK
            return Err(MonitorError::Unavailable);
        }
        Ok(route)
    }
    fn drain(&self, shared: &Shared) -> Result<(), MonitorError> {
        let mut bytes = [0u8; 65536];
        // Bound each pass so a noisy route socket cannot starve shutdown or configuration events.
        for _ in 0..128 {
            let count = unsafe { read(self.0, bytes.as_mut_ptr().cast(), bytes.len()) };
            if count > 0 {
                shared.invalidate();
            } else if count == 0 {
                return Err(MonitorError::Unavailable);
            } else {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock {
                    return Ok(());
                }
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(MonitorError::Unavailable);
                }
            }
        }
        Ok(())
    }
}
impl Drop for Route {
    fn drop(&mut self) {
        unsafe {
            close(self.0);
        }
    }
}

fn run(
    shared: Arc<Shared>,
    stop: mpsc::Receiver<()>,
    ready: mpsc::SyncSender<Result<(), MonitorError>>,
) -> Result<(), MonitorError> {
    let route = match Route::open() {
        Ok(value) => value,
        Err(e) => {
            let _ = ready.send(Err(e));
            return Err(e);
        }
    };
    let name = CFString::new("Hoen network monitor");
    let patterns = CFArray::from_CFTypes(&[
        CFString::new("State:/Network/.*"),
        CFString::new("Setup:/Network/.*"),
    ]);
    let mut context = Context {
        version: 0,
        info: (&shared as *const Arc<Shared>).cast_mut().cast(),
        retain: None,
        release: None,
        description: None,
    };
    let store = unsafe {
        SCDynamicStoreCreate(
            kCFAllocatorDefault,
            name.as_concrete_TypeRef(),
            Some(changed),
            &mut context,
        )
    };
    if store.is_null() {
        let _ = ready.send(Err(MonitorError::Unavailable));
        return Err(MonitorError::Unavailable);
    }
    struct StoreGuard(Store);
    impl Drop for StoreGuard {
        fn drop(&mut self) {
            unsafe {
                CFRelease(self.0);
            }
        }
    }
    let _store = StoreGuard(store);
    if unsafe {
        SCDynamicStoreSetNotificationKeys(store, ptr::null(), patterns.as_concrete_TypeRef())
    } == 0
    {
        let _ = ready.send(Err(MonitorError::Unavailable));
        return Err(MonitorError::Unavailable);
    }
    let source = unsafe { SCDynamicStoreCreateRunLoopSource(kCFAllocatorDefault, store, 0) };
    if source.is_null() {
        let _ = ready.send(Err(MonitorError::Unavailable));
        return Err(MonitorError::Unavailable);
    }
    let loop_ref = unsafe { CFRunLoopGetCurrent() };
    unsafe {
        CFRunLoopAddSource(loop_ref, source, kCFRunLoopDefaultMode);
    }
    struct SourceGuard(core_foundation::runloop::CFRunLoopRef, CFRunLoopSourceRef);
    impl Drop for SourceGuard {
        fn drop(&mut self) {
            unsafe {
                CFRunLoopRemoveSource(self.0, self.1, kCFRunLoopDefaultMode);
                CFRelease(self.1.cast());
            }
        }
    }
    let _source = SourceGuard(loop_ref, source);
    let result = if ready.send(Ok(())).is_err() {
        Ok(())
    } else {
        loop {
            match stop.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break Ok(()),
                Err(mpsc::TryRecvError::Empty) => {}
            }
            if shared.state().closed {
                // Shutdown closes the state before it sends the stop signal. Allow that
                // signal to arrive rather than treating an orderly shutdown as a failure.
                match stop.recv_timeout(Duration::from_millis(100)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break Ok(()),
                    Err(mpsc::RecvTimeoutError::Timeout) => break Err(MonitorError::Unavailable),
                }
            }
            let status = unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.1, 1) };
            if status == 1 || status == 2 {
                break Err(MonitorError::Unavailable);
            }
            if let Err(e) = route.drain(&shared) {
                break Err(e);
            }
        }
    };
    result
}

pub(super) fn start() -> Result<NetworkMonitor, MonitorError> {
    let shared = Shared::new();
    let worker = shared.clone();
    let (stop_tx, stop_rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = oneshot::channel();
    std::thread::Builder::new()
        .name("hoen-macos-network-watch".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run(worker.clone(), stop_rx, ready_tx)
            }))
            .unwrap_or(Err(MonitorError::Unavailable));
            worker.close_and_notify();
            let _ = done_tx.send(result);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[hbb_common::tokio::test]
    async fn starts_and_shuts_down() {
        let monitor = NetworkMonitor::start().await.expect("start macOS monitor");
        assert!(!monitor.state().closed);
        monitor.shutdown().await.expect("monitor shutdown");
    }

    #[test]
    fn configuration_callback_invalidates_state() {
        let shared = Shared::new();
        let initial = shared.state();
        unsafe {
            changed(
                ptr::null(),
                ptr::null(),
                (&shared as *const Arc<Shared>).cast_mut().cast(),
            );
        }
        assert_ne!(shared.state(), initial);
    }
}
