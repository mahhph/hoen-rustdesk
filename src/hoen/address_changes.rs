//! Address-change hints wake reconciliation; they never authorize or close a session.
use hbb_common::tokio::time::{self, Duration, Interval};

pub(crate) struct AddressChanges {
    poll: Interval,
    #[cfg(windows)]
    notifications: windows::Notifications,
    #[cfg(target_os = "macos")]
    notifications: macos::Notifications,
}

impl AddressChanges {
    pub async fn new() -> Self {
        let mut poll = time::interval(Duration::from_secs(15));
        poll.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        Self {
            poll,
            #[cfg(windows)]
            notifications: windows::Notifications::start().await,
            #[cfg(target_os = "macos")]
            notifications: macos::Notifications::start(),
        }
    }

    pub async fn tick(&mut self) {
        #[cfg(any(windows, target_os = "macos"))]
        hbb_common::tokio::select! {
            _ = self.poll.tick() => {},
            _ = self.notifications.changed() => {},
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        self.poll.tick().await;
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use hbb_common::{libc, tokio::{io::unix::AsyncFd, time::Instant}};
    use std::os::unix::{io::FromRawFd, net::UnixDatagram};

    // Routing messages are hints only. Runtime reconciliation still resolves
    // the route to the mailbox and never closes established session tasks.
    fn relevant(bytes: &[u8]) -> bool {
        if bytes.len() < 4 || bytes[2] != libc::RTM_VERSION as u8 { return false; }
        matches!(bytes[3] as i32, libc::RTM_ADD | libc::RTM_DELETE | libc::RTM_CHANGE |
            libc::RTM_NEWADDR | libc::RTM_DELADDR | libc::RTM_IFINFO | libc::RTM_IFINFO2)
    }

    pub(super) struct Notifications {
        socket: Option<AsyncFd<UnixDatagram>>,
        due: Option<Instant>,
    }
    impl Notifications {
        fn wrap(socket: UnixDatagram) -> std::io::Result<AsyncFd<UnixDatagram>> {
            socket.set_nonblocking(true)?;
            AsyncFd::new(socket)
        }
        pub(super) fn start() -> Self {
            let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
            let socket = if fd < 0 { None } else {
                // UnixDatagram supplies safe ownership and recv for this nonblocking socket;
                // no address is constructed and nothing is transmitted to the route socket.
                let socket = unsafe { UnixDatagram::from_raw_fd(fd) };
                Self::wrap(socket).ok()
            };
            if socket.is_none() {
                hbb_common::log::warn!("Address notifications unavailable; periodic checks remain active");
            }
            Self { socket, due: None }
        }

        pub(super) async fn changed(&mut self) {
            while self.due.is_none() {
                let Some(socket) = &self.socket else { return std::future::pending::<()>().await; };
                let mut ready = match socket.readable().await {
                    Ok(ready) => ready,
                    Err(_) => { self.socket = None; continue; }
                };
                let mut bytes = [0u8; 4096];
                let result = ready.try_io(|inner| inner.get_ref().recv(&mut bytes));
                drop(ready);
                match result {
                    Ok(Ok(n)) if relevant(&bytes[..n]) => self.due = Some(Instant::now() + Duration::from_secs(1)),
                    Ok(Ok(_)) | Err(_) => {},
                    Ok(Err(_)) => { self.socket = None; }
                }
            }
            // Keep the deadline across select! cancellation by a poll or accept.
            if let Some(due) = self.due { time::sleep_until(due).await; }
            // Discard queued hints from the same burst. Reconciliation observes
            // current state, not the event contents. Limit draining so a noisy
            // route socket cannot starve the host loop.
            if let Some(socket) = &self.socket {
                let mut bytes = [0u8; 4096];
                for _ in 0..128 {
                    match socket.get_ref().recv(&mut bytes) {
                        Ok(_) => {},
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            }
            self.due = None;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[hbb_common::tokio::test]
        async fn injected_hint_debounces_and_survives_cancellation() {
            let (read, write) = UnixDatagram::pair().unwrap();
            let mut notifications = Notifications { socket: Some(Notifications::wrap(read).unwrap()), due: None };
            write.send(&[4, 0, libc::RTM_VERSION as u8, libc::RTM_NEWADDR as u8]).unwrap();
            assert!(time::timeout(Duration::from_millis(20), notifications.changed()).await.is_err());
            time::timeout(Duration::from_secs(3), notifications.changed()).await.unwrap();
        }
        #[hbb_common::tokio::test]
        async fn missing_socket_falls_back_to_poll() {
            let mut changes = AddressChanges { poll: time::interval(Duration::from_millis(10)),
                notifications: Notifications { socket: None, due: None } };
            time::timeout(Duration::from_secs(1), changes.tick()).await.unwrap();
            time::timeout(Duration::from_secs(1), changes.tick()).await.unwrap();
        }
        #[hbb_common::tokio::test]
        async fn native_route_socket_opens_without_network_changes() {
            let notifications = Notifications::start();
            assert!(notifications.socket.is_some());
        }
        #[test]
        fn filters_short_wrong_version_and_irrelevant_messages() {
            assert!(!relevant(&[]));
            assert!(!relevant(&[4, 0, 0, libc::RTM_NEWADDR as u8]));
            assert!(!relevant(&[4, 0, libc::RTM_VERSION as u8, libc::RTM_GET as u8]));
            assert!(relevant(&[4, 0, libc::RTM_VERSION as u8, libc::RTM_NEWADDR as u8]));
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use ::windows::Win32::{
        Foundation::HANDLE,
        NetworkManagement::IpHelper::{
            CancelMibChangeNotify2, NotifyUnicastIpAddressChange, MIB_NOTIFICATION_TYPE,
            MIB_UNICASTIPADDRESS_ROW,
        },
        Networking::WinSock::AF_UNSPEC,
    };
    use hbb_common::tokio::{sync::Notify, task::spawn_blocking, time::Instant};

    static CHANGED: Notify = Notify::const_new();

    // Context and row pointers are intentionally unused: Windows' row may be incomplete.
    // The process-lifetime notifier also makes a late callback safe if cancellation fails.
    unsafe extern "system" fn on_change(
        _: *const std::ffi::c_void,
        _: *const MIB_UNICASTIPADDRESS_ROW,
        _: MIB_NOTIFICATION_TYPE,
    ) {
        CHANGED.notify_one();
    }

    struct Subscription(isize);
    impl Subscription {
        fn register(initial: bool) -> ::windows::core::Result<Self> {
            let mut handle = HANDLE::default();
            unsafe {
                NotifyUnicastIpAddressChange(
                    AF_UNSPEC,
                    Some(on_change),
                    None,
                    initial,
                    &mut handle,
                )
                .ok()?;
            }
            Ok(Self(handle.0 as isize))
        }
    }
    impl Drop for Subscription {
        fn drop(&mut self) {
            // Drop is on the runtime owner, never on the Windows callback thread.
            if unsafe { CancelMibChangeNotify2(HANDLE(self.0 as *mut std::ffi::c_void)).ok() }
                .is_err()
            {
                hbb_common::log::warn!("Address notification cancellation failed");
            }
        }
    }

    pub(super) struct Notifications {
        subscription: Option<Subscription>,
        due: Option<Instant>,
    }
    impl Notifications {
        pub async fn start() -> Self {
            let subscription = match spawn_blocking(|| Subscription::register(false)).await {
                Ok(Ok(subscription)) => Some(subscription),
                _ => {
                    hbb_common::log::warn!(
                        "Address notifications unavailable; periodic checks remain active"
                    );
                    None
                }
            };
            Self {
                subscription,
                due: None,
            }
        }

        pub async fn changed(&mut self) {
            if self.subscription.is_none() {
                std::future::pending::<()>().await;
            }
            if self.due.is_none() {
                CHANGED.notified().await;
                self.due = Some(Instant::now() + Duration::from_secs(1));
            }
            // Keep the deadline in the owner: cancellation by listener traffic or the
            // fallback poll must not consume a hint and discard its pending debounce.
            if let Some(due) = self.due {
                time::sleep_until(due).await;
            }
            self.due = None;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[hbb_common::tokio::test]
        async fn os_subscription_wakes_and_survives_wait_cancellation_without_network_mutation() {
            let subscription = spawn_blocking(|| Subscription::register(true))
                .await
                .unwrap()
                .unwrap();
            let mut notifications = Notifications {
                subscription: Some(subscription),
                due: None,
            };
            assert!(
                time::timeout(Duration::from_millis(20), notifications.changed())
                    .await
                    .is_err()
            );
            time::timeout(Duration::from_secs(3), notifications.changed())
                .await
                .unwrap();
            drop(notifications);
        }

        #[hbb_common::tokio::test]
        async fn missing_subscription_still_allows_periodic_reconciliation() {
            let mut changes = AddressChanges {
                poll: time::interval(Duration::from_millis(10)),
                notifications: Notifications {
                    subscription: None,
                    due: None,
                },
            };
            time::timeout(Duration::from_secs(1), changes.tick())
                .await
                .unwrap();
            time::timeout(Duration::from_secs(1), changes.tick())
                .await
                .unwrap();
        }
    }
}
