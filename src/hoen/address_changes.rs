//! Address-change hints wake reconciliation; they never authorize or close a session.
use hbb_common::tokio::time::{self, Duration, Interval};

pub(crate) struct AddressChanges {
    poll: Interval,
    #[cfg(windows)]
    notifications: windows::Notifications,
}

impl AddressChanges {
    pub async fn new() -> Self {
        let mut poll = time::interval(Duration::from_secs(15));
        poll.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        Self {
            poll,
            #[cfg(windows)]
            notifications: windows::Notifications::start().await,
        }
    }

    pub async fn tick(&mut self) {
        #[cfg(windows)]
        hbb_common::tokio::select! {
            _ = self.poll.tick() => {},
            _ = self.notifications.changed() => {},
        }
        #[cfg(not(windows))]
        self.poll.tick().await;
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
