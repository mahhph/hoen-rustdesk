//! Request an ordinary macOS display wake after a viewer is authenticated.
use std::{process::Command, time::Duration};

const WAKE_SECONDS: &str = "10";
const DISPLAY_POLLS: usize = 20;
const DISPLAY_POLL_INTERVAL: Duration = Duration::from_millis(250);

async fn wait_for_active(
    mut is_active: impl FnMut() -> bool,
    polls: usize,
    interval: Duration,
) -> bool {
    for _ in 0..polls {
        if is_active() {
            return true;
        }
        hbb_common::tokio::time::sleep(interval).await;
    }
    is_active()
}

pub(crate) async fn request() {
    match Command::new("/usr/bin/caffeinate")
        .args(["-u", "-t", WAKE_SECONDS])
        .spawn()
    {
        Ok(mut child) => {
            std::thread::spawn(move || match child.wait() {
                Ok(status) if status.success() => {}
                Ok(status) => hbb_common::log::warn!("Mac display wake exited with {status}"),
                Err(error) => hbb_common::log::warn!("Mac display wake wait failed: {error}"),
            });
        }
        Err(error) => hbb_common::log::warn!("Mac display wake request failed: {error}"),
    }
    let active = wait_for_active(
        || scrap::quartz::Display::primary().is_active(),
        DISPLAY_POLLS,
        DISPLAY_POLL_INTERVAL,
    )
    .await;
    if active {
        hbb_common::log::info!("Mac display wake: primary display is active");
    } else {
        hbb_common::log::warn!("Mac display wake: no active primary display after five seconds");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[hbb_common::tokio::test]
    async fn checks_until_display_becomes_active() {
        let mut checks = 0;
        assert!(
            wait_for_active(
                || {
                    checks += 1;
                    checks == 3
                },
                4,
                Duration::ZERO
            )
            .await
        );
        assert_eq!(checks, 3);
    }

    #[hbb_common::tokio::test]
    async fn inactive_display_wait_is_bounded() {
        let mut checks = 0;
        assert!(
            !wait_for_active(
                || {
                    checks += 1;
                    false
                },
                4,
                Duration::ZERO
            )
            .await
        );
        assert_eq!(checks, 5);
    }
}
