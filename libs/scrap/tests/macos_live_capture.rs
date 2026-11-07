//! Opt-in physical-display integration test. It never writes frame pixels to disk.
#![cfg(target_os = "macos")]

use scrap::{Capturer, Display, TraitCapturer};
use std::{
    io, thread,
    time::{Duration, Instant},
};

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGPreflightScreenCaptureAccess() -> bool;
}

// The standalone scrap test does not link the app's Objective-C helper. This
// test never calls Display::scale; the symbol is needed by the linked library.
#[no_mangle]
extern "C" fn BackingScaleFactor(_display: u32) -> f32 {
    1.0
}

#[test]
#[ignore = "requires an unlocked GUI session and Screen Recording permission for the test process"]
fn primary_display_produces_a_frame() -> io::Result<()> {
    if !unsafe { CGPreflightScreenCaptureAccess() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Screen Recording permission is not granted to this test process",
        ));
    }
    if !scrap::quartz::Display::primary().is_active() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "macOS reports the primary display is inactive; no display is available to capture",
        ));
    }
    let display = Display::primary()?;
    eprintln!("primary display: {}x{}", display.width(), display.height());
    let mut capturer = Capturer::new(display)?;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        match capturer.frame(Duration::from_millis(100)) {
            Ok(frame) if frame.valid() => {
                eprintln!("received a valid capture frame after {:?}", start.elapsed());
                return Ok(());
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(err),
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "no valid frame received within 15 seconds after capture initialization",
    ))
}
