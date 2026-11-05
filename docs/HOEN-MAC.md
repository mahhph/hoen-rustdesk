# macOS host and viewer integration

Status: source and build review only. This branch is not an integrated host,
and no service, privacy setting, listener, or firewall setting has been installed.
The earlier custom Hoen Remote prototype is preserved in the mailbox repository;
it is not the RustDesk engine.

## Current Mac build baseline

The CI macOS ARM64 job selects the `arm64-osx` vcpkg triplet, Rust 1.81,
Flutter 3.44.9, ScreenCaptureKit and macOS 12.3 minimum deployment target.
The vcpkg baseline is `9e593bb18ea69cc5095e012465dcd675a822ed0d`.
This Mac reports Apple Silicon, macOS 27.2 and Xcode 27.2. Rust is installed.
A complete local build additionally requires the pinned Flutter SDK, vcpkg and
its native libraries, build tools, and the CI-generated native bridge files.
Do not run bridge code generation: repository instructions require use of the
CI artifact. The available artifact identified in the handoff was generated
with Flutter 3.44.8; verify its digest and compatibility with the current 3.44.9
build and source before restoring only the generated paths. CI may produce a
newer artifact; do not assume an older artifact is current.

## macOS permissions and session boundaries

RustDesk checks Screen Recording, Accessibility and Input Monitoring through
platform APIs. The installed, signed app/helper identities need to be checked
in System Settings and verified in the actual target session. The existing
LaunchDaemon and LaunchAgent installation paths require local administrator
access. Their presence alone does not demonstrate that capture or control works
at a locked screen or the login window. Test signed-in, locked and signed-out
states separately; do not change FileVault or bypass macOS privacy protections.

## Authentication and network review

At commit `92dfd7e4aabe746f4c3acfbf4dd005d8aaedcdc6`, the upstream direct
IP/domain branches in `src/client.rs` return a TCP connection before the shared
secure handshake. `src/rendezvous_mediator.rs` uses `listen_any` for its direct
server. These paths are shared across desktop platforms, including macOS; neither
a direct address nor a listener proves approved-home-network admission or a
verified mailbox identity. Do not expose the direct server as a Hoen host until
the planned authenticated handshake, grant validation, transport provenance,
and approved-interface enforcement are implemented and tested. Follow
`HOEN-AUTH.md`; do not use legacy fallback in Hoen mode.

## Evidence and remaining gates

The isolated `hoen-mailbox-auth` crate's two tests pass on this Mac. This checks
its canonical encoding and proof verification, not runtime authentication or a
RustDesk session. A production-signed Mac build, bridge and dependency validation,
actual capture/input/clipboard behavior, service lifecycle, local-network policy,
and two-machine tests remain outstanding. Native RustDesk clipboard formats are
allowed; separate file-transfer sessions remain outside the current scope.
