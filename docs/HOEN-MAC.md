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

## Native adapter validation at 4095dc5 (mailbox seq165)

The Mac branch fast-forwarded to `4095dc54ac21e7f63f1b9cde7be8d17569416606`.
Later Windows host/viewer hooks require a separately identified checkpoint.
The local Podfile minimum is 12.3, matching the ARM64 CI patch and
ScreenCaptureKit baseline; this only changes macOS dependency resolution.

Portable `cargo +stable test --locked --manifest-path
libs/hoen-mailbox-auth/Cargo.toml` passed 7 tests (exit 0, 7.85 seconds).
The corresponding history manifest passed 9 tests (exit 0, 6.93 seconds).
Compiler: rustc 1.99.1, aarch64 Apple Darwin; this is not Rust 1.81 validation.
Commands and logs are retained locally under `.hoen-mac-build/seq165/`
in the parent workspace. Portable tests do not compile the native runtime adapters.

`src/hoen/credentials.rs` exports `ProtectedStore` only on Windows. macOS
needs a Keychain provider with separate viewer and host/helper identities,
explicit provisioning/access policy and errors for locked or denied access.
Do not substitute plaintext config storage. Device private keys and mailbox
credentials remain local; mailbox identity is cryptographic, not a display name.

`network::verify_binding` and `network::admit_socket` return
`SnapshotUnavailable` on macOS. Both host and viewer must remain denied until
an approved macOS interface/network policy, actual local/peer route checks and
network-change revalidation are implemented. Windows adapter/network GUIDs
are not an implemented macOS approval identity. Coordinate any shared policy
contract change before coding it.

The seq159 TLS transition remains preparation only. Strict HTTPS clients need
an explicitly provisioned trust root and a matching IP/DNS SAN leaf. The old
SAN-less API certificate cannot be repaired by installing a root. Stage public
trust and obtain consumer acknowledgments before a coordinated Linux cutover;
do not modify watcher profiles or rotate live trust as part of desktop builds.

Remaining acceptance includes native adapter compilation, signed app packaging,
viewer and host flows, denied/revoked capture/input permissions, native clipboard
formats, reconnect/lock/login behavior and metadata-only history recovery.
Clipboard payloads must never enter history. No host installation or unattended
readiness follows from these test results.

Full app probes used `cargo +stable check --locked --features
flutter,hoen-mailbox --lib` (exit 101, 142.48 seconds) and feature-off
`cargo +stable check --locked --features flutter --lib` (exit 101,
1.31 seconds). Feature-on failed in magnum-opus build.rs:71, missing
`/opt/homebrew/Cellar/opus`; feature-off reported the same and
scrap build.rs:89, missing `/opt/homebrew/Cellar/libyuv`. These were
baseline environment probes without the isolated vcpkg environment; its
arm64 installed libraries are also absent. Supply native dependencies before
repeating the native adapter build. No app or package artifact was produced.
Ruby Podfile syntax validation and `git diff --check` passed.
Regression surface: only the Podfile deployment minimum changes existing
macOS build behavior; shared runtime/protocol and feature-off code are untouched.

## Mac verification of shared checkpoint 4095dc5

On Apple Silicon macOS 27.2 with Xcode 27.2, merge `bf8406255930c8f88fd14b48502adeb1a566a71b`
compiled and passed 12 selected shared `hoen::` tests with Rust 1.81.0 using
`cargo test --locked --release --lib --features
flutter,hwcodec,unix-file-copy-paste,screencapturekit,hoen-mailbox hoen::`.
The first run took 211.97 seconds, with `CARGO_PROFILE_RELEASE_LTO=false`; this
is test-build evidence, not a shipping-profile build. The Mac vcpkg environment
with the project's pinned ARM64 libraries was supplied. The earlier missing
`opus`/`libyuv` probe described above did not use that environment.

At the same checkpoint the standalone mailbox authentication helper passed
7 tests and history helper passed 9 tests. These tests do not enable a runtime
connection, implement the Mac protected credential store or network provider,
or validate the native UI/host behavior. Existing per-machine build-only changes
were preserved outside the commits; no host was installed.
