# macOS host and viewer integration

Current seq210 integration supersedes earlier network policy and readiness notes below.
The native TCP transport checks its configured local binding; adapter/network IDs,
SSID, interface type, OS category and peer route are not authorization checks.
Mac retains Keychain enrollment and the development app namespace, but no longer
queries Wi-Fi identifiers or automatically selects a pinned-network address.
Network notifications may terminate a session; reconnection requires fresh proof.
The configured bind address does not automatically follow DHCP. Relay is unimplemented.
Earlier seq191/193 admission descriptions are historical and superseded.

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
a direct address nor a listener proves direct-LAN admission or a
verified mailbox identity. Do not expose the direct server as a Hoen host until
the planned authenticated handshake, grant validation, transport provenance,
and actual socket/interface and on-link route enforcement are implemented and tested. Follow
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
a macOS direct-LAN provider, actual local/peer route checks and
network-change revalidation are implemented. Windows adapter/network GUIDs
are not macOS approval identities and must not become policy pins. Coordinate any shared policy
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

## Direct-LAN clarification (mailbox seq191)

Seq191, request `683e1f69-ab87-4691-95c4-24f3b3ba57dc`, supersedes
the home-Wi-Fi, approved-SSID/adapter and Windows Private-profile assumptions,
including seq189's request to change MeshMonkey's profile. Any same LAN over
physical Wi-Fi or Ethernet is in scope. Do not pin an SSID, network GUID,
named network or adapter, and do not change a network profile for authorization.
Actual bound socket/interface and on-link route checks, cryptographic mailbox
identity and single-use grant proof remain required. Hoen mode has no public
rendezvous/relay, router exposure, password or manual-approval fallback.
Windows firewall provisioning is a separate reviewed integration step.

VPN is acceptable future scope under a separately reviewed transport policy;
the direct-LAN helper may reject VPN until implemented. The Mac provider still
returns `SnapshotUnavailable`, so no Mac admission behavior changes here.
Seq193 published commits `b9ade1684` and `d750e367e` on
`codex/area51-hoen-admission-guard`. Their five code/build file changes were
reviewed and applied locally without conflicts, preserving the existing Mac
documentation edits. Legacy host login rejects mailbox proofs; the direct-LAN
helper removes network/profile pins and checks physical Wi-Fi or Ethernet.
Area51's 17/17 feature-gated tests remain sender-reported, not locally reproduced.
Host listener, viewer login, enrollment and two-machine acceptance remain
incomplete; session readiness is not established.

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


### macOS monitor startup investigation (mailbox seq217, 2026-11-06)

On macOS 27.2 (26B123), arm64, uid 501, inside the local Codex
workspace-write execution sandbox, the isolated harness compiling the actual
`network_monitor.rs` and `macos_network_monitor.rs` ran five tests: four passed;
`starts_and_shuts_down` failed with `MonitorError::Unavailable`.
A direct native-call probe in the same execution context identified the first
startup failure: `socket(17, 3, 0)` (`PF_ROUTE`, `SOCK_RAW`, `AF_UNSPEC`)
returned -1 with errno 1 (`EPERM`, Operation not permitted). `Route::open`
therefore exits before its `fcntl` calls and before any dynamic-store
subscription or run-loop-source setup. A separate `SCDynamicStoreCreate`
probe succeeded with `SCError() == 0`; notification subscription and source
creation are not established by that probe.

This establishes the failing syscall in the agent execution environment. It
does not establish whether the restriction also applies to the intended signed
application or an ordinary unsandboxed user shell. No normal-user-session
startup result is available yet, so runtime readiness remains unverified.
Do not infer that the connected network type caused the error or change
network settings to address it. The monitor provides invalidation, not network
authorization. Retain the fail-closed error rather than bypass routing events.

Remaining verification: run the existing `starts_and_shuts_down` test in an
ordinary user execution context, then the integrated native feature suite once
the previously reported native dependency build blockers are resolved. If
`EPERM` persists there, inspect that process's sandbox/entitlement policy before
choosing a narrowly scoped implementation or packaging fix. This investigation
changes documentation only; no runtime path, network settings, entitlements,
service, or watcher configuration changed. Harness log:
`/private/tmp/hoen-seq217-monitor.log`.

### Integrated Mac test update (2026-11-06)

With the installed ARM64 vcpkg dependencies and ordinary local socket access,
the integrated source based on Area 51's merged PR #4 passed all 30 selected
Mac development-feature Hoen tests in an optimized Rust 1.81 test build with
release LTO disabled. This includes the actual macOS network monitor startup
and shutdown, Keychain round trip, binding policy, and encrypted handshake
tests. The authentication and history helper suites passed 8 and 10 tests,
respectively, and the isolated build-script checks passed 4 tests.

The monitor failure above was reproduced only in the restricted execution
sandbox. The passing test demonstrates startup in the less-restricted command
environment; it does not establish the behavior of a signed or sandboxed app.
It also does not constitute an installed-host or two-machine session test.
