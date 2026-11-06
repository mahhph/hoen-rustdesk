# Hoen Windows host: build and integration notes

Inspection applies to checkout `cbde394`; no build, executable, installation, listener, or unattended session was tested here. The local `libs/hbb_common` submodule is initialized at `fae47e024dd83cef6aaecde0aa7d11731df11649`. On this machine the user-local Rust 1.75.0 x64 MSVC toolchain is installed and verified (`rustc +1.75.0 --version`); the stable default remains unchanged. Rustup attempted a self-update and reported a pre-existing `cargo-miri.exe` link conflict after installing the toolchain. Rust and Cargo are available, Visual Studio's installer reports VC x86/x64 tools version 17.14, `VCPKG_ROOT` is unset and Clang and protoc were not found on PATH. Visual Studio provides CMake and Ninja. Python and Flutter were subsequently installed under `%LOCALAPPDATA%\HoenBuildTools` and are available when their directories are added to the current shell PATH; WindowsApps Python aliases are not interpreters. PATH absence does not prove a tool is absent elsewhere. Do not put credentials in build commands, logs, or this document.

## Reproduce the x64 Windows Flutter build

Use a clean, non-production build environment and the checked-in CI workflow as the source of truth: [flutter-build.yml](../.github/workflows/flutter-build.yml), [bridge.yml](../.github/workflows/bridge.yml), [vcpkg.json](../vcpkg.json), and [build.py](../build.py). The application is not ready for deployment merely because it builds.

1. Check out the intended fork commit, then initialize the pinned submodule with `git submodule update --init --recursive`; confirm `git submodule status` has no leading `-`, `+`, or `U`. Record both commit IDs.
2. Provision a Windows x64 build environment with MSVC x64 desktop C++ tools/Windows SDK, working Python 3, Git, Rust `x86_64-pc-windows-msvc`, LLVM/Clang 15.0.6, and Flutter 3.24.5. The x64 CI uses Rust 1.75. Confirm `rustc --version`, `cargo --version`, `flutter doctor -v`, `python --version`, and C++ build tools. Rust 1.75 is the CI selection, not a claim that newer local toolchains work.
3. Provision vcpkg at commit `9e593bb18ea69cc5095e012465dcd675a822ed0d`, bootstrap it, set `VCPKG_ROOT`, and from the repository root run `& "$env:VCPKG_ROOT/vcpkg.exe" install --triplet x64-windows-static --x-install-root="$env:VCPKG_ROOT/installed"`. The manifest includes libvpx, libyuv, opus, aom, libjpeg-turbo, mfx-dispatch and Windows static FFmpeg features; its baseline and overlay ports/triplets are significant. Record tool versions and dependency revisions.
4. CI restores bridge files from the separate [bridge workflow](../.github/workflows/bridge.yml); these generated files are gitignored. Use the CI-generated `bridge-artifact` corresponding to this same source revision. **Do not run `flutter_rust_bridge_codegen` locally**: this repository's `AGENTS.md` expressly forbids it. CI's x64 job also installs a RustDesk custom Flutter engine and applies the checked-in Flutter dropdown patch; reproduce those steps in an isolated SDK as specified in the workflow. The distribution workflow separately builds a topmost-window artifact; follow that workflow and package steps before claiming a full installer.
5. From the root, after the prerequisites and bridge artifacts are in place, the x64 CI build invocation is `python .\build.py --portable --flutter --skip-portable-pack --hwcodec --vram`. The build script runs a locked Rust release library build and `flutter build windows --release`; the CI then stages `flutter/build/windows/x64/runner/Release`. CI includes additional driver/packaging and signing steps; a staged directory alone is not a tested installer. Run applicable CI test commands and retain only non-sensitive test output.

These are CI-derived instructions, not commands validated in this environment. Do not run `--install-service`, `--install`, an installer, or firewall configuration against either target until the Hoen policy and rollback are implemented and the package is reviewed.

## Existing Windows behavior and required validation

`src/platform/windows.rs` defines an SCM service, a session-monitoring loop, IPC authorization checks and a privileged worker launch path using native `LaunchProcessWin`; it also refers to desktop selection and Winlogon. This is useful existing machinery, not proof that this fork works in any particular protected session or meets the Hoen security model. The service reports Running before its initial worker launch, so Hoen readiness must be based on verified worker/host initialization, not SCM state alone. Do not disable UAC or change secure-desktop policy.

After a reproducible, reviewed Hoen package exists, validate installation and rollback on an isolated Windows Home/Pro test machine: record original service/configuration state; install the reviewed package using its documented installer flow; verify service identity, automatic startup, protected executable/config permissions, worker session, authenticated IPC and clean uninstall; then reboot and repeat connection tests in both directions on the two target devices. Test signed-in, locked, signed-out, login, UAC, logout/login, restart, worker failure and pressed-key cleanup separately. Capture evidence of observed results without saving screen pixels, keystrokes, clipboard contents, passwords, or device secrets. None of these acceptance tests has been run.

## Home network and clipboard

The upstream direct-access loop in `src/rendezvous_mediator.rs` calls `listen_any` when direct access is enabled; this is not binding to the explicitly approved home interface. The code also has rendezvous, UDP punch and relay paths (`src/rendezvous_mediator.rs`, `src/server.rs`). The `whitelist` check in `src/server/connection.rs` admits all when empty or containing `0.0.0.0`; an address range or a generic Wi-Fi/private-IP check cannot identify the approved home network. Hoen needs an explicit policy that disables all non-approved transports and discovery, binds only the approved interface/address, verifies IPv4 and IPv6 peers, fails closed on network changes, and is complemented by reviewed host firewall rules. Prove no public rendezvous/relay, UPnP or port forwarding is used; do not assume direct mode disables them. Authentication and peer identity pinning are separate from network admission.

Stock rich clipboard support is permitted: `src/clipboard.rs` handles text, HTML, RTF, images, file URLs and special formats. Clipboard and file-transfer permissions are distinct (`enable-clipboard` and `enable-file-transfer` in `libs/base/src/config/keys.rs`), so test the actual chosen permissions and avoid logging clipboard payloads. Do not add a text-only filter.
A useful next coding slice is a fail-closed Hoen policy gate with narrowly scoped hooks at the direct listener and connection admission: explicit approved local address/interface plus peer policy, no rendezvous/relay path under Hoen mode, and tests for disabled/missing/changed configuration and both IP families. The host must not advertise readiness until mailbox registration/secrets integration, enrolled peer authentication and real Windows acceptance tests are complete. No existing runtime path was modified by this document.


## User-local setup steps

The preflight was rerun after the Rust installation and recognizes the pinned toolchain. Run `powershell -NoProfile -File .\scripts\hoen-build-preflight.ps1` from the fork root. It exits 1 when required checks are missing, 0 when the file/tool checks pass; manual provenance and an actual build remain necessary even on 0. It reads only metadata, tool versions and files; it neither installs nor builds. PATH checks can miss tools installed elsewhere. The vcpkg check samples selected packages rather than proving the complete manifest, and presence of generated bridge files does not verify their provenance.

For an isolated setup, pick a writable user-owned tools directory and avoid changing the system PATH. The following are proposed setup steps, not actions taken here:

1. Use rustup's per-user installation: `rustup toolchain install 1.75.0 --profile minimal --target x86_64-pc-windows-msvc`. In the build shell set `$env:RUSTUP_TOOLCHAIN = '1.75.0-x86_64-pc-windows-msvc'` so `build.py` actually uses the CI toolchain. Set this only for the current shell.
2. Obtain official [Python 3.12 releases](https://www.python.org/downloads/release/python-31210/) and install Python 3.12.10 for the current user only, or unpack an appropriate standalone distribution. Put its directory first in this shell's PATH, and run `python --version`. Do not rely on WindowsApps aliases.
3. Obtain [LLVM 15.0.6 Windows binaries](https://github.com/llvm/llvm-project/releases/tag/llvmorg-15.0.6), provision them in the user-owned tools directory, add `bin` to this shell's PATH and `LIBCLANG_PATH`, and confirm `clang --version`. Avoid a system-wide PATH change.
4. Obtain the official [Flutter SDK archive](https://docs.flutter.dev/install/archive), select Windows stable **3.24.5**, extract it into the user-owned tools directory, and prepend its `bin` to this shell's PATH. Run `flutter precache --windows` and follow the x64 custom-engine and dropdown patch steps in the pinned CI workflow on this isolated SDK. Verify the downloaded custom engine's provenance: CI references a mutable `main` release, so record the exact artifact hash before using it.
5. Create a separate user-owned vcpkg checkout, run `git clone https://github.com/microsoft/vcpkg.git <local-vcpkg-path>`, then `git -C <local-vcpkg-path> checkout --detach 9e593bb18ea69cc5095e012465dcd675a822ed0d`. Run `<local-vcpkg-path>\bootstrap-vcpkg.bat`, set `$env:VCPKG_ROOT` to that absolute path for the current shell, and run the manifest command in step 3 above from the fork root. vcpkg builds native packages and downloads dependencies into that local directory; inspect upstream instructions and the package sources before doing so.
6. Obtain the **matching-source** `bridge-artifact` from an authorized CI run of [bridge.yml](../.github/workflows/bridge.yml), restore its six paths at the fork root, and record the source commit and artifact digest. Locally running codegen is explicitly prohibited by `AGENTS.md`. Until an appropriate artifact is available, this is a separate blocker even after tools are installed.
7. Run the preflight again, resolve its missing items, verify the remaining manual items, then attempt the CI build command above. Never treat a passing preflight as proof of a successful build or secure deployment.

### Bridge CI trigger investigation

`bridge.yml` declares `workflow_call` only; it is not directly dispatchable. It builds on GitHub-hosted Ubuntu, generates the bridge using its pinned tool versions, and uploads artifacts; the workflow itself contains no signing, deployment or secret use. The existing manually dispatchable `flutter-ci.yml` calls the full Flutter build with `upload-artifact: false`, which in turn calls the bridge workflow. Its publishing and signing steps are gated by that false input, but it starts a much larger build matrix. A small manually dispatched wrapper that calls only `bridge.yml` with read-only repository permissions would avoid the unrelated jobs; it would need to be committed to a branch and reviewed before use. No workflow was edited or triggered. Confirm the CI run checkout SHA and bridge artifact digest before restoring generated files. Workflow behavior depends on repository Actions settings and permissions, which have not been verified here.

### Confirmed local SDKs

Official Python 3.12.10 x64 **embeddable** ZIP was extracted to `%LOCALAPPDATA%\HoenBuildTools\python-3.12.10`. Its MD5 matched the [python.org release listing](https://www.python.org/downloads/release/python-31210/) (`fe8ef205f2e9c3ba44d0cf9954e1abd3`); computed SHA-256 is `4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3`. `python.exe --version` and `build.py --print-features` succeeded. This isolated distribution has no `pip`; packaging steps that require pip need a separately provisioned full per-user Python or another verified approach.

Official Flutter 3.24.5 x64 archive was extracted to `%LOCALAPPDATA%\HoenBuildTools\flutter-3.24.5\flutter`. Its SHA-256 `b8a7485acd3c6fb23a76b7ac09f89e8d93d62fbff7147c6f5f8c5686d949eeac` matched the [official Windows release manifest](https://storage.googleapis.com/flutter_infra_release/releases/releases_windows.json); framework revision `dec2ee5c1f98f8e84a7d5380c05eb8a3d0a81668` and `flutter --version` were verified. The root task later applied the checked-in dropdown patch and installed the custom x64 engine as documented below.

To use these installations in the current PowerShell process only:

```powershell
$tools = Join-Path $env:LOCALAPPDATA 'HoenBuildTools'
$env:PATH = (Join-Path $tools 'python-3.12.10') + ';' + (Join-Path $tools 'flutter-3.24.5\flutter\bin') + ';' + $env:PATH
$env:RUSTUP_TOOLCHAIN = '1.75.0-x86_64-pc-windows-msvc'
.\scripts\hoen-build-preflight.ps1
```

With those process-local variables, the preflight recognizes Python and Flutter. LLVM/Clang and pinned vcpkg are now installed locally; the vcpkg package build completed successfully as described below. The matching bridge artifacts were restored as described below; the custom Flutter engine and patch are installed as documented below. The application build outcome is recorded below; no host service or firewall action was performed.

### Matching bridge artifact restored

The parent task restored the six expected generated paths without overwriting existing files from successful CI run `42115480465`, source commit `0272f0270767f839e828a68861635df517e6eeaf`, artifact `13456556600`, archive SHA-256 `92acc800f0994474c7d74bd74843e54957060e1ebc8f01c4d4f09107d0f93f2f`. The generated files are ignored by Git. Confirm that the build's source commit matches that CI commit and that later FFI changes do not make the artifact stale; file presence alone does not establish compatibility. Windows and ARM64 Mac bridge artifacts were published by that run.

### Native prerequisites on Lenovo

The user-local vcpkg checkout at `%LOCALAPPDATA%\HoenBuildTools\vcpkg` is bootstrapped at commit `9e593bb18ea69cc5095e012465dcd675a822ed0d`. Bootstrap validated the downloaded executable signature; vcpkg executable SHA-256 is `13b8175e99a884c5ad34249218754b45541a1a63f216e92603aee57a285ac741`. LLVM 15.0.6 was extracted without running its installer to `%LOCALAPPDATA%\HoenBuildTools\llvm-15.0.6`; `clang --version` reports 15.0.6. The official LLVM archive SHA-256 `22e2f2c38be4c44db7a1e9da5e67de2a453c5b4be9cf91e139592a63877ac0a2` matched the [LLVM contributor's published hash](https://github.com/llvm/llvm-project/issues/152849). 7-Zip 25.01 was extracted into the same tools directory to unpack LLVM; no machine-wide installation or PATH change was made.

The native vcpkg manifest build uses process-local `VCPKG_ROOT`, `VCPKG_DEFAULT_HOST_TRIPLET=x64-windows-static`, `LIBCLANG_PATH`, PATH and binary cache; its log is `%LOCALAPPDATA%\HoenBuildTools\vcpkg-native-build.log`. A successful bootstrap does not imply successful package builds. The successful run is logged as `vcpkg-native-build-fifth.log`: all 16 packages completed and vcpkg exited 0. Earlier attempts failed on Git lazy-fetch DNS errors and then a missing local cache directory; pinned port trees were fetched and the cache directory created before retry. A subsequent preflight with process-local tool paths and `VCPKG_ROOT` exited 0. The preflight's package checks are not a substitute for that outcome. The custom x64 Flutter engine and dropdown patch are installed as documented below.



### Flutter x64 engine and patch

The root task ran `flutter precache --windows` successfully, applied the checked-in Flutter 3.24.5 dropdown patch after `git apply --check`, and confirmed its isolated SDK diff contains only that patch (9 additions, 1 deletion). It obtained the RustDesk custom x64 engine from official `rustdesk/engine` GitHub release asset `210168939` (63,301,215 bytes), validated the expected 10 flat archive entries, and installed them to the isolated SDK's `bin/cache/artifacts/engine/windows-x64-release`; replaced stock files were backed up to `%LOCALAPPDATA%\HoenBuildTools\flutter-engine-stock-backup`. The downloaded archive's computed SHA-256 is `ec8cabf36ee4ff24c8d98de25b00e70781eb03876265aee84d0fe554a110036e`. Upstream did not publish a digest for this asset, so this records the downloaded bytes rather than an independent checksum verification.

### Flutter package resolution

The initial `flutter pub get` exited 1 because Windows Developer Mode was disabled and Flutter requires symlink support. The user enabled Developer Mode; the root task verified the setting and reran `flutter pub get` successfully (exit 0; user-local log `flutter-pub-get.log`). The application build subsequently succeeded as recorded below. Generated plugin directories are ignored, and any tracked lockfile changes require review.

### First Windows x64 application build

After the user enabled Developer Mode and `flutter pub get` succeeded, the root task started a fresh local x64 build with the pinned Rust toolchain and completed native packages. The build log records the main Rust release Cargo step as 9 minutes 9 seconds and Flutter's Windows build step as 129.2 seconds. The enclosing Python process began at approximately 17:25:00 EST and its log's final output was at 17:41:13 EST on November 5, 2026, approximately 16 minutes 13 seconds including first-run Cargo dependency downloads. This is not an incremental build benchmark. Flutter reported a built executable; `flutter/build/windows/x64/runner/Release` contains `rustdesk.exe`, `librustdesk.dll`, `flutter_windows.dll`, and `dylib_virtual_display.dll`. The executable SHA-256 is `a7e42d198fd5640248f513934c5d6493f791289165dbfa1288b7d5550fc3a739`. The enclosing build command exited 0, verified by the root task. The executable was not launched, installed, or tested as a host, and this build does not establish mailbox integration or unattended access readiness.

### Feature-gated integration checkpoint

On November 5, 2026, the root application compiled the new `hoen-mailbox` modules with Rust 1.75. The expanded test run passed all 15 selected tests using `cargo +1.75.0 test --release --config profile.release.lto=false --lib --features flutter,hwcodec,vram,hoen-mailbox hoen::`. This test profile disables link-time optimization; it does not change the shipping build defaults. The first smaller seven-test release run also passed with the default release profile. Logs are in `%LOCALAPPDATA%\HoenBuildTools\hoen-integration-final-test.log` and `hoen-integration-test.log`.

The tests cover real loopback TCP encryption and matching channel bindings, host pin/signature/version rejection, replayed greetings without encrypted confirmation, payloads above the temporary handshake limit, network policy, synthetic Windows DPAPI storage/tamper rejection, worker configuration failure, stable history intents and durable outbox reopen ordering. Separately, the typed HTTPS auth client passed seven tests and Clippy; the history crate passed nine tests. These tests do not establish a real approved Wi-Fi connection, active desktop capture/control, or unattended service behavior.

The new native modules are not called by the existing desktop session loops yet. Remaining gates include enrollment and protected configuration provisioning, viewer/host startup hooks, final admission and small-frame/liveness checks, network-change teardown, lifecycle history hooks, live mailbox API reconciliation/deployment, installation/rollback and two-machine acceptance. No host service or firewall rule was installed. Area51 has begun the separately authorized matching-baseline build setup; its comparison timings remain pending.

Regression surface at this checkpoint: the root Cargo manifests/lock add optional dependencies and OS bindings; `src/lib.rs` adds a feature-gated module; client-only protobuf definitions add optional fields; Windows/Mac CI commands include the feature tests. Existing desktop login, capture, input, clipboard, and service runtime paths are unchanged. No `hbb_common` submodule change was made.

## Superseding direct-LAN policy (seq191)

Earlier approved-home-interface/network language above is superseded: permit
any same LAN over physical Wi-Fi or Ethernet without SSID, network GUID,
named-network or adapter pins and without requiring a Windows Private profile.
Do not change MeshMonkey or another network profile for Hoen authorization;
seq189's request is superseded. Keep actual socket/interface and on-link route
checks with cryptographic mailbox identity and single-use grants. No public
rendezvous/relay, router exposure, password or manual-approval fallback is
permitted. Firewall provisioning remains a separate reviewed integration step.
VPN transport may be added under a separately reviewed future policy.
Seq193 published `b9ade1684` and `d750e367e`; their code/build changes have
been reviewed and integrated locally. Windows runtime and two-machine acceptance
remain unverified on this Mac. See HOEN-MAC.md for integration status.
