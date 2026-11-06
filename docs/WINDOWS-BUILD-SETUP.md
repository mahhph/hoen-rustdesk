# Windows x64 build setup

This guide builds the Flutter desktop application from `feat/mailbox-integration` on Windows. It covers source and tooling only; a successful build does not install a host or establish unattended remote access. Use a clean checkout and keep credentials outside the repository and build logs.

## Required components

| Component | Required version or source | Why it is needed |
| --- | --- | --- |
| Git and initialized submodules | Commit recorded by the selected source revision | `libs/hbb_common` is a pinned submodule. |
| Rust and Cargo | `1.75.0-x86_64-pc-windows-msvc`, including `rustfmt` | The build uses MSVC Rust; a build script invokes `rustfmt`. |
| Visual Studio C++ tools | x64 MSVC compiler and linker | Rust build scripts and native codec sources invoke `cl.exe` and `link.exe`. |
| Windows SDK | Headers, libraries, and resource tools for x64 | Native code needs `um`, `ucrt`, `shared`, and `winrt` headers, including `wrl/client.h`, plus `kernel32.lib` and `rc.exe`. |
| CMake and Ninja | Available on the build process PATH | Native dependencies and Flutter Windows plugins use them. |
| Python | 3.12.10 | Runs `build.py`. The embeddable distribution works for the build script but lacks `pip` for packaging steps. |
| LLVM/Clang | 15.0.6 | Bindgen needs `libclang`; set `LIBCLANG_PATH` to the LLVM `bin` directory. |
| vcpkg | `9e593bb18ea69cc5095e012465dcd675a822ed0d` | Builds the repository's `x64-windows-static` native manifest, including FFmpeg, codecs, and audio packages. |
| Flutter SDK | 3.24.5 with the repository's dropdown patch and RustDesk custom x64 engine | Builds the Windows UI. The stock Flutter engine is insufficient for this project. |
| Generated bridge files | CI `bridge-artifact` from matching FFI inputs | The six ignored Rust, Dart, and Apple header paths must be restored; `AGENTS.md` forbids local bridge codegen. |
| Windows Developer Mode or an elevated build shell | Symlink creation permission | Flutter creates plugin symlinks. A normal shell without Developer Mode fails at `flutter build windows`. |

Use the checked-in [CI workflow](../.github/workflows/flutter-build.yml), [bridge workflow](../.github/workflows/bridge.yml), [vcpkg manifest](../vcpkg.json), and [Windows notes](HOEN-WINDOWS.md) as the source of truth if versions or flags change. The bridge artifact used for the November 5 baseline came from CI run `42115480465`, source `0272f0270767f839e828a68861635df517e6eeaf`, artifact `13456556600`, SHA-256 `92acc800f0994474c7d74bd74843e54957060e1ebc8f01c4d4f09107d0f93f2f`. Check the FFI inputs against the target commit before reusing it.

## Prepare an isolated build shell

Install tools under a user-owned directory and set variables only for the current shell. This example uses the Area51 layout; replace paths for another machine. Visual Studio's installer should include the Desktop development with C++ workload, Windows SDK, and CMake tools. Flutter 3.24.5 may report a newer Visual Studio release as incomplete even when its MSVC compiler is present, so inspect both `flutter doctor -v` and the actual tool paths.

For Visual Studio 2026, Flutter 3.24.5 has a separate generator mismatch: its `visual_studio.dart` maps every version other than 2022 to `Visual Studio 16 2019`. CMake 4.4 supports `Visual Studio 18 2026`, but the stock Flutter tool does not select it. The Area51 isolated Flutter SDK was locally adjusted with `18 => 'Visual Studio 18 2026'` in that switch. A supported Visual Studio 2022 installation avoids this particular adjustment.

On Area51, CMake could read the Flutter plugin sources directly but failed to open their Windows `CMakeLists.txt` files through Flutter's generated `.plugin_symlinks` (`cmListFileCache` errors). The successful local build copied all 11 Windows plugin directories to `flutter/windows/flutter/ephemeral/.plugin_copies` and changed the isolated SDK's `flutter_plugins.dart` so its generated CMake plugin path uses `.plugin_copies` instead of `.plugin_symlinks`. Recreate those copies after any plugin dependency update. This is a local compatibility workaround, not a checked-in project patch or proof that other machines need it. Record both Flutter tool diffs alongside the checked-in dropdown patch; do not describe this SDK as stock Flutter 3.24.5.

```powershell
$tools = Join-Path $env:LOCALAPPDATA 'HoenRustDeskBuild\tools'
$sdk = Join-Path $tools 'winsdk\root2'
$msvc = 'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.51.36231'
$cmake = Join-Path $tools 'vcpkg\downloads\tools\cmake-4.4.0-windows\cmake-4.4.0-windows-x86_64\bin'
$ninja = Join-Path $tools 'vcpkg\downloads\tools\ninja-1.13.2-windows'
$env:PATH = "$env:USERPROFILE\.cargo\bin;$tools\python-3.12.10;$tools\flutter-3.24.5\flutter\bin;$tools\llvm-15.0.6\bin;$msvc\bin\Hostx64\x64;$sdk\bin\10.0.26100.0\x64;$cmake;$ninja;$env:PATH"
$env:LIB = "$msvc\lib\x64;$sdk\Lib\10.0.26100.0\um\x64;$sdk\Lib\10.0.26100.0\ucrt\x64"
$env:INCLUDE = "$msvc\include;$sdk\Include\10.0.26100.0\um;$sdk\Include\10.0.26100.0\ucrt;$sdk\Include\10.0.26100.0\shared;$sdk\Include\10.0.26100.0\winrt"
$env:RUSTUP_TOOLCHAIN = '1.75.0-x86_64-pc-windows-msvc'
$env:VCPKG_ROOT = Join-Path $tools 'vcpkg'
$env:VCPKG_DEFAULT_HOST_TRIPLET = 'x64-windows-static'
$env:LIBCLANG_PATH = Join-Path $tools 'llvm-15.0.6\bin'
```

If Visual Studio and the SDK are installed normally, prefer their developer shell over manually setting `LIB` and `INCLUDE`. Do not persist the example paths in system PATH. Confirm the SDK contains `winrt\wrl\client.h`; omitting `winrt` causes `hwcodec` C1083 errors. Add `rustfmt` to the pinned toolchain with `rustup component add rustfmt --toolchain 1.75.0-x86_64-pc-windows-msvc`.

Initialize submodules and restore the matching CI bridge archive in the checkout root. The archive must contain `src/bridge_generated.rs`, `src/bridge_generated.io.rs`, `flutter/lib/generated_bridge.dart`, `flutter/lib/generated_bridge.freezed.dart`, `flutter/macos/Runner/bridge_generated.h`, and `flutter/ios/Runner/bridge_generated.h`. Verify its checksum before extraction; do not run local codegen. Build the vcpkg manifest into `$env:VCPKG_ROOT\installed` using the static target and host triplet before invoking `build.py`.

```powershell
& "$env:VCPKG_ROOT\vcpkg.exe" install --triplet x64-windows-static --x-install-root="$env:VCPKG_ROOT\installed"
flutter precache --windows
```

Apply [the checked-in dropdown patch](../.github/patches/flutter_3.24.4_dropdown_menu_enableFilter.diff) to the isolated Flutter SDK after `git apply --check`. Install the matching RustDesk custom `windows-x64-release` engine into that SDK's `bin/cache/artifacts/engine/windows-x64-release` as CI does; back up the stock files and record the downloaded archive hash. The CI URL points to a mutable `main` release, so the URL alone does not identify reproducible bytes. The Area51 archive was 63,301,215 bytes with SHA-256 `ec8cabf36ee4ff24c8d98de25b00e70781eb03876265aee84d0fe554a110036e`.

## Build and verify

From the repository root:

```powershell
git status --short --branch
git submodule update --init --recursive
.\scripts\hoen-build-preflight.ps1
python .\build.py --portable --flutter --skip-portable-pack --hwcodec --vram
```

Record the full source and submodule commits, tool versions, build start/end, exit code, and whether caches were cold or warm. Run an unchanged second build only after the first completes if measuring a warm repeat. Keep dependency setup time separate from application build time.

The Rust library can finish while Flutter still fails. On Area51 at source commit `4095dc54ac21e7f63f1b9cde7be8d17569416606`, Rust completed after the SDK include fix. Flutter first stopped because Developer Mode was off, then selected the unavailable Visual Studio 2019 generator, then failed to open plugin CMake files through symlinks. After the local SDK and plugin-copy adjustments above, the full `build.py` command completed and Flutter reported `rustdesk.exe` under `flutter/build/windows/x64/runner/Release`.

The first complete run's log spans about 3 minutes 29 seconds (Rust 3 minutes 10 seconds; Flutter 16.1 seconds). Its executable SHA-256 was `81d971e1c1af3709d91d1af1959da42b77e7de9740e926b9ceb4b80828753440`; `librustdesk.dll` SHA-256 was `1103041ccdc18c596f03dc08ea14168f9a320a72ef6138db8ad20ba6f4786ccf`. An unchanged warm repeat's log spans about 3 minutes 30 seconds (Rust 3 minutes 17 seconds; Flutter 10.7 seconds); its executable SHA-256 was `6adb4d8d067834a3f02901249cfa0978daa73902916027b5cff1d4d214260bb2`. These are build-log and file-time measurements, not a benchmark controlled for background load. The changed executable hash means these two runs were not byte-identical. Verify launch/install behavior separately. No build result alone proves mailbox integration, network policy, locked-screen hosting, or two-machine acceptance.
