# Windows installation and machine identity

## Current implementation

The GUI is **Remote Desktop Client**; the Windows background service is **Remote Desktop Service**, SCM name `RemoteDesktopService`. Phase 1 installs one payload in `Program Files\Remote Desktop Service`. Launch `rustdesk.exe` in that protected directory without arguments for the client; SCM launches that same executable with `--service`. A viewer launched from a build folder or another installation path is rejected by the service broker's exact executable-path check. Separate product roles do not require separate copies of the binary. Do not weaken this check to accept a writable build directory.

The service reuses the machine's existing mailbox identity and bearer. `scripts/remote-desktop-bootstrap.ps1` reads the existing client configuration and an explicitly approved network/trust configuration, validates their contents, and writes a one-time machine-DPAPI transfer under SYSTEM/Administrators-only permissions. Inputs are read once; reviewed input digests are checked before provisioning. No credential is placed in command-line arguments or ordinary logs.

On first startup, the LocalSystem host runtime validates the transfer, generates its signing seed only when its protected store is confirmed absent, seals it with LocalSystem DPAPI, verifies readback, then consumes the transfer. Corrupt or conflicting existing state is never silently replaced. Runtime state uses the Windows known folder `ProgramData\Remote Desktop Service State\host`; history storage is protected before bootstrap consumption. The viewer requests host metadata and channel-bound proofs through the authenticated service broker. It receives neither the machine bearer nor private signing key and needs no separate viewer enrollment. See [broker boundary and tests](HOEN-LOCAL-PROOF.md).

The host resolves the approved interface's current IPv4 address on startup and updates the registry after binding its listener. Its key remains unchanged when DHCP changes the address. Registration eligibility is not a liveness lease. HTTPS validates the supplied trust root, hostname/IP SAN and recorded leaf fingerprint before credentials are transmitted. The production SAN-less certificate still needs replacement; the verifier must not be bypassed.

The approved home-network restriction remains active. Area51's broader-network branch is not merged pending direct user confirmation. The live network-change disconnect test was explicitly waived; transition handling remains implemented but that behavior is unverified in a live session.

## Installer lifecycle

`scripts/remote-desktop-service-installer.ps1` supports these explicit actions:

- `Plan` is read-only and produces the payload hash manifest. With `ExpectedManifest`, it checks the exact payload against a previously reviewed manifest.
- `Install` requires elevation, the reviewed manifest, existing mailbox client-config path and approved-config path. It refuses an existing target/service, creates the protected installation, provisions the encrypted bootstrap and creates a disabled LocalSystem service. It does not start the service.
- `Activate` verifies installed files, permissions and exact SCM identity, changes startup to Automatic and starts the service with bounded status polling. On failure it attempts to stop and disable the service. SCM Running alone does not establish host readiness.
- `Deactivate` verifies ownership, disables the service and requests stop without stopping dependent services implicitly.
- `Rollback` requires the exact owned service to be disabled/stopped and the payload unchanged. It removes only owned installation objects and preserves encrypted runtime/bootstrap/history state. It refuses foreign files or directories.

Stock RustDesk install, update, uninstall and service-control commands are blocked in mailbox builds. No broad image-name kill or unrelated-service removal is part of this installer. The native runner uses an absolute sibling DLL with restricted loading for its feature check; a missing DLL also rejects legacy pre-core service control. That narrow feature-off change is intentional. Import failures return a nonzero native process exit.

## Evidence and remaining acceptance

Checkpoint `eab9d7d87` built the Windows application with shipping release settings. The feature suite passed 38 tests and the feature-off unauthorized-admission suite passed 3 tests. Actual runner invalid-input rejection returned exit 1; the release payload passed exact manifest rechecking. See [artifact hashes and build timings](HOEN-WINDOWS.md). Bootstrap and installer synthetic/mock checks are not evidence of actual SCM deployment or unattended operation.

Before calling Phase 1 ready for two-machine testing, complete installed LocalSystem first startup and restart with unchanged identity, authenticated local broker use from the protected client path, registration of the current IP, live host/viewer authentication and desktop interaction, history delivery/retry, and actual install/deactivate/rollback verification. Validate locked and signed-out workers, session transitions, native clipboard formats and capture/input cleanup. Test rejected grants, unavailable service and malformed IPC without recording credentials or screen/key/clipboard contents. The user-waived network transition test must remain explicitly unverified rather than silently reported as passed.

The upstream worker launcher can fall back from a winlogon token to a user process token. The protected host store rejects a non-LocalSystem worker; code inspection alone does not prove locked/signed-out hosting. Worker identity, supervision, shutdown and listener readiness require actual Windows evidence. No service or firewall rule has been installed by the recorded checks. The certificate transition and working installed desktop sessions remain outstanding.
