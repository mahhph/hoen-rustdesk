# Controlled Windows installer and upgrade trial

Scope: the first integrated installer/firewall and staged payload upgrade/restore trial. Use a designated Windows test machine or a user-agreed maintenance window. Do not interrupt an active remote session. These scripts are not an unattended update service, and this guide does not declare production deployment acceptance.

## Inputs and preflight

- Run from the reviewed source revision in an elevated Windows PowerShell or PowerShell 7 session. Keep installer, bootstrap, firewall and upgrade scripts from the same revision together.
- Prepare separately verified old/new payload manifests and the new payload directory. Manifest hashes must describe the actual package; a manifest generated from arbitrary files is not independent release verification.
- Record the machine's existing public registry identity/key fingerprint, service state and a successful remote connection. Do not export or read the SYSTEM-only enrollment file to compare identity.
- Retain the existing approved public configuration and protected mailbox profile for fresh installation only. An upgrade does not require re-enrollment or passing a credential to the upgrade tool.
- Check that `C:\Program Files\Remote Desktop Service Upgrade` does not already contain a pending transaction. If it does, use `Validate` and investigate; do not delete it to force a new upgrade.

The examples below use placeholder paths. Replace them with reviewed inputs for the test machine. `Rollback` on the original installer means **uninstall**; `Restore` on the upgrade tool means **restore the previous application version**.

## Fresh installation

Run the existing `Plan` and review the payload before `Install`:

```powershell
./scripts/remote-desktop-service-installer.ps1 -Action Install -SourceDirectory C:\review\new-payload -ExpectedManifest C:\review\new-manifest.json -ClientConfigPath C:\protected\client.json -ApprovedConfigPath C:\review\approved-config.json
./scripts/remote-desktop-service-installer.ps1 -Action Activate
```

Install now records the approved listener port and whether it created the owned firewall rule inside the protected install manifest. Activate checks that the exact rule is active. Verify registration, current IP, unchanged/reused identity and a real connection from another machine. A service-running message is not desktop readiness. Test uninstall only after closing the client and deactivating the owned service; verify unrelated/manual firewall rules and protected identity/history remain.

## Existing installations without firewall metadata

Close the client and finish all sessions, then use `Deactivate`. Review the approved configuration and its SHA-256 before adoption:

```powershell
./scripts/remote-desktop-service-installer.ps1 -Action Deactivate
./scripts/remote-desktop-service-installer.ps1 -Action AdoptFirewall -ApprovedConfigPath C:\review\approved-config.json -ExpectedApprovedSha256 REVIEWED_SHA256 -ConfirmedExistingListenerPort
```

Adoption requires a cleanly stopped/disabled service and no installed payload process. Before stopping, independently confirm the approved configuration's port matches the existing listener (or the original approved enrollment record). `-ConfirmedExistingListenerPort` asserts this operator check; the installer cannot prove the port inside SYSTEM-only encrypted enrollment. It records only public installation metadata and does not decrypt service credentials. A changed configuration digest or existing metadata is rejected. The prior manual rule `HoenRemoteDesktopServiceTCP42830`, if present, remains separately owned and untouched.

## Stage and upgrade

```powershell
./scripts/remote-desktop-upgrade.ps1 -Action Stage -SourceDirectory C:\review\new-payload -OldManifest C:\review\old-manifest.json -NewManifest C:\review\new-manifest.json
./scripts/remote-desktop-upgrade.ps1 -Action Validate
```

Stage copies/verifies the replacement in a protected same-volume workspace and writes recovery metadata. It does not change service state. Before replacement, close all sessions and the installed client, then:

```powershell
./scripts/remote-desktop-service-installer.ps1 -Action Deactivate
./scripts/remote-desktop-upgrade.ps1 -Action Upgrade
./scripts/remote-desktop-service-installer.ps1 -Action Activate
```

Upgrade requires a cleanly stopped/disabled owned service and no installed executable process. It verifies each package before moving it and retains the old package. Two directory moves are not one atomic transaction: `Validate` distinguishes the staged, interrupted-between-moves and upgraded layouts by inspecting verified contents. Credentials, history, SCM configuration and firewall rules are not changed by the upgrade tool.

After activation, verify the registry public key is unchanged, the listener/address is correct, the local client lists aliases, and a second machine can establish an authenticated desktop session. Record versions, evidence and any error; do not log private credentials or session contents.

## Restore and interruption tests

```powershell
./scripts/remote-desktop-service-installer.ps1 -Action Deactivate
./scripts/remote-desktop-upgrade.ps1 -Action Validate
./scripts/remote-desktop-upgrade.ps1 -Action Restore
./scripts/remote-desktop-service-installer.ps1 -Action Activate
```

Verify the previous payload, unchanged public identity, listener, remote connection and history continuity. If stopping fails or an unknown process/file is present, stop the trial and retain all files. Never force-kill unrelated processes or bypass the guard.

In an isolated fixture/VM, exercise interruption after the first directory move, a modified/untracked payload, a busy process and failed activation. A verified between-moves layout can continue with `Upgrade` or return with `Restore`; uncertain layouts refuse changes. Tests should confirm the original package remains recoverable and no unrelated paths are touched.

## Limits to record

- Service stop/start is explicit; there is no automatic deployment scheduler or session-drain protocol. A running service is not proof that no user session is active.
- If staging fails before a complete recovery record exists, the original installation remains intact but the workspace is retained for administrator inspection. Automatic cleanup of that incomplete workspace is not implemented.
- The workspace retains both reviewed versions. Automatic retirement/rotation for a later, different upgrade is not implemented; do not delete recovery data during this trial.
- Restoring payload files does not reverse application data-schema migrations. Test version compatibility before using a pair of releases; no credential/history rollback is attempted.
- Mocked service tests and isolated filesystem tests do not prove live SCM behavior, effective network policy, post-upgrade desktop readiness or disaster recovery. Record those outcomes separately before closing PRD-01/02.
