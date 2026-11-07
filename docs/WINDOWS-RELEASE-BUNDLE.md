# Remote Desktop Windows release bundle

This is an unsigned, experimental administrator bundle, not a finished graphical installer. Windows may show an unknown-publisher warning. Obtain its SHA-256 through a separately trusted release channel and compare it before extracting; a checksum distributed only alongside a modified bundle does not authenticate it.

The bundle contains the application, its reviewed payload manifest and installation scripts. It does not contain enrollment credentials or host configuration. `release.json` records the payload source revision supplied by the packager; it is not proof that the payload was built from that revision.

Extract to a directory accessible only to the administrator. In PowerShell, run the following from that directory to verify the included payload:

```powershell
.\scripts\remote-desktop-setup.ps1 -Action Plan
```

For a fresh host, prepare an existing protected mailbox client profile and an approved host configuration separately. In an elevated PowerShell, run:

```powershell
.\scripts\remote-desktop-setup.ps1 -Action Install -ClientConfigPath C:\protected\client.json -ApprovedConfigPath C:\review\host.json
```

Install refuses an existing service or installation. It provisions the service and then activates it. An activation failure leaves the installed service in place for inspection; it does not claim a successful connection. Verify registration and a remote desktop connection from another machine.

For an already enrolled installation, close all remote sessions and the installed client and tray. Obtain the independently reviewed manifest for the installed payload. The installed service must have reviewed firewall ownership metadata, and its upgrade workspace must be available. From elevated PowerShell:

```powershell
.\scripts\remote-desktop-setup.ps1 -Action Upgrade -OldManifest C:\review\installed-manifest.json
```

This experimental upgrade retains the previous application and preserves enrollment. It refuses active sessions and unclosed installed clients, but its checks are not an atomic session lock. It does not adopt legacy firewall metadata or automatically retire an earlier recovery workspace. If either is present, stop and follow the controlled test guide; do not delete recovery data or bypass the checks. The coordinator has not yet been exercised in a live upgrade. Confirm a connection in each direction after the trial.

The ZIP checksum only verifies bytes against an independently trusted checksum. The payload manifest checks the application files, not the scripts; verify the whole ZIP before running anything. Fresh-machine installation, archive recovery, failure handling on real service operations, and this bundle's end-to-end workflow still require validation before production release.
