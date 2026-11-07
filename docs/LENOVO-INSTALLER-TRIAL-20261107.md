# Lenovo installer trial — 2026-11-07

This records a controlled live test, not production acceptance.

## Source and build validation

PRs #12–14 were merged into `develop` at `8ae61d7c3779e234a3f499f854ec1e24bba00456`. The Windows application built locally in 607.14 seconds. Its native DLL matched the compiler output and its payload manifest passed an exact recheck. All 44 selected native mailbox tests, 4 Flutter machine-picker tests, and the existing installer/firewall/upgrade guard suites passed. The local payload was retained separately; it was not installed.

## Area51 bundle trial

The user requested testing Area51's installer instead of the prepared manual upgrade. The tested release asset was `remote-desktop-windows-x64-0b372d9da-test2.zip`, from release `windows-installer-test-20261107`.

- ZIP SHA-256: `49be5feb000d3795d4b1c58cfd1df211dc1b4ed35755f0593ba6f2f413d6fd33`, checked against Area51's authenticated mailbox message 321.
- Installer revision reported by the producer: `27c3782e6457e675d9d1c700a6ff5811d7993140`.
- Payload revision reported by the producer: `0b372d9da452de5255116c3a7249cb3c951a6d56`. This has the same source tree as the merged local build, but is a separately built artifact; reproducible binary provenance is not claimed.
- The bundle was copied, checksum-verified and extracted in an administrator/SYSTEM-only directory before execution under elevated Windows PowerShell 5.1.
- The original 91-file installation matched the independently retained `mailbox-ui-manifest.json`; no arbitrary current-files manifest was substituted. Required port/ownership metadata was present.
- The user confirmed sessions/client were closed. Remaining installed idle client/tray processes were closed after checking for active desktop sockets; the coordinator itself was not modified.

| Step | Observed result |
| --- | --- |
| Bundle `Plan` | Passed exact payload validation. |
| `ArchiveRestored` | Passed on the prior restored/staged workspace. Retained the complete staged package and journal in a unique protected sibling archive. |
| Setup `Upgrade`: stage and replacement | Passed. Original package retained for recovery. |
| New service activation | Failed. SCM event 7000 reported an Application Control block. Code Integrity events 3077/3033 identified the installed `rustdesk.exe` as failing Enterprise signing-level requirements. |
| Coordinator automatic recovery | Restored the original payload and restarted the service automatically. Service Running/Auto, exit codes zero; original payload hashes all matched. |
| Local post-recovery checks | Listener returned on the registered TCP port; registered public key unchanged. |
| Remote post-recovery connection | Requested from Area51 in mailbox message 322; pending at this checkpoint. |

The new application was **not successfully deployed**. The observed result validates the restored-workspace archival path and a real activation-failure recovery path. It does not establish archive restoration, fresh installation, all failure modes, or a successful new-version connection. No application-control policy was disabled or bypassed. Both prior recovery data and the rejected replacement remain retained; no enrollment credentials or history were reset.

Packaging trust/signing compatibility must be resolved before repeating deployment. The earlier 2026-11-06 trial passed the upgraded-version connection (Area51 message 312), but its post-restore connection failed (message 314); that earlier round trip must not be recorded as a complete pass. Area51 subsequently reported working baseline connections in message 321.

Regression surface: this checkpoint changes documentation only. Installer/runtime implementation remains owned by the corresponding source revisions.
