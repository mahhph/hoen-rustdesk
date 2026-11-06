# Isolated mailbox adapter trial

This standalone, opt-in program is restricted to the disposable seq178 trial at `https://192.168.1.24:42829`. It checks the trial CA's exact SHA-256 fingerprint before reading a credential, requires HTTPS hostname/IP validation, and refuses any other endpoint or CA. The CA and endpoint are public trial metadata, not credentials. No RustDesk desktop, screen sharing, keyboard, clipboard, native host key or production mailbox is involved.

It uses the actual `hoen-mailbox-auth` client to list registered machines, check the synthetic `windows-hoenlenovo` row (`c` repeated 64 times, placeholder port 49999), issue and consume a synthetic grant and check replay rejection. It then uses the actual `hoen-mailbox-history` outbox and HTTPS delivery adapter with two independent temporary outboxes to send the same create, heartbeat and end event IDs twice. A bounded read-only GET verifies the server stored exactly three unique events. The synthetic binding and fingerprint do not prove a desktop connection or possession of a real device key.

The trial writes synthetic grant and history records to the isolated server. It does not register or modify a machine. Failures after a create trigger a best-effort terminal report; if delivery is ambiguous, the printed synthetic session ID allows reconciliation. A missing terminal event is unknown, never inferred. Temporary SQLite outboxes contain only synthetic metadata and are removed on normal exit. The trial service and forwarding are temporary and may be stopped or its certificate expired; do not substitute a live endpoint or production credential.

From the RustDesk repository root, create the public CA file from the received trial reply without displaying any credential:

```powershell
$trialReply = Get-Content -Raw -LiteralPath (Join-Path $env:LOCALAPPDATA 'HoenAgentMailbox-hoenlenovo\trial-reply-179.json') | ConvertFrom-Json
$trialCa = Join-Path $env:TEMP 'hoen-seq178-public-ca.pem'
[System.IO.File]::WriteAllText($trialCa, $trialReply.content.publicCaPem)
```

Supply the **synthetic trial bearer only** via standard input from an appropriately protected file or another private process. Never put it in arguments, source, terminal output or logs. For example, after setting `$trialCredentialFile` privately to the protected file path:

```powershell
Get-Content -Raw -LiteralPath $trialCredentialFile | cargo +1.75.0 run --locked --manifest-path integration/hoen-mailbox-live-trial/Cargo.toml -- https://192.168.1.24:42829 $trialCa
```

Only status messages and the synthetic session ID are printed. Run the local unit tests without network access using:

```powershell
cargo +1.75.0 test --locked --manifest-path integration/hoen-mailbox-live-trial/Cargo.toml
```

The existing standalone auth and history crates contain local TLS tests. On November 5, 2026 (America/New_York), Lenovo ran this harness against Mac's isolated Linux trial and exited 0. Authenticated listing, synthetic grant consumption/replay rejection, and history create/heartbeat/end with identical-ID retries passed; the server contained exactly three events for synthetic session `b71c5936-52ae-421d-b55c-2d35074924af`. The bearer was retrieved through the existing mailbox secrets API and piped directly to the child process, without printing it or storing it in a file. Two local unit tests and Clippy also passed. This proves cross-machine Rust API integration only, not native desktop authentication, display/control, network-change teardown or unattended access.
