# LAN migration and parallel delivery

Architecture: [LAN-ARCHITECTURE.md](LAN-ARCHITECTURE.md). Acceptance criteria: [LAN-STORIES.md](LAN-STORIES.md).

## Existing deployment baseline

On 2026-11-08 Lenovo installed `bb58ac5c4` (PR19), preserving its existing identity/key and rollback payload. Listener and registry were verified at `192.168.1.11:42830`; client displayed build `bb58ac5c4f4a` and service connected. Forty native and five widget tests passed. Mac independently reported TCP reachability, not an authenticated desktop session. Mac and Area51 still reported stale listeners/trust-repair blockers. Do not label all three machines upgraded or accepted.

The current reserved mailbox endpoint is `https://192.168.1.9:42819`. Its corrected public leaf fingerprint is `11FE824540DAD976B83222BC867ED8425A9D3FD8024CB7A206F17CB3681B7259`, independently confirmed by the user. This is migration evidence for the current endpoint, not a permanent pin to embed in source. Preserve existing tokens and desktop keys. Local mailbox-app repair remains separate from the working CLI/watcher/native service evidence.

## Work ownership

| Owner | First work | Owned implementation | Integration boundary |
|---|---|---|---|
| Lenovo | LAN-01 fixture/schema PR | All Windows development: shared Rust/IPC, DPAPI/SCM/notifications, Flutter, migration/install/repair/rollback and integration tests (LAN-03 through LAN-10) | Owns Windows and shared desktop code; coordinates contracts with Mac. |
| Mac | Reconcile live mailbox source; draft additive LAN-02 schema/API | Mailbox database/API, trust/renewal, macOS Keychain/launchd/notifications/permissions (LAN-02/03/04/06/07/08/09) | Server contracts require fixture agreement; Mac-only changes stay gated. |
| Area51 | Wait for completed tested package | Setup and verification only (LAN-11); no coding or build assignment | Returns defects to Lenovo; receives handoff only after Windows release/canary gates pass. |

Use `codex/lan-<story>-<platform>` branches from the latest target `develop`; mailbox owner first confirms which current branch contains the deployed server and targets that integration branch. Do not overwrite parallel work or revive obsolete prototype branches. Send proposed shared-file edits before coding conflicting sections. Server API docs in old local checkouts are historical, not deployment truth.

First parallel deliverables are fixtures and Windows migration inventory/plan on Lenovo, plus additive server schema/API proposal and trust plan on Mac. Do not dispatch an Area51 story until the completed package and setup handoff are ready. They can proceed without waiting for live CA changes. Implementation behind version/capability gates follows reviewed contracts. No third-party mesh provisioning, new account subscription or blanket permission changes are part of these assignments.

## Deployment waves

1. Freeze LAN-01 fixtures/error codes; confirm platform build and privileged-install capabilities. A mailbox worker lacking Keychain, Xcode cache or elevated Windows access reports the exact blocker and hands off to an authorized local agent. Messages do not expand its permissions.
2. Deploy additive mailbox capabilities/presence with a database backup and v1 compatibility. Keep current endpoint and certificate operational. Stage the scoped trust bundle and test renewal in isolation before a live trust transition.
3. Build/test broker and migration adapters. Validate all deployed TLS runtimes against both transition and replacement leaves. Review package hashes, process guards and rollback compatibility.
4. Migrate Lenovo as the canary. Preserve encrypted state; verify broker, mailbox app, watcher, desktop UI, listener, public identity/key and history. Obtain a real peer session before marking the canary complete.
5. After the Windows implementation and Lenovo canary gates pass, send Area51 LAN-11 setup instructions for the completed package. Migrate Area51, then Mac, one at a time. Keep at least one known-working peer while changing another. Do not confuse mailbox Linux server migration with Mac desktop migration. If a machine is already broken, report baseline limitations and repair its existing credentials first.
6. After all consumers support the scoped CA trust, activate the reviewed renewable server leaf. Verify old/new-mode compatibility and rollback during overlap. Retire per-app configuration only after recorded successful adoption by every consumer; never erase secrets or watcher state as cleanup.
7. Run cross-machine acceptance and publish release notes/known limits. New-machine enrollment approval is the next milestone after existing-client recovery, not a prerequisite for re-enrolling current devices.

## Per-machine transaction

`inventory -> private backup -> prepare -> validate -> activate -> verify -> committed`.

Before activation, cancellation leaves current components unchanged. After activation, a failing verification enters `rollback-required` or performs the verified restore; it never claims migration complete. A resumable nonsecret journal records package/config versions, step outcomes and backup references, not decrypted credentials. Installer locks prevent concurrent migration/repair. Defer active desktop sessions and pending watcher jobs safely; preserve their durable state rather than restarting arbitrary processes.

Checkpoints: trusted unauthenticated TLS probe; authenticated read-only API; broker availability; same identity/key; listener/current registry endpoint; watcher cursor/pending continuity; mailbox-app account/privilege continuity; UI build/list; real authenticated session; metadata-only history delivery. Service Running or TCP connect alone cannot satisfy the final session checkpoint. Retain recovery packages/configuration and explicitly state how to restore them.

## Evidence and reporting

Each owner replies via mailbox with story IDs, repository/branch/commit, tests and actual output summary, package hashes, installed/config revision if deployed, blocker/next action and affected shared files. Do not send secrets, private keys, raw credential files or screen/clipboard content. Report implementation, build, install, TCP reachability and authenticated desktop acceptance separately.

Windows live network disruption remains waived. Use injected address changes and isolated loopback/integration environments. Record any untested reboot, locked/signed-out or Mac permission state rather than claiming it from a unit test.

