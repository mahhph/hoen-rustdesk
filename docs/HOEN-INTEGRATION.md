# Hoen mailbox integration

Current design update (2026-11-08): [LAN-only registration and recovery](LAN-ARCHITECTURE.md), [implementation stories](LAN-STORIES.md), and [existing-client migration/ownership](LAN-ROLLOUT.md) govern the next increment. No Tailscale or mesh service. Address-change monitoring is now explicitly requested for recovery, without notification-triggered session invalidation. Earlier network-monitoring statements below are historical where they conflict with this baseline.

Status (2026-11-06): the user accepted Windows development as complete after confirming connections in both directions. Mac development remains active. Historical test limits below remain evidence limits, not claims of tests that were never run.

## Decision and repositories

The user approved RustDesk as the remote desktop engine on 2026-11-05. Preserve the earlier custom Rust prototype as reference; it is no longer the Phase 1 engine. Preserve RustDesk's AGPL license and notices. Changes to this fork remain available with corresponding source; the mailbox stays a separate service accessed through authenticated APIs.

- Desktop host and viewer: https://github.com/mahhph/hoen-rustdesk, branch `develop`.
- OSS coordination/relay server: https://github.com/mahhph/hoen-rustdesk-server. Forked for future integration; no deployed Hoen service yet.
- Mailbox: https://github.com/mahhph/hoen-agent-mailbox, existing integration branch `feat/rust-remote-desktop`.
- Mac-specific work in this fork: proposed branch `codex/mac-mailbox-integration`.

## Current product requirements

Any authenticated mailbox user may connect to any registered, hosting-enabled machine. A disabled or revoked host must not admit a new session. Enrollment and authentication must be verified by the service; a RustDesk name, address or self-reported peer ID does not establish a mailbox identity. Existing operator-only read credentials are not an interactive user enrollment mechanism.

Windows Phase 1 includes Lenovo and Area51 in either role, unattended locked/signed-out access, installer and rollback. The network path does not grant or deny access: local, VPN, Internet, and relay paths are permitted when they provide the verified encrypted channel and mailbox proof. The current implementation supports only direct native TCP; other transports require implementation and acceptance tests. Mac host and viewer must follow the same rule: no macOS network category, interface type, SSID, or peer route may authorize or reject a session. Network-change notifications do not reject or disconnect sessions. Shared code must support Mac host and viewer development in parallel under this authentication rule.

The user accepts RustDesk's supported clipboard formats, including text, images and rich text. The previous text-only filter and custom text limit are superseded. Separate file-transfer sessions remain out of scope. Clipboard content must never enter session history or mailbox audit events.

Acceptance change, November 6, 2026: the user requested complete removal of network-change monitoring and its session invalidation behavior. Socket failures still end connections, and secure handshake and mailbox authorization remain required.

The mailbox owns enrollment, access grants, deliberately shared secrets, and metadata-only central session history. Device private keys stay local. RustDesk OSS uses a separate SQLite peer database (`db_v2.sqlite3`); the mailbox uses `mailbox.sqlite`. Do not write directly into one another's databases.

## Integration sequence and acceptance

1. Establish reproducible Windows builds and a source/license-preserving package. Use pinned upstream dependencies and record the exact built revision. Verify install/uninstall without claiming service-running means a usable host.
2. Add mailbox machine registration and a short-lived connection authorization flow. Bind the authenticated mailbox viewer to the intended host and the actual encrypted session, with expiry, replay rejection and revocation. Keep credentials out of command lines and ordinary messages. All authenticated users share the access policy; identity proof still distinguishes them for audit.
3. Require verified encrypted channel binding and mailbox proof on every enabled transport. Do not silently fall back to an unverified path. Keep upstream behavior unchanged outside explicitly enabled Hoen mode.
4. Add best-effort durable metadata-only history delivery and authenticated lifecycle hooks. Preserve stable event IDs over retries and display a missing end as unknown/stale. Do not attribute a session using a self-reported RustDesk viewer ID. Valid identity remains mandatory; unavailable, slow, or full history storage must not block an otherwise authorized connection. A temporary mailbox delivery outage may queue events without inventing successful central delivery.
5. Validate actual host/viewer operation in both Windows role directions, native clipboard formats, disconnect/reconnect, lock/sign-out, reboot, network changes, authentication rejection, revocation and history recovery. Readiness for user testing requires working artifacts and local integration evidence; final two-machine acceptance remains separate.

See [history design](HOEN-HISTORY.md) and [Windows build notes](HOEN-WINDOWS.md). The initial outbox crate is independently testable; it does not itself connect RustDesk to the mailbox or establish viewer identity.

## Parallel ownership

Lenovo coordinates mailbox authentication/history and shared integration contracts and owns Windows packaging. Mac owns macOS-specific build, permissions, host/viewer validation and packaging. Propose shared protocol changes before editing the shared submodule. Preserve the existing Mac prototype branch; do not merge its custom protocol into RustDesk.
