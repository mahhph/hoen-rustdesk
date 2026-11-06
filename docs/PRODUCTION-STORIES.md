# Remote Desktop production readiness

Created 2026-11-06 following user acceptance of Windows development. This is a new hardening backlog, not a reversal of that acceptance. GitHub Issues is disabled; this file is the story and evidence index. All stories target `develop` through reviewed, tested checkpoints. Status changes require linked evidence, not merely implemented code.

## Delivery order

Start PRD-01, then PRD-02 and PRD-04. PRD-03 can proceed alongside them once the release/signing environment is known. PRD-05/06 provide operational evidence; PRD-07/08 cover recovery and security lifecycle. PRD-09 is the Mac release gate. Internet discovery/relay and separate file-transfer sessions are outside this backlog. The user-waived live network-change disconnect test remains waived.

## PRD-01 — Repeatable installation and firewall setup

**Status:** In progress. **Priority:** P0. **Owner:** Windows packaging.

As an administrator, I want one repeatable installation process so a newly installed host is reachable without manual firewall repair.

Acceptance criteria:

- Installation validates the reviewed payload, service identity and approved configuration before mutation, and reuses the protected machine mailbox identity.
- Configure only an inbound TCP rule for the installed executable and configured listener port; never disable a firewall profile or modify unrelated rules. Network category is not an authentication rule.
- Repeated setup is idempotent. A same-name rule with different ownership or scope is reported rather than overwritten. Validation distinguishes a missing/disabled rule from a matching enabled rule.
- Removal deletes only an explicitly owned, matching rule; enrollment and history are preserved. Installation failure accurately reports which resources remain.
- A fresh-machine trial demonstrates listener, current registry address and a connection from a second machine. SCM Running alone is not success.

First increment: a separately invocable, tested firewall lifecycle helper. Integration into the full installer and a fresh-machine trial remain required before closing the story.

Initial evidence (2026-11-06): `scripts/remote-desktop-firewall.ps1` implements explicit-port Validate/Configure/Remove. Mocked lifecycle/filter checks and the existing installer process/stop guards passed. Native filter representations were checked read-only against Lenovo's existing rule. The subsequent installer integration retains approved port/ownership metadata and includes explicit legacy adoption, documented below. No live rule or service was changed during development, and no fresh-machine trial is claimed.

## PRD-02 — Upgrade and rollback without losing identity

**Status:** In progress. **Priority:** P0. **Depends on:** PRD-01.

As an administrator, I want to upgrade or roll back without recreating credentials, losing history or leaving the machine unusable.

Acceptance criteria:

- Preflight validates old and new manifests, free space, service ownership and active sessions before stopping anything. An active session is reported and the upgrade is deferred by default.
- Stage and verify the replacement under protected permissions; retain a verified recovery package and explicit recovery instructions.
- Stop only the owned service/worker, require a confirmed clean stop, and refuse replacement while an owned client or worker still holds the payload.
- Preserve protected enrollment and durable history without decrypting or weakening their permissions. Verify the registered public key remains unchanged after upgrade and rollback.
- Exercise install failure, activation failure and interrupted replacement in an isolated test environment. Recovery restores a usable verified package and truthful service/firewall state; it does not silently rotate identity.
- Record both old/new versions and final outcome without credentials. Demonstrate one successful upgrade and one rollback with remote reconnection.

Implementation checkpoint: installer/firewall integration and protected public port/ownership metadata are implemented, with explicit legacy adoption. The standalone upgrade tool stages a verified replacement, retains the old package and supports verified restore/recovery between directory moves. PowerShell 5.1 and 7 isolated filesystem tests passed; service state checks were simulated. Use [the controlled test guide](INSTALLER-TEST-GUIDE.md) for live validation. Automatic session drain, deployment orchestration, recovery-workspace retirement, live activation/reconnection and identity/history continuity remain acceptance work. PRD-01's fresh-machine trial is also still open.

## PRD-03 — Signed, traceable releases

**Status:** Ready. **Priority:** P1. **Owner:** Release engineering.

As a user, I want a recognizable, verifiable installer with a version I can report when something goes wrong.

Acceptance criteria:

- A documented build pins source revision, toolchains, dependencies and generated bridge artifacts; a clean CI build produces the expected package without developer-local files.
- Package and application show a consistent version, product name and distinct icon. Release notes identify changes, known limits and supported OS versions.
- Windows signing verifies publisher identity and timestamp; the signing key is held by an approved protected signing mechanism, never in the repository or ordinary build logs. Report missing signing access as a dependency rather than ship an unsigned artifact as signed.
- Publish checksums, source revision, corresponding source/license notices and a manifest with the release. Verification rejects altered package contents.
- A fresh Windows machine installs the signed artifact, connects and uninstalls through documented steps. Reproducibility means traceable controlled inputs; claim byte-identical builds only if separately demonstrated.

## PRD-04 — Unattended operation and recovery

**Status:** Ready. **Priority:** P0. **Owner:** Windows runtime. **Depends on:** PRD-01.

As a user, I want my registered host to return after restart or interruption without someone logging in to launch it.

Acceptance criteria:

- Test boot before interactive login, locked desktop and signed-out desktop separately; record capture/control results, not just listener presence.
- Test sleep/wake, session switching and a controlled worker crash on a designated test machine. No duplicate worker/listener or stuck input remains.
- Retry failures with bounded backoff; report persistent failure and recover after the dependency is restored.
- Startup registers the current address and preserves identity. Restart/reconnect obtains fresh authenticated proof.
- Test stop/start cleanup and rollback prerequisites. Coordinate disruptive reboot/sign-out/crash trials with the user; never run them during their active session.

## PRD-05 — Useful health and connection diagnostics

**Status:** Ready. **Priority:** P1. **Owner:** Shared UI/runtime.

As a user or administrator, I want errors that distinguish service, network, trust and authorization failures so I know what to fix.

Acceptance criteria:

- Distinguish local service unavailable, directory unavailable, target TCP unreachable, certificate/pin failure, denied grant and desktop initialization failure where the implementation has reliable evidence.
- Status separates installed, running, listening, registered and successfully connected; registered machines are never labeled online without a liveness check.
- Provide a bounded diagnostic report with version, public machine identity, timestamps and actionable error codes; exclude bearer tokens, private keys, grants, screen contents, keystrokes and clipboard data.
- UI fails cleanly and clears stale selection on refresh failure. Retry does not loop forever on an invalid identity or trust error.
- Verify representative failures and successful recovery using production entry points; preserve useful underlying failure information without exposing secrets.

## PRD-06 — Verified central session history

**Status:** Ready. **Priority:** P1. **Owner:** Shared history/mailbox.

As an administrator, I want reliable session records attributable to authenticated participants.

Acceptance criteria:

- A live session records the cryptographically verified viewer and target identities with a stable session ID and documented lifecycle semantics.
- Normal disconnect produces one terminal event; an abrupt crash/power loss leaves an honest unknown/missing-end state rather than a fabricated clean disconnect.
- During a simulated mailbox delivery outage, durable local events survive process restart and retry with the same event IDs; central records are not duplicated.
- History contains metadata only. Inspect a synthetic session's stored records and logs to confirm no screen, keyboard or clipboard contents are captured.
- Expose pending/failed delivery truthfully and define retention and cleanup behavior. Demonstrate delivery and recovery against the central database, not only unit tests.

## PRD-07 — Credential, certificate and machine lifecycle

**Status:** Ready. **Priority:** P1. **Owner:** Shared authentication/mailbox.

As an administrator, I want to revoke a retired machine and renew trust without weakening authentication or permanently locking out legitimate hosts.

Acceptance criteria:

- Revoked credentials and hosting-disabled machines cannot start new sessions; document and test the intended treatment of existing sessions.
- A certificate renewal rehearsal stages public trust, verifies hostname/SAN and exact pin, switches consumers coherently and has a tested rollback path.
- Removing a machine clears discoverability/eligibility appropriately and does not delete unrelated identity or history records.
- Re-enrollment never silently replaces a conflicting protected identity. All credential operations avoid command-line secrets and ordinary logs.
- Test expired/replayed grants, wrong host pin and failed renewal without enabling legacy fallback or disabling TLS verification.

## PRD-08 — Backup and restore of the mailbox service

**Status:** Ready. **Priority:** P1. **Owner:** Mailbox/Linux operations.

As an administrator, I want a tested recovery procedure for mailbox storage and protected configuration.

Acceptance criteria:

- Inventory the database, encrypted secret values/audit history, encryption-key dependencies, TLS material and service configuration; keep backup access restricted and encryption keys separate from ordinary artifacts.
- Create a consistent backup without copying a live SQLite file unsafely. Define retention, recovery-point and recovery-time targets with the user before claiming compliance.
- Restore into an isolated environment without sending production messages or creating a competing production endpoint.
- Verify identities, registry, secret decryption/audit continuity and session history using synthetic checks; report missing key material explicitly.
- Demonstrate one restore and document elapsed time, backup timestamp and recovery limits. Never overwrite newer production data as part of a drill.

## PRD-09 — Mac release acceptance

**Status:** Ready; Mac development owns current evidence. **Priority:** P1. **Depends on:** applicable PRD-03/05/06/07 work.

As a Mac user, I want the same alias-based client and authentication guarantees with platform-appropriate packaging.

Acceptance criteria:

- Build from the shared revision with protected Mac enrollment and the shared directory/transport contract; retain Mac-specific adapters without changing Windows behavior.
- Test Mac viewer connections to both Windows hosts with display, input, native clipboard and central history. Keep viewer acceptance separate from Mac host/unattended acceptance.
- Verify signing/notarization and Keychain behavior for the distributed app identity; upgrades preserve the intended enrollment namespace.
- Verify relevant denied/granted macOS permissions for hosting without bypassing system protections. Do not require host capture permissions merely to claim viewer readiness.
- Record artifacts, supported OS/architecture, tests, known limitations and rollback steps; preserve AGPL notices and corresponding source.

## Completion rule

Each story records implementation revision, automated checks, live evidence and remaining limitations. A passing build or a mock test alone never closes an operational acceptance criterion. Do not restart the previous Windows-acceptance automation; this backlog is a separate user-authorized production workstream.
