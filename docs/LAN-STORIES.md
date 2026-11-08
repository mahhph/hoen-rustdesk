# LAN-only implementation stories

Baseline 2026-11-08. All stories are planned unless explicitly noted; assignment does not imply acceptance or completion. Architecture: [LAN-ARCHITECTURE.md](LAN-ARCHITECTURE.md). Migration/evidence: [LAN-ROLLOUT.md](LAN-ROLLOUT.md). Scope contains no Tailscale or mesh work.

## LAN-01 — Freeze shared contracts
Owner: Lenovo. Dependencies: none. Priority: P0.

As a platform implementer, I need common schemas so Windows, Mac and mailbox changes interoperate.

- Commit versioned fixtures for configuration, capability negotiation, registration/presence, migration journal and allowlisted errors, with bounded field sizes.
- Preserve current identity/key format and v1 API; define exact duplicate, conflict, expiry and unsupported-version responses.
- Add cross-language fixture validation and negative cases for unknown fields, wrong actor, stale lease/sequence and credential-bearing diagnostics.
- Mac and Area51 review fixtures before dependent implementation merges. No parallel modification of shared runtime interfaces without coordinator agreement.

## LAN-02 — Server registry and presence
Owner: Mac, mailbox repository. Depends: LAN-01. Priority: P0.

As a user, I need the list to distinguish available hosts from stale registrations.

- Add transactional schema/API changes to the actual deployed server baseline, retaining v1 behavior and existing rows/history.
- Derive actor from authentication, preserve pinned desktop key, enforce self-update ownership and new alias uniqueness without merging existing identities.
- Issue fenced runtime leases; 15-second heartbeat / 60-second expiry uses server time. Reject an old process overwriting a new runtime and conflicting duplicate updates; exact retries are idempotent.
- Return Online/Offline/Needs attention plus server lastSeen; legacy availability remains Unknown. New grants reject expired v2 presence, disabled or revoked identities.
- Tests cover persistence/restart, lost responses, out-of-order updates, alias collision, role changes, expiry and mixed v1/v2 clients. Deploy additively with database backup and tested server rollback first.

## LAN-03 — Machine configuration and local broker
Owner: Lenovo shared Rust/IPC; Area51 Windows adapter; Mac Mac adapter. Depends: LAN-01. Priority: P0.

As a user, I want one machine connection setting instead of repairing three applications separately.

- Extend existing service and authenticated IPC; no new standalone daemon. A client-only install runs a broker with hosting disabled.
- Keep one protected versioned configuration and secret references. Existing DPAPI/Keychain signing keys stay unchanged; user/operator credentials retain their separate scopes.
- Mailbox app, watcher and desktop use a coherent revision; bounded authenticated reload makes a failed update leave the previous usable revision.
- Clients cannot retrieve machine bearer/private key, proxy arbitrary URLs or use a read-only operator credential for privileged operations.
- Tests cover caller rejection, partial write, concurrent reload, restart and incompatible schema. Verify both signed-in and unattended service contexts on each OS.

## LAN-04 — Host address and presence recovery
Owner: Lenovo shared loop; Area51 Windows notifications; Mac macOS notifications. Depends: LAN-01/02/03. Priority: P0.

As a host, I want a DHCP address change to recover without reinstalling or re-enrolling.

- OS notifications trigger debounced reconciliation; the 15-second fallback remains. Resolve address from the route to the mailbox; events themselves never authorize/reject sessions.
- Bind, idempotently publish, and swap listeners under the same identity/key. A failed update, duplicate event, rapid A/B/C transition or lost response cannot publish an unbound ready endpoint or let stale work win.
- Existing session tasks remain untouched by notification processing. Actual socket loss reports disconnection; recovery obtains fresh proof.
- Offline Wi-Fi, mailbox outage, service restart, sleep/wake and IP reuse recover with bounded retries. No busy loop or per-poll warning flood.
- Automated loopback/fake-route tests cover missed notifications, occupied port, publication failure and established-session preservation. Do not disrupt the user's real Wi-Fi.

Existing checkpoint `bb58ac5c4` supplies polling/listener replacement as a starting point; it does not close this story.

## LAN-05 — Useful server list and diagnostics
Owner: Lenovo Flutter/shared client; Mac validates Mac client. Depends: LAN-01/02/03. Priority: P0.

As a viewer, I want to select a familiar machine name and understand a failure.

- Show aliases, roles, presence, lastSeen and specific safe error categories. Online is reported readiness, not proof of desktop delivery.
- Retain selected immutable identity on valid refresh, clear it on removal/revocation, refresh every 30 seconds and on resume.
- Resolve fresh endpoint on Connect; retry one pre-handshake TCP failure with new lookup, never an authentication failure or a different machine at a reused IP.
- Directory outage shows Status unavailable; legacy hosts show availability unknown. A stale v2 host is not presented as ready.
- Widget and transport tests cover list changes, identity stability, wrong peer key, directory outage, offline host and compact-window layout.

## LAN-06 — Stable TLS trust and server renewal
Owner: Mac server; Lenovo shared verifier; Area51 Windows migration. Depends: LAN-01/03. Priority: P0.

As a user, I want routine server certificate renewal to work without editing every client.

- Produce an application-scoped CA bundle and standard-tool server renewal process; restricted CA key remains server-side and is never shared as a mailbox secret.
- New leaves are CA:FALSE/serverAuth with required IP SAN. Strict chain/expiry/hostname validation passes on Rust, Electron and watcher runtimes, including their deployed versions.
- Test renewal to a second valid leaf with no client edits, and rejection of wrong SAN, unknown CA, expired certificate and CA-as-leaf before credentials are sent.
- Keep legacy exact-pin support during rollout. Explicit verified migration selects CA mode; a trust failure never selects a less strict mode.
- Document/verify root overlap, restore of the prior server certificate, scheduled renewal and expiry alert. No production rotation until compatible clients and rollback are prepared.

## LAN-07 — In-place migration
Owner: Area51 Windows installer; Mac Mac installer; Lenovo integration verification. Depends: LAN-01/02/03/06. Priority: P0.

As an existing user, I want Upgrade this machine without losing enrollment or history.

- Inventory all real service/user profiles, including Windows MSIX redirection. Detect identity/configuration conflicts; do not guess which credential is authoritative.
- Privately back up packages, encrypted stores, config and watcher state; preserve ownership/ACLs and secret-store access controls. Never save decrypted enrollment.
- Stage broker config and app adapters; verify proposed trust with no credentials first, then authenticated read-only access using the existing credential in its proper context.
- Switch one coherent revision, restart only affected components while idle, preserve cursor/pending batch and history outbox IDs, and update the same registered identity/key/address.
- Resume after interruption using a nonsecret journal; repeated migration makes no duplicate identity, event or registration. Failure restores package/config and reports actual remaining resources.
- Mixed old/new clients work during rollout. No legacy source is removed until its consumers have migrated; retain a verified rollback version supporting the active trust policy.
- Demonstrate migration, interrupted migration and rollback with unchanged token/key equality checks in memory, stable public fingerprint, watcher continuation and a second-machine session. No new identity as fallback.

## LAN-08 — New-machine installation and approval
Owner: Area51 setup/Windows; Mac approval backend and Mac setup; Lenovo shared UI. Depends: LAN-01/02/03/06. Priority: P1, after existing-machine recovery.

As a new user, I want install, approve, name, connect.

- Detect existing mailbox enrollment first and reuse it; otherwise create a pending public-key-bound pairing request with 10-minute expiry and rate-limited attempts.
- A registration administrator approves one machine/roles/alias; normal remote-access credentials and read-only operator tokens cannot approve enrollment.
- Deliver new credentials only to the approved key holder; tests reject guessed/reused codes, wrong-key claim, expired approval and concurrent duplicate claims.
- Configure only owned service/firewall resources, verify protected secret storage, and guide Windows elevation/Mac permissions. Missing Mac permissions show Needs attention, not Online.
- Interrupted setup resumes without a duplicate identity. New machine appears ready only after successful registration, listener/readiness check and a real second-machine authentication test.

## LAN-09 — One repair command and controlled updates
Owner: Area51 Windows packaging; Mac Mac packaging; Lenovo diagnostic contract. Depends: LAN-03/06/07. Priority: P1.

As a user, I want Repair to explain and fix configuration without wiping the application.

- Diagnose broker, trusted mailbox, credentials, registry, listener and permissions separately with an allowlisted report.
- Repair uses the canonical configuration, preserves identity, restarts only owned affected components, defers for active sessions and never imports an unapproved certificate.
- Signed/traceable package checks and verified rollback reuse existing installer work. No broad process kills or firewall disabling; unknown ownership stops safely.
- A fault-injection test demonstrates partial-upgrade recovery and truthful failed/pending/complete states. Missing signing/OS approval is explicit, not reported as installed.

## LAN-10 — Revocation, history and acceptance
Owner: Lenovo test coordinator; all machines supply evidence. Depends: LAN-02/04/05/07; LAN-08 for fresh enrollment acceptance. Priority: P0 for migrated release.

As an administrator, I need trustworthy results and a way to remove a machine.

- Revocation denies new enrollment claims/grants and registry updates. Active sessions revalidate authorization at most every 60 seconds; failed/offline revalidation closes by that bound. Document this policy before implementation; test without logging payloads.
- Preserve durable idempotent metadata-only history and unknown missing-end semantics across migration and rollback. History delivery delay must not fabricate success or erase events.
- Test Lenovo-to-Area51 and reverse, Mac-to-Windows and reverse, clipboard, listener restart, sleep/wake and permitted unattended states. Record exact source/package/config revisions.
- Exercise simulated address changes, server outage, wrong certificate, host revocation, old/new-client coexistence and rollback in isolation. No live Wi-Fi-disconnect test; explicitly record that acceptance limitation.
- Ready for user testing requires working artifacts, current registration, actual authenticated session evidence and usable rollback. Source complete, SCM Running and TCP reachable are separate evidence levels.
