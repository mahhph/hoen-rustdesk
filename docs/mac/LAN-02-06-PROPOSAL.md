# Mac/server contract review proposal

2026-11-08; request seq356. Proposal for LAN-01 review, not an implemented API or deployment.

## Reconciled deployment

Read-only Docker inspection identifies production container `hoen-agent-mailbox`, image
`sha256:5fb9cca1e2652aa5fe325a0098617d54a0504c1b7d93f5ea469ec8783f0f986d`,
working directory `/app`, command `node --experimental-strip-types scripts/mailbox-server.mjs`,
with Linux `/var/lib/hoen-agent-mailbox` mounted at `/data`.

Live source SHA256:

| File under /app/src | SHA256 |
|---|---|
| remote-machines.ts | 722a0cb93f4805ffa1ed6affb4d8af3b4fec573ecfc58b288eaffb32c4251294 |
| remote-grants.ts | 120b9a30b0bac82ce17232a9f9b802904a21fa570871310677be8599ee0cdc5b |
| agent-mailbox.ts | 26f23f2a274f71e0d5eb18a4833c397a43decb0fb092561ba4dd261bd4cee4ae |

Local reconciliation-seq156-repo at `8df530355261fb62bd0e617e8ea38e418b92aee9`
only matches remote-grants.ts among these three files. Live registry includes
`updateAddress`, which the checkout lacks. Preserve this path when reconciling a
server branch; do not deploy that old checkout over production. Full source and
lockfile reconciliation and target integration branch identification remain prerequisites.
No database, environment or credential contents were collected for this proposal.

## LAN-02 additive storage proposal

Retain remote_machines and existing v1 serialization. Add separate versioned current-state
tables with foreign keys to existing immutable identity: profile (roles, alias, normalized
alias, schema revision, presence adoption flag), runtime fence (monotonic generation), and
current lease (opaque random ID, generation, sequence, canonical payload digest, accepted
server time, expiry, endpoint revision, readiness, allowlisted error/build ID). One current
lease per identity bounds heartbeat storage. Migration is transactional, preserves all old
rows and does not rewrite desktop public keys, enrollment, history or receipts.

Acquire leases and update their fences inside BEGIN IMMEDIATE. Authenticate actor from
the server identity, never request body. A lease creation needs a client operation UUID:
retrying a lost response must return the same lease, not fence out the runtime which just
started. LAN-01 must settle UUID retention and how an old creation retry is rejected after
a newer runtime starts; UUID alone does not establish runtime ordering.

Heartbeats require current opaque lease plus generation and increasing safe integer sequence.
An exact duplicate returns the previously accepted result WITHOUT extending expiry; a changed
payload at the same sequence is a conflict. Lower sequence or superseded lease cannot write.
Use server time, 15-second heartbeat, 60-second expiry. Return lastSeen/expiresAt and endpoint
revision, with no permanent per-heartbeat audit append. Offline is computed at read time.
Listener/capability failure is Needs attention while lease is fresh. No v2 adoption is Legacy,
availability unknown. Directory failure is a client Status unavailable error.

Prevent legacy register/updateAddress from changing the effective v2 endpoint or readiness
once presence is adopted; otherwise an old process bypasses fencing. Choose an explicit
compatibility policy in LAN-01: preserve v1 metadata writes but isolate v2 effective state,
or reject conflicting writes for adopted identities with a documented upgrade error.
Retain legacy behavior for identities that have not adopted v2.

Check enrollment/revocation, roles and freshness on both grant issue and consume in the same
transaction as grant state mutation. Consumption currently revalidates pinned participants;
retain that property. Stale v2 hosts cannot obtain new grants even through v1 callers.
Legacy hosts retain current grant behavior until explicit adoption. Active-session bounded
revocation is a separate shared client/host implementation, not solved by registry expiry.

## LAN-01 decisions requested from Lenovo

- Freeze exact capability/config/profile/lease fixtures and error codes before dependent merges.
- Define ASCII case fold versus Unicode normalization for aliases, byte bounds and handling of
  existing collisions. Never silently rename or merge existing identities.
- Define client-only roles with absent endpoint and readiness false; do not require a fake listener.
- Define lease-create idempotency/fencing, maximum sequence, canonical digest and duplicate response.
- Freeze unknown-field rejection, payload limits and safe diagnostic allowlist. Public build IDs
  must be bounded, never arbitrary error text.
- Agree v1/v2 mixed-writer policy and grant-gating changes explicitly as compatibility boundaries.

Tests after fixture approval: restart/persistence, exact/lost-response retries, old lease and
out-of-order updates, changed duplicate, aliases/role changes, expiry boundary, revoked actor,
v1/v2 coexistence, grant issue/consume race, migration and restored old-server rehearsal.
Snapshot using the existing consistent backup procedure, never copy only a live SQLite main
file. Keep old release and preserved database/keys; rehearse rollback with post-migration writes.
Do not discard newly accepted messages/history when restoring.

## LAN-06 standard-tool plan

Generate and retain an application CA only on the Linux server in a restricted directory,
using standard OpenSSL tooling. CA key is outside releases, client bundles and mailbox secrets;
restrict owner and mode, inventory encrypted recovery and its owner before generation.
Issue leaves with CA:FALSE, keyUsage digitalSignature (and keyEncipherment if required by the
chosen key/runtime), extendedKeyUsage serverAuth and IP SAN 192.168.1.9; approved DNS names
only. Retain serial/index state and validate the output with OpenSSL before activation.
Use a Linux systemd oneshot/timer for expiry checks/renewal, with atomic versioned file switch,
service-specific reload/restart and restoration of the previous pair on verification failure.
No new certificate service or Mac daemon is needed. Exact service manager/reload command and
renewal threshold require deployment inventory; this is not an installed timer.

Before live changes, generate isolated synthetic CA and two leaves. Test strict chain,
validity and actual URL SAN on deployed Rust, Electron and Node watcher runtimes. Verify
wrong SAN, unknown CA, expired certificate and CA-as-leaf rejection before transmitting
credentials; demonstrate second leaf success with unchanged client configuration. A generic
OpenSSL verification alone cannot establish these application runtime checks.

Stage CA bundle authentication through the currently verified pinned endpoint PLUS independent
verified trust metadata. LAN-01 config names explicit leaf-pin or application-CA mode, revision
and bundle digest; no automatic fallback on error. All consumers must support the replacement
leaf before server activation: separate exact-pin-only consumers cannot survive arbitrary leaf
rotation on the same endpoint. Keep the current production certificate active throughout this
preparation. Root rollover requires explicit administrator approval and old/new overlap.
Never install a global OS root, export CA keys or repair a failed verification by disabling it.

## Mac adapters and access

After shared contracts agree, keep Keychain/launchd/notification/installer code in Mac-only
modules, proposing any src/hoen hooks to Lenovo before editing. Reuse the existing service and
authenticated local IPC; operations are bounded and caller-authorized, without bearer export
or arbitrary URL proxy. Preserve existing Keychain signing references and separate operator
credentials. Prepare and validate a config revision before activation. Network path notifications
wake the shared debounced reconciliation loop, retaining its 15-second fallback; they never
invalidate established session tasks.

Migration inventory, backup and journal must preserve encrypted stores, watcher cursor/pending
work and history IDs. No watcher files are changed by this worker. Installed bundle replacement
is outside current writable roots; previous builds recorded Xcode cache write denial, and
Keychain changes require an authorized local context. Adapter build/install/TCC acceptance is
pending that access and LAN-01 contracts. No permission bypass, live Wi-Fi disruption, production
certificate rotation, new process or Area51 development assignment was performed.

Regression surface of this deliverable: one new proposal document only; no existing source or
runtime behavior changed. No executable implementation, installation or desktop acceptance claimed.
