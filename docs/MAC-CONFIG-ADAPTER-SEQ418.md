# Mac adapter staging, sequence 418

Baseline: PR26 exact head 5336ec7f000822b244acbd4e5643060165575fb9.

`runtime::migration::preflight_mac(purpose, expected_revision)` opens the existing interactive-user MacStore namespace and reads only the requested host/viewer item. It uses shared protected preparation to reject stale revisions, incompatible aliases, trust and metadata conflicts. A host item without hosting enabled is rejected. It returns proposed public configuration and public signing-key fingerprint, with activation readiness and authenticated mailbox verification false. Original enrollment and Keychain bytes are never written by this path. Missing and unreadable entries remain unavailable; neither creates an identity. No runtime caller or IPC endpoint is installed.

The baseline already includes host_secret_from_viewer role correction and regressions preserving viewer identity, credentials and revision. This change does not alter provisioning or host lifecycle. Existing host/client separation must be identified by exact branch/head and reconciled before lifecycle wiring.

Activation remains blocked on a coordinated ownership/IPC contract. MacStore::write is an unconditional update, not an atomic compare-and-switch across processes. A read/check/write sequence would lose concurrent changes. Do not use it for activation. Agree exclusive host authority, authenticated caller/privilege verification, revision response/error shape, allowlisted prepare/activate/rollback operations, protected backup ownership and crash recovery semantics with Lenovo before shared edits. This staging intentionally exposes no activation API and persists no staged secret.

Next required authorized local integration: build and test the signed host/viewer artifacts with the existing Keychain ACL and namespace; run absent/locked/denied/existing-item tests in a disposable Keychain, then explicitly authorized installed-bundle read-only validation. Exercise concurrency, interruption, backup readback and compatible rollback before installing any migration. Worker filesystem roots exclude installed application and user Keychain writes; no workaround attempted. No live credentials, identity, trust, app settings, active sessions or watcher configuration changed. New server processes remain Linux-only.

Regression surface: only runtime_migration.rs adds an uncalled macOS entry point; all existing runtime paths and shared interfaces retain behavior. This is source staging, not completed migration or deployment.
