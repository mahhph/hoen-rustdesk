# Production mailbox TLS handoff

Status as of 2026-11-06: preparation only. No live certificate, trust profile, service, or database was changed by these checks. Native Windows TLS still rejects the current production certificate because it has no matching SAN. Do not bypass hostname validation.

## Reconciled candidate

Mac message 209 reported conflicting local copies. Lenovo subsequently connected through the previously pinned SSH host at `192.168.1.24:42822`, using its dedicated protected key. Read-only checks on Linux confirmed:

- Candidate `/var/lib/hoen-mailbox-tls-candidates/seq204/mailbox.crt` has SHA-256 fingerprint `7F:E7:4D:2D:23:2D:6A:E1:A3:F3:EF:D0:A4:53:A8:26:55:F5:A5:2C:3C:10:3E:D1:13:34:18:53:B8:39:99:5F` and IP SANs `192.168.1.24` and `127.0.0.1`.
- The certificate's public-key DER hash and the public-key DER hash derived locally from its private key both equal `3d47a92011d87df4f0ff378bd09d2aa090608d0ed00fe080e6594663c7be0cfb`. No private key was transferred or printed.
- The attached public PEM independently matches that fingerprint and validates its own signature. Validity is 2026-11-06 05:16:15 UTC through 2027-12-08 05:16:15 UTC.
- Live production image is `sha256:c470c86b25f653b85d8acf4d77d1f492ee4b64a4bf8cd134ab901266ced29ff5`, started at `2026-11-06T01:32:09.517593527Z`, matching the reported rehearsal image/time. Matching metadata is not a fresh rehearsal.

The other Mac workspace PEM, fingerprint beginning `31:2D`, is not this Linux candidate. Mac received the reconciliation evidence in message 220. The reported historical nine-assertion synthetic TLS rehearsal has not been independently rerun on Lenovo against this exact candidate. Native Rust and coordinated cutover checks remain outstanding.

## Trust consumers identified on Lenovo

- CLI: `%LOCALAPPDATA%\HoenAgentMailbox-hoenlenovo\client.json` is a protected credential profile; never copy its bearer into this repository or messages.
- Mailbox watcher: its `watcher.json` references that same CLI connection file. Updating the shared pin affects the watcher too; coordinate its trust update with its maintainer.
- Installed mailbox desktop app: `%APPDATA%\HoenAgentMailboxDesktop\connection.encrypted` exists. Its saved endpoint/pin have not been inspected or changed. Use the application's supported configuration path; this is a separate consumer from the CLI.
- Remote Desktop Service: not installed; neither the service bootstrap nor runtime ProgramData directories exist. The eventual bootstrap must use the activated, validated certificate and current machine profile.

On Linux the portal has a separate `HOEN_PORTAL_UPSTREAM_PIN` and its own browser-facing certificate mount. Its upstream pin requires coordinated update, while browser-facing TLS and development TLS are separate. Mac's CLI/address-refresh/watcher and Area51's consumers still need their exact inventory and supported update procedure; requests were sent in messages 220 and 221.

## Before activation

Reconcile the remaining consumer inventories and prepare exact reversible commands. Run a fresh isolated candidate validation, including the native Rust client, without changing live trust. Establish a backup/recovery procedure that preserves the latest database and credentials. Stage matching trust changes together with the production TLS replacement and portal configuration; validate strict TLS, exact pins, authentication and data afterward. Rollback must restore old TLS and matching client/portal pins without restoring an older database over newer messages. Returning to the old SAN-less certificate restores legacy clients only; it does not make native hostname validation succeed.

Area51 PR #4 separately removes the home-network admission policy and uses the saved local bind address instead of resolving the current address at startup. It is not merged into Lenovo's approved-home-network branch. The current-IP registration regression and conflicting policy requirements were sent back to Area51 in message 221; neither issue is resolved by a certificate change.

## Four-case native acceptance and supported re-enrollment

Mac's time-limited `hoen-tls-test-seq234` endpoint was tested through Lenovo's existing dedicated-key, strictly pinned SSH tunnel. A Rust 1.75 harness compiled the actual production `tls_pin.rs` verifier and performed raw TLS handshakes only: correct sole root, expected IP `127.0.0.1` and exact pin succeeded; unrelated root failed with `UnknownIssuer`; expected IP `192.168.1.25` failed with `NotValidForName`; wrong exact pin failed with the verifier's pin-mismatch error. No HTTP request or credential was sent. The owned local tunnel was stopped afterward; Mac's service remained under its configured expiry. The reproducible manual harness is `libs/hoen-mailbox-auth/examples/staged_handshake_probe.rs`; it also passes the standalone crate's locked, offline Rust 1.75 example check. This is loopback TLS evidence, not desktop or direct-LAN acceptance.

The custom Windows profile-edit draft PR3 was rejected in review and subsequently closed. The agreed simpler path is the existing per-agent encrypted bootstrap: retain the old protected profile and existing enrollment private key, refresh the envelope using the unchanged token, and exclusively create a distinct new profile after verified certificate activation. Lenovo independently verified its retained RSA3072 key pair matches server-recorded public SPKI SHA256 `c94d07a8d1bf10fc47459b792188acb0f8fe997c648cecea6b4fb2f542810354`. Mac message 273 confirms that existing-token envelope is refreshed through 2026-11-07 15:16:05.578 UTC. The actual private profile must still be created and verified; no token or private key was transferred.

Lenovo's planned new path is `%LOCALAPPDATA%\HoenAgentMailbox-hoenlenovo\client-san-20261106.json`, currently absent. Its existing parent has a protected, inheritable DACL allowing only the current user and SYSTEM. The old `client.json`, enrollment key and desktop encrypted configuration remain unchanged. The supported client must receive the explicit identity `windows-hoenlenovo`, never Area51's `windows` identity. Compare URL/environment and token equality privately after bootstrap; do not print credentials. A watcher reading configuration at startup still needs its owner's supported switch and restart.

Portal review also found three omitted live settings in the initial replacement command: read-only root filesystem, all capabilities dropped and no-new-privileges. Mac message 268 confirms the revised draft preserves these and checks full configuration against the live baseline. It has not been executed. Message 281 explicitly establishes **no cutover window or bootstrap go-ahead**: Mac's worker is prohibited from modifying watcher state/configuration and requires authorized owner readiness plus fresh full stopped-data recovery and coordinated activation confirmation. Do not mistake prepared envelopes or successful TLS tests for permission to change live trust.
