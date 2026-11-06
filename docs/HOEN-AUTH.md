# Mailbox connection authentication contract

The `hoen-mailbox` build feature contains strict handshake and proof-consumption entry points in `src/hoen`, typed HTTPS registry/grant calls in `libs/hoen-mailbox-auth`, and feature-gated host/viewer runtime hooks. These are source implementations, not a deployed or two-machine-validated authorization service. No existing password/manual-approval path gains a mailbox identity simply because a peer supplies a name or token.

## Policy

Every enrolled mailbox identity may request access to any registered hosting-enabled machine. The network path is not an access rule: local, VPN, Internet, and relay connections are allowed when the encrypted channel and mailbox proof are verified. The current runtime implements only direct native TCP; other transports still need their own verified channel binding and tests. Windows network category, network name, adapter identity, and peer route do not grant or deny access. Device private keys stay local. The mailbox issues a fresh 60-second opaque grant to the authenticated viewer; only its SHA-256 hash is stored. Only the designated authenticated host can consume it, once, while both identities and their pinned keys remain valid. A failed or ambiguous consumption requires a fresh connection/grant, not replay of the consumed token.

Both desktop peers must verify the actual cryptographic context. The mailbox cannot establish a channel binding from an arbitrary submitted hex string. Host lookup is not a grant, and grant consumption is not proof of a live desktop session.

## Proposed native TCP binding

Use only the authenticated encrypted native TCP path with negotiated key-exchange version 1. Reject plaintext, insecure direct-access fallback, unknown versions and other transports in Hoen mode until separately reviewed. The existing server handshake exposes the two ephemeral box public keys and negotiated version before calling `set_negotiated_key`; the viewer has the corresponding values while verifying the signed host identity. Do not modify the shared submodule merely to derive this public transcript hash.

Existing `secure_connection` return values and `is_secured` are not sufficient evidence: legacy fallback can return a public key without completing the intended encrypted handshake. Capture an explicit verified context only after successful signature verification and `set_negotiated_key`. `Stream::Tcp` also wraps some KCP and relay paths, so retain explicit transport provenance and prove the channel binding for the transport actually used. In Hoen mode, use the mailbox-pinned host signing key as the trust anchor rather than requiring a public rendezvous lookup.

The current direct IP/domain client path returns before `secure_connection`, so it needs an explicit Hoen handshake rather than a flag applied to the old path. The registry currently stores only a fingerprint; upstream `SignedId` does not expose the long-term verification key. Proposed protocol addition: an optional raw host verification-key field on `SignedId`, populated in Hoen mode. The viewer first checks SHA-256 of that exact 32-byte key against the authenticated mailbox pin, then verifies the signature and derives the channel context. Merely carrying the key in a message proves nothing without the pin/signature checks. The signed RustDesk ID differs from the socket IP; Hoen must keep endpoint addressing separate from identity and anchor identity in the pinned key. The host's direct listener must explicitly select the secure handshake in Hoen mode.

Define `channelBinding` as lowercase hex SHA-256 of this fixed binary concatenation:

1. ASCII `hoen-mailbox-channel/v1` followed by one zero byte.
2. Verified host Ed25519 public key, 32 raw bytes (not a PEM certificate).
3. Initiator ephemeral box public key, 32 raw bytes.
4. Responder ephemeral box public key, 32 raw bytes.
5. Advertised key-exchange version, unsigned 32-bit big-endian.
6. Selected key-exchange version, unsigned 32-bit big-endian.

Do not derive this from a RustDesk peer ID, IP, name, public grant body, or caller-supplied login field. Both sides independently compute it from their successful handshake. Host public-key fingerprint means SHA-256 over the raw 32-byte Ed25519 public key. Canonical key lengths and accepted versions must be checked before hashing.

## Proposed viewer proof and admission

After verifying the host's signed identity against its mailbox registry pin, the viewer requests a grant for that host and its independently computed binding. The token travels only inside the encrypted desktop connection. The viewer also sends its raw 32-byte Ed25519 public key and a detached signature made by its locally protected device key over:

`ASCII("hoen-mailbox-viewer-proof/v1") || 0x00 || raw_channel_binding_32 || SHA256(raw_grant_token_32)`.

The grant token uses canonical base64url without padding; decode to exactly 32 bytes before hashing. The signature is 64 bytes. No private key or password goes in the proof. Do not log tokens or proof-bearing login payloads.

The host independently derives the binding from its secure handshake and verifies the detached signature. It consumes the token with its own authenticated mailbox credential and the derived binding. Before desktop initialization/admission, it requires the returned host fingerprint to match its own key and viewer fingerprint to equal SHA-256 of the verified viewer key. It then has an authenticated mailbox participant for history. All failure paths reject admission in Hoen mode; none fall back to a password, manual approval or a self-reported identity.

The proposed login proof must live in a new dedicated optional protobuf field in `libs/base/protos/message.proto`; existing password or trusted-device fields must not be repurposed. The feature-off path remains unchanged. The allocated fields are `SignedId.hoen_host_key = 2` and `LoginRequest.hoen_proof = 20`; `HoenProof` contains raw viewer key (1), raw grant token (2), and signature (3). These additions live in client-only `libs/base`; no shared submodule changed. The allocation was sent to Mac in mailbox 144. No existing login/admission path uses them yet.

Carry the verified binding in connection-scoped state through viewer login/UI retries; never cache it globally or by peer ID. Host enforcement must cover the common final authorization path before `authorized=true`, including connection-manager approval, recent-session reuse, 2FA and side-switch paths. Reuse a successful grant verification only on the exact same connection; do not consume again on a login retry, and never reuse across a reconnection. The version bytes in this independent hash are big-endian even though RustDesk's split-key KDF uses little-endian bytes; use the contract encoding, not the KDF transcript serialization.

The initial registry has one machine/key per authenticated identity. Viewer key enrollment must be automatic onboarding, not an extra host-specific access whitelist. Separating user identities from multi-device key enrollment is future work. Mailbox commit `37e0f45` permits equal viewer/host identities while retaining enrollment, pin, eligibility and single-use checks. Enrollment must be automatic for a signed-in viewer before claiming complete authorization integration.

## Required verification

The host now sends an encrypted `Message.hoen_key_confirmation = 35` carrying `HoenKeyConfirmation.channel_binding = 1` after key installation. The viewer checks it before requesting a grant, preventing a replayed signed greeting without the ephemeral private key from spending the viewer's grant quota.

The handshake caps packets at 4 KiB until host authentication. The viewer restores the native frame limit after encrypted key confirmation; the host must retain its pre-admission cap until successful authorization. RustDesk's legacy decryptor accepts raw frames of zero or one byte without AEAD verification. Every Hoen receive path must reject decoded frames of length at most one before activity/liveness accounting or dispatch, including the eventual desktop session loops; empty messages are not a Hoen keepalive. The new handshake rejects them, but the old session loops have not yet received this gate. No shared-submodule patch is needed if all Hoen paths enforce this condition.

The typed HTTP client runs on a bounded dedicated worker; construction, requests and destruction of its blocking runtime stay off the application async runtime. The current direct transport helper binds its configured local address and uses the actual socket; it does not decide authorization from network type or route. Its encrypted handshake and mailbox proof remain mandatory. Public rendezvous/relay is not yet implemented in this path, even though the product requirement permits those transports once they have verified channel binding and authentication.

Windows credential storage uses separate DPAPI user scopes for the interactive viewer and LocalSystem service, protected owner-only directories, and atomic replacement. The installer must provision these directories and transfer enrollment securely to the service identity; neither happens automatically in these modules. Existing RustDesk configuration obfuscation is not used for mailbox credentials.

Before enabling admission, test matching host/viewer binding vectors, swapped ephemeral keys, changed host key or negotiated version, invalid signatures, incorrect viewer pin, expired/replayed token, wrong host, disabled registration, missing credential, and plaintext/legacy fallback rejection. Test real native TCP end to end and failure cleanup. Central history starts only after successful authentication and desktop initialization, not after issuing or consuming a grant. A valid channel binding authenticates one encrypted connection; each additional transport must derive and verify its own binding.
