# Browser remote desktop prototype

Real browser remote desktop using the existing mailbox authentication, pinned host handshake, encrypted transport, video and input protocol. The UI has a registered-computer picker, original-size/fit views, automatic scrolling, an edge-docked icon toolbar, bounded reconnect attempts and phone controls. File transfer is not included.

## Use the existing deployment

Open https://192.168.1.9:42841 from a device that can reach the Mac. Trust the verified local public certificate on that device and use the separately supplied prototype website password. No source checkout or per-device SSH forwarding is needed for this shared address.

## Check out and build on another machine

Use Node.js 24 and Git:

```sh
git clone --branch codex/browser-desktop-prototype --single-branch https://github.com/mahhph/hoen-rustdesk.git
cd hoen-rustdesk/browser-prototype
npm ci --include=dev
npm test
npm run build
```

Run commands from `browser-prototype`; the gateway serves its `dist` directory. No Rust or Flutter build is required to build this website. Native remote desktop hosts must already be installed and enrolled in the same mailbox.

## Private gateway configuration

Set `PROTOTYPE_VIEWER_CONFIG` to an absolute path outside the repository. On Linux/macOS its file mode must be 0600, with its parent directory accessible only to its owner. Use equivalent owner-only ACLs on Windows. Required JSON fields:

| Field | Meaning |
| --- | --- |
| `viewerIdentity` | Separately enrolled viewer identity; current deployment uses `browser-test` |
| `hostIdentity` | Default registered host identity, such as `windows` |
| `mailboxUrl` | HTTPS mailbox URL reachable from the gateway |
| `mailboxCaPem` | Trusted public PEM certificate/CA |
| `mailboxFingerprint` | Exact server certificate SHA-256, 64 hexadecimal characters without colons |
| `accessToken` | Existing viewer mailbox credential, canonical base64url encoding of 32 bytes |
| `viewerSeed` | Viewer Ed25519 seed, canonical base64url encoding of 32 bytes |
| `transportOverrides` | Optional server-controlled map from registered identity to `{ "address": "IP", "port": 42830 }` |

The viewer public-key fingerprint must be registered for its identity. A new seed alone does not enroll a viewer. Obtain the existing private configuration through the approved secret mechanism, or coordinate a separately enrolled viewer; never replace another machine's identity or token. Credentials, signing seeds, TLS private keys and website passwords are deliberately not in Git.

Example PowerShell launch after private provisioning:

```powershell
$env:PROTOTYPE_VIEWER_CONFIG = 'C:\private\viewer.json'
$env:DESKTOP_HOST = '192.168.1.3'
$env:DESKTOP_HOST_PORT = '42830'
$env:LISTEN_HOST = '127.0.0.1'
$env:LISTEN_PORT = '42840'
node gateway.mjs
```

On Linux/macOS, set the same environment variables using the shell's `export` syntax. `DESKTOP_HOST` and `DESKTOP_HOST_PORT` supply the fallback endpoint and are required startup configuration. Picker connections use the selected host's authenticated registry endpoint, or a private transport override after confirming its registration. The browser still verifies the selected host key and obtains a fresh connection-bound mailbox grant.

For local testing open http://127.0.0.1:42840. Keep this raw gateway on loopback: it delegates the configured viewer's access and is not a public login service.

## Shared HTTPS access

`shared-access.mjs` provides the prototype password sign-in and authenticated HTTPS/WebSocket proxy. Run it as a separate process on the same machine as the gateway:

```powershell
$env:SHARED_ACCESS_CONFIG = 'C:\private\access.json'
node shared-access.mjs
```

The private JSON has `origin` (for example `https://192.168.1.9:42841`), `certFile`, `keyFile`, `salt`, and `passwordHash`. Certificate/key paths must be absolute. `passwordHash` is the hexadecimal result of Node `scryptSync(password, salt, 32)`; provision a random salt and keep this configuration private. Do not commit credentials or use a shared example password.

The HTTPS process listens on loopback port 42841 and proxies to loopback 42840. A host-side TCP ingress must make 42841 available at the configured origin; this is deployment-specific. The certificate must match the origin hostname/IP and be trusted by each device. Website sessions expire after eight hours or a proxy restart. This prototype uses one shared website password, not individual contractor accounts.

## Existing Mac/Linux deployment notes

- Source checkout: `/home/hudsonhoen.guest/browser-desktop-prototype`.
- Gateway configuration: `/var/lib/hoen-browser-prototype/gateway-config/viewer.json`.
- HTTPS private configuration: `/var/lib/hoen-browser-prototype/shared-access/access.json`.
- Containers: `hoen-browser-prototype` and `hoen-browser-shared-access`.
- Mac publishes shared HTTPS port 42841. Area51 and Lenovo are reached using their registered LAN endpoints.
- Mac's desktop transport override is Linux host loopback `127.0.0.1:42833`, supplied by Mac's persistent SSH forwarding LaunchAgent. This endpoint is specific to the Linux VM, not portable to another machine. Keep the registry's real Mac LAN endpoint unchanged. Containers using this override need host networking.
- Linux keeps `.9/32` and the legacy `.24/32` service aliases. Do not restore the old `.24/24` loopback alias: it captures the whole LAN route.

Use a service manager for persistent processes. The running Linux image history is deployment state, not a required build dependency: this source can run directly with Node after `npm ci` and `npm run build`.

## Verification and limits

Area51 browser login/live video, live resolution changes (the resolution UI was later removed), Mac browser login/live video, shared LAN TLS/sign-in/WebSocket handshake, and automatic reconnect after a gateway restart have passed. Unit tests cover framing, authentication vectors, host handshake rejection, registered-host routing and retry/cancel/timeout behavior. Phone-sized portrait/landscape layouts were checked. Physical iPhone Safari touch/keyboard acceptance is still pending. Mac's native lock screen was visible during the agent test; the user subsequently confirmed the browser connection worked.

This remains a prototype. Individual users, per-user machine assignments, public certificate deployment and full reboot/recovery acceptance are not completed.

## Attribution

The viewer contains an MIT-licensed subset of https://github.com/bropines/rdweb at commit `bdb92fae6c32d175e7633c6c68c4279ee9a994ba`, adapted for the mailbox handshake and toolbar behavior. See `vendor/rdweb/LICENSE` and `vendor/rdweb/NOTICE`.
