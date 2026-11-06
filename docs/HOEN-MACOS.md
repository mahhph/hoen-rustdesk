# macOS mailbox host development

## Mac viewer test (2026-11-06)

The user tested the development Mac client against both Area 51 and Lenovo and
reported that both worked. Before the final monitor/retry fix, a connection to
Area 51 displayed the desktop but repeatedly disconnected; after the fix the
user reported success against both machines. The current development viewer
uses the existing `mac` mailbox identity with a Keychain-protected signing key.
This user-reported result is viewer evidence; it does not establish Mac host,
unattended service, clipboard-format, or session-history acceptance.

## Mac host development: shared device identity

The development client can provision a separate host Keychain entry from its
existing protected viewer entry with `--hoen-provision-host-from-viewer`. This
explicit operation reuses the same mailbox identity, trust, credential and
signing key, and refuses to replace an existing host entry. It does not start a
listener or grant a remote connection. The host must still bind successfully,
register with the mailbox, complete the authenticated transport and grant
checks, and pass interactive capture/input permission and live-session tests.
This is a logged-in-user development path, not an unattended login-window
service or a production installer.

The logged-in Mac app also keeps its host controller available while hosting
is disabled, so enabling the service later does not require restarting the
app. If host startup fails, the controller logs the failure and stops rather
than repeatedly requesting Keychain access. A restart is currently required
after correcting that failure. This behavior does not establish login-time
startup or automatic recovery from network changes.
The Mac host acquires the app's local control socket before starting hosting;
if another instance owns it, the new host stops without closing that instance.

To inspect the app's macOS permissions without requesting either permission,
run its signed executable with `--hoen-host-permissions` from the intended
logged-in account. It reports Screen Recording and Accessibility separately,
and exits unsuccessfully if either is missing. Grant permissions to the same
app in System Settings before a live host test. This check does not start a
listener, access Keychain, or establish that capture and input work.

Current seq210 integration supersedes earlier network policy and readiness notes below.
The native TCP transport checks its configured local binding; adapter/network IDs,
SSID, interface type, OS category and peer route are not authorization checks.
Mac retains Keychain enrollment and the development app namespace, but no longer
queries Wi-Fi identifiers or automatically selects a pinned-network address.
Network notifications may terminate a session; reconnection requires fresh proof.
At startup the app resolves the current local address used to reach the mailbox;
after a successful bind the host registers that address. A running host does not
yet reinitialize itself after a network change. Relay is unimplemented.
Earlier seq191/193 admission descriptions are historical and superseded.

The development build uses the `hoen-mac-dev` feature and separate application, Keychain, and history names. The production mailbox feature keeps network admission disabled until the real-device trial has passed. Stock RustDesk installation, removal, and update commands are disabled in mailbox mode pending a separate installer. The application bundle identifier and launch-agent isolation still require verification before running alongside an existing installation.

With Rust, Flutter, CocoaPods and the native dependencies already configured, `python3 scripts/build-hoen-mac-dev.py` builds a separate development bundle and signs it locally for testing. It preserves the existing Xcode project contents, saves recovery copies under the build directory, and refuses to overwrite a project file changed during the build. This ad-hoc signature is not a production signing identity.

The mailbox-enabled Mac build uses a logged-in user's Keychain for enrollment and a private user-owned directory for the history outbox. The login-window/root context is not enrolled by this implementation. Host and viewer entries have distinct names, but Keychain access control identifies the executable, so those names are not an isolation boundary between processes running as the same user and executable.

Historical network-policy notes below describe the superseded Wi-Fi trial, not the
current host's admission policy. The mailbox grant and authenticated host
handshake remain required; missing identity or trust data fails closed.

The following commands are development setup operations for the signed application executable inside the app bundle. Run them as the intended logged-in user, not as root:

- `--hoen-request-wifi-access` requests Location Services authorization because macOS restricts access to Wi-Fi identity. The app does not request location coordinates.
- `--hoen-network-identifiers` displays opaque candidate adapter and network identifiers and the current local IPv4 address. Discovery is not approval. Independently verify the intended Wi-Fi before using these identifiers in an enrollment bundle; do not place mailbox tokens or private keys in command arguments or logs.
- `--hoen-import-host` reads the validated enrollment bundle only from standard input and saves it to the user's Keychain.

The code and synthetic tests do not establish production readiness. A signed application and stable signing identity, explicit network approval, real-device enrollment, a second authenticated machine, screen-recording and accessibility permissions, real Wi-Fi and reboot transitions, and complete interactive session tests remain necessary. The macOS network observer and Keychain behavior must also be verified in the installed application's actual launch-agent context. A login-time address change only works when the mailbox service itself remains reachable and its TLS identity still validates.
