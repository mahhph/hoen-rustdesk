# Windows home-network observation trial

This is an opt-in diagnostic for the existing Windows policy, snapshot and notification code. It does not install or start a service, change Wi-Fi, routes or firewall rules, open a listener, connect to a peer, authenticate a user, or start a desktop session. It is not evidence of end-to-end access or unattended operation.

On the intended Windows machine, run `powershell -NoProfile -File scripts/hoen-network-candidates.ps1` from the repository root to list non-secret candidate adapter GUIDs, Network List Manager network GUIDs, and preferred local addresses. This is discovery only: an operator must independently identify the intended approved home Wi-Fi. The live Rust check also requires a connected physical Wi-Fi adapter, private profile, matching address and network identity. Do not enroll a candidate merely because it appears in the list. Do not paste credentials or private keys into this diagnostic.

With Rust and the normal RustDesk Windows build prerequisites installed, supply the chosen approved values explicitly:

```powershell
cargo run --features hoen-mailbox --example hoen_network_trial -- <adapter-guid> <network-guid> <local-ip> 30
```

Optionally append a peer IP to test the route snapshot for the approved interface and on-link route. This performs a route query only; it does not open a socket. IPv6 unique-local addresses are supported; scoped link-local addresses are not represented by this trial.

The program subscribes to the real monitor before inspecting the actual binding. It confirms the approved policy, rejects a deliberately different adapter ID against the same live query, and waits a bounded number of seconds for an operating-system notification. `NOT OBSERVED` means no transition was observed; it is not a pass for transition handling. A changed network during the checks invalidates the attempt. Any disruptive Wi-Fi or adapter change must be coordinated separately with the person using the machine. Run this only when explicitly requested; this repository does not automatically change connectivity.

This trial reports observations from a single machine. It does not establish that a remote connection or application session was secured or terminated on a network change. Approval, enrollment, OS firewall enforcement, authenticated host admission, installation, and two-machine tests remain separate steps.

## Lenovo observation, November 5, 2026

The example compiled and ran with the current physical Wi-Fi adapter and local address, but returned `NotApproved` at the initial binding check. Read-only Windows queries confirmed the adapter is active, hardware-backed Native 802.11 and nonvirtual, while its network profile is **Public**. A public profile is sufficient to reject this policy. The candidate discovery script now displays network category and whether the private-profile requirement is satisfied. No network profile or connectivity setting was changed. The user has been asked before changing Windows trust to Private; this remains pending. The mismatched-adapter, peer-route and notification checks were not reached, so this run does not establish that they work against the real network.
