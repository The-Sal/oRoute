# oRoute

oRoute is a small utility that optimizes connectivity to a remote host that you normally reach over Tailscale. If a direct/local path ("fast path") to the same machine is available on your LAN, oRoute will detect it and use that instead for lower latency and higher throughput, while still working seamlessly via the Tailscale address when no local path exists.

The project is split into:
- oRoute (client CLI): probes a target reachable via Tailscale to discover an equivalent local/LAN address and then runs your command (ssh, rsync, etc.) against the best path.
- oRoute_daemon (server/agent): runs on the target machine and exposes minimal info (its server UUID and its local IPs) over a tiny TCP service used by the client to verify local reachability.
- installer.py: a simple convenience script to copy the client and daemon into /usr/local/bin and set them executable.


## How it works (high level)
1. You provide a host that is reachable via Tailscale (for example, a Tailscale IP or name).
2. The oRoute client connects to the oRoute_daemon on that host (default TCP port 9800) and asks for:
   - GET_LOCAL_IP → the list of local/LAN IPs the server sees on its interfaces
   - GET_SERVER_ID → a UUID that identifies that specific server process
3. For each reported local IP, the client attempts to connect back to the daemon and read the same server UUID. If a match is seen, it knows that IP reaches the same machine locally, and it will prefer that IP for subsequent commands.
4. Depending on the selected service (ssh, rsync, etc.), the client will substitute the Tailscale host with the discovered local IP in your command invocation.

This handshake ensures that the client only switches to a local IP if it really reaches the same server (UUID match), avoiding accidental routing to a different node that happens to share an IP or hostname.


## Components in detail

### 1) oRoute (client CLI)
File: oRoute.py

Key features:
- resolve_connectivity(host): Quietly probes the daemon to determine if a local IP is reachable and returns a JSON-serializable result containing tailscale_address, local_address (if verified), reachable, and server_uuid.
- SSH fast path: Defaults to acting like an optimized ssh launcher that swaps the host with the verified local IP when possible.
- rsync fast path: Supports both ssh-style rsync ([user@]host:path) and rsync daemon URLs (rsync://host[:port]/module/path). It can also inject a host into shorthand daemon URLs like rsync:///module/path, and then replace that host with the local IP if a fast path is found.
- SavedHostLayer persistence: Automatically save a mapping from username -> Tailscale address when you connect using user@address, and later allow connecting using just the username or a custom alias. Data is stored at ~/.cache/oRoute.json.
- Network scan: search_for_servers() can sweep local subnets to locate oRoute servers and display their IPs and UUIDs.
- update: convenience action to clone the GitHub repo and run installer.py.

Primary CLI services exposed via help:
- ssh: Optimized SSH connection (default behavior if you invoke the client for SSH use).
- rsync: Optimized rsync over SSH or rsync daemon URLs.
- search: Scan local networks for oRoute servers and list what is found.
- resolve: Output JSON containing tailscale/local addresses, reachability, and server UUID.
- update: Update from GitHub using installer.
- help: Show usage help and examples.

Rsync helpers inside oRoute:
- _replace_host_in_rsync_endpoint(endpoint, original_host, new_host): Carefully swaps the host portion of an rsync endpoint, supporting both SSH and rsync daemon syntaxes while leaving local paths untouched.
- _inject_host_if_missing_in_rsync_endpoint(endpoint, host): Supports shorthand rsync daemon URLs (rsync:///module/path) by injecting a host and later replacing it with a local IP when available.


### 2) oRoute_daemon (server/agent)
File: oRoute_daemon.py

- Lightweight TCP server built on utils3.networking.sockets.Server, listening on 0.0.0.0:9800 by default.
- Exposes two simple requests:
  - GET_LOCAL_IP → returns a JSON array of detected local IPs
  - GET_SERVER_ID → returns a per-process UUID
- Collects local IP addresses by invoking ifconfig and parsing out non-loopback addresses.
- Can be run in the foreground, or with the --screen flag to spawn a detached GNU screen session named "oRoute_daemon".

Note: The daemon returns what it believes to be local IPs. The client verifies any claimed local IP by re-connecting and matching UUIDs, which prevents accidental misrouting.


### 3) installer.py (installer helper)
File: installer.py

- Prompts for confirmation and then copies:
  - oRoute.py → /usr/local/bin/oRoute
  - oRoute_daemon.py → /usr/local/bin/oRoute_daemon
- Sets executable permissions on both.
- Optionally offers to delete the project directory afterward.

This is a very simple convenience script intended for quick local installs. It uses sudo cp/chmod and will ask for your password.


## Installation

Prerequisites:
- Python 3.9+ on both client and server hosts
- The server host must be reachable via Tailscale initially
- Port 9800/TCP open from the client to the server for the daemon
- Utilities used by the daemon: ifconfig, grep, awk (present on most Unix-like systems)

Options:

A) Quick local install using installer.py
- Clone or download this repository on the machine where you want the tools.
- Run: python3 installer.py
- Confirm the prompts; the scripts will be copied to /usr/local/bin as oRoute and oRoute_daemon.

B) Manual install
- Copy oRoute.py to your PATH as oRoute and make it executable (chmod +x).
- Copy oRoute_daemon.py to your PATH as oRoute_daemon and make it executable.


## Running the daemon
- Foreground: oRoute_daemon
- Detached via GNU screen: oRoute_daemon --screen
  This starts a detached screen session named "oRoute_daemon".

By default it listens on 0.0.0.0:9800 so that the client can reach it from your LAN and via Tailscale.


## Usage examples

### Saved hosts and aliases (SavedHostLayer)

- Storage file: ~/.cache/oRoute.json
- It stores two maps:
  - hosts: username -> Tailscale address
  - aliases: alias -> {"user": username, "address": Tailscale address}
- Aliases provide anti-collision on usernames: multiple aliases can target the same username but different addresses.
- Backward compatibility: older files with aliases as alias -> username still work; those aliases will resolve via the saved host mapping.
- It auto-saves whenever you invoke ssh using user@<tailscale>.

Examples:
- First time, save by connecting once with explicit user@tailscale:
  - oRoute kali@100.64.0.10  # saves {"kali": "100.64.0.10"}
- Later, connect using just the username (or an alias):
  - oRoute kali               # resolves to kali@100.64.0.10
- Create aliases that disambiguate the same username:
  - oRoute --saved-host-cli   # then add alias "pi1" -> pi@100.64.0.21; alias "pi2" -> pi@100.64.0.22
  - Now `oRoute pi1` and `oRoute pi2` resolve to pi@... with their respective addresses.
- Manage entries interactively:
  - oRoute --saved-host-cli
- Quick view of saved hosts and aliases:
  - oRoute --list-saved-hosts

Help:
- oRoute --service help

Search for servers on the LAN:
- oRoute --service search

Resolve and print JSON only (no command execution):
- oRoute <tailscale-host-or-ip> --service resolve

SSH with fast-path:
- oRoute <tailscale-host-or-ip>  # behaves like optimized ssh launcher

Rsync over SSH (replace host when fast path is available):
- oRoute <tailscale-host-or-ip> --service rsync --src ./local/dir \
  --dst user@<tailscale-host-or-ip>:/remote/dir

Rsync daemon URL, explicit host:
- oRoute <tailscale-host-or-ip> --service rsync \
  --src rsync://<tailscale-host-or-ip>/module/path \
  --dst ./local/dir

Rsync daemon URL, shorthand (host injected automatically):
- oRoute 100.65.205.20 -s rsync --src . --dst rsync:///Argus
  The client injects the provided host into the rsync:/// URL and, if it finds a verified local IP, swaps it in for faster transfer.

Add custom rsync args:
- --rsync-args "-av --exclude='.venv' --progress --stats"  # defaults as shown in help


## Security and safety notes
- The daemon exposes minimal information (local IPs and a random UUID). It does not execute arbitrary commands.
- The client only switches to a local IP if the UUID matches on both the Tailscale path and the local IP path, mitigating misrouting.
- You should still restrict access to TCP/9800 to trusted networks or hosts when possible.


## Project metadata
- pyproject.toml: Project/package metadata and dependencies (if any).
- version_bumb.py and version_hash.txt: Simple versioning helpers used in this repository.


## Troubleshooting
- Client cannot connect to daemon: Ensure oRoute_daemon is running on the target and that TCP/9800 is reachable (firewall rules, container/network namespaces, etc.).
- Daemon cannot find ifconfig: On some systems, ifconfig may not be present or live at a non-standard path. oRoute_daemon searches common locations and will raise an error if not found. Install net-tools or provide an equivalent.
- No fast path selected even on the same LAN: The daemon might report multiple addresses; only those that can be probed and return the same UUID will be considered valid.


## License
This project is distributed as-is; see repository history or add a LICENSE file as appropriate for your use case.


## Supported paths and interfaces (beyond Tailscale)

Because oRoute bases its decision purely on IP reachability plus a UUID match to prove it’s the same host, it can leverage many link types that Tailscale does not optimize for or cannot use directly. If the target exposes an IP on any interface and the client can reach TCP/9800 there, oRoute can discover and use that path.

Tested/known-good examples:
- USB-SSH / USB networking (RNDIS/ECM, USB‑Ethernet dongles) — Tailscale typically cannot use this path; oRoute can if an IP is assigned.  
- VM networks (host‑only, NAT, bridged vmnet/vboxnet/virbr0) — oRoute can prefer the VM’s LAN IP if reachable locally.  
- Direct Ethernet/Wi‑Fi on the same LAN/VLAN — common fast path.  
- Phone USB tethering/hotspot adapters that present a local IPv4 subnet.  
- Ad‑hoc/peer‑to‑peer links that assign IPv4 addresses.  

Other likely‑supported scenarios (depends on your system’s routing/firewall):
- Docker/macvlan/bridge subnets when the host and target are mutually reachable on those networks.  
- Point‑to‑point adapters (tun/tap) aside from Tailscale, if they present a routable IPv4 and allow TCP/9800.  

What is not supported or has caveats:
- IPv6 only: current implementation probes IPv4 addresses parsed from ifconfig output.  
- Interfaces with no IP or blocked TCP/9800: discovery/verification will fail.  
- Networks that NAT or firewall connections back to the same host in ways that change the TCP path may cause the UUID check to fail (by design, to avoid misrouting).  
- If the daemon advertises its Tailscale IP among local IPs, the client will still verify via UUID and may consider it a match, but you won’t gain a faster path; prefer a real LAN/USB/VM IP for benefit.  


## How fast‑path selection works relative to interfaces

- The daemon returns all non‑loopback IPv4s it finds from ifconfig on the target (e.g., eth0, wlan0, en*, vmnet*, vboxnet*, virbr0, bridges, USB adapters, etc.).  
- The client connects to the target via the Tailscale address you provided, reads the server UUID, then attempts to re‑connect on each advertised local IPv4.  
- The first IP that returns the same UUID is considered a verified fast path and is used for your ssh/rsync command.  
- If none verify, oRoute falls back to the original Tailscale path.  

Notes:
- Ordering of IPs depends on ifconfig output; you can influence it by disabling unwanted interfaces on the server side if necessary.  
- Only verified matches (UUID equality) are accepted, preventing accidental routing to a different host that shares an IP range.  


## What `-s search` scans

The search service enumerates your local IPv4 addresses and naively scans the /24 for each one to find oRoute daemons:
- Interface discovery: runs ifconfig locally, collects all non‑127.0.0.1 IPv4s.  
- For each IP x.y.z.w, it scans x.y.z.1–254 on TCP/9800 with a short timeout (0.5s) using threads.  
- When it finds a daemon, it prints the found IP, the server’s UUID, and the server’s own advertised local IPs.  
- It labels a potential mismatch if the probed IP is not among the daemon’s reported local IPs (useful for spotting NAT/proxy oddities).  

Implications:
- It will search across interfaces like Wi‑Fi, Ethernet, USB adapters, VM host‑only/bridged networks, etc., as long as those adapters have an IPv4 address.  
- It does not scan IPv6 and assumes /24; customized/non‑/24 subnets may yield incomplete coverage.  
- Scanning very large or slow networks can take time; consider running the daemon on expected targets to return results quickly.  

Tips:
- If you know the host’s Tailscale address already, prefer `--service resolve` for a quick yes/no on fast path rather than scanning entire subnets.  
- Ensure local firewalls allow inbound TCP/9800 to the daemon for discovery and verification.
