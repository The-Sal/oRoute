#!/usr/bin/env python3
"""
oRoute - Optimised Routing Client. Automatic routing from tailscale to local network if available.
Supports SSH for now.

Because sometimes Tailscale routing is not the fastest i.e. USB-SSH, VMs, etc... etc... and you
just need shit to work
"""

CLIENT_VERSION = 3.0

import os
import sys
import json
import socket
import argparse
from tqdm import tqdm
from utils3 import runAsThread


class SavedHostLayer:
    """
    Save tailscale address and their username for example kali@100.64.x.y
    - Automatically saves when you connect using user@tailscale.
    - You can connect using just the username (e.g., `oRoute kali`) and it resolves to `kali@<saved-tailscale>`.
    - Supports aliases: alias -> host -> tailscale. Aliases resolve to the host, then we build host@tailscale.

    Storage: ~/.cache/oRoute.json
    Structure example:
      {
        "hosts": {"kali": "100.64.0.10", "ubuntu": "100.85.2.3"},
        "aliases": {"vm": "kali"}
      }
    """

    DEFAULT_PATH = os.path.expanduser("~/.cache/oRoute.json")

    def __init__(self, data=None, path=None):
        self.path = path or self.DEFAULT_PATH
        data = data or {}
        self.hosts = dict(data.get('hosts', {}))  # host -> tailscale address
        self.aliases = dict(data.get('aliases', {}))  # alias -> host

    # -------- persistence --------
    @classmethod
    def load_default(cls):
        path = cls.DEFAULT_PATH
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    data = json.load(f)
            else:
                data = {"hosts": {}, "aliases": {}}
        except Exception:
            data = {"hosts": {}, "aliases": {}}
        return cls(data, path=path)

    def save(self):
        # Ensure dir exists
        d = os.path.dirname(self.path)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        with open(self.path, 'w') as f:
            json.dump({"hosts": self.hosts, "aliases": self.aliases}, f, indent=2)

    # -------- operations --------
    def list_items(self):
        return {
            'hosts': dict(self.hosts),
            'aliases': dict(self.aliases),
            'path': self.path,
        }

    def print_summary(self):
        info = self.list_items()
        print(f"SavedHostLayer file: {info['path']}")
        print('Hosts:')
        if info['hosts']:
            for h, a in info['hosts'].items():
                print(f"  {h} -> {a}")
        else:
            print('  (none)')
        print('Aliases:')
        if info['aliases']:
            for al, val in info['aliases'].items():
                # Support both new and legacy formats
                if isinstance(val, dict) and 'user' in val and 'address' in val:
                    print(f"  {al} -> {val['user']}@{val['address']}")
                else:
                    # Legacy: alias -> host (username); resolve via hosts map
                    h = str(val)
                    addr = self.hosts.get(h, '(unknown)')
                    print(f"  {al} -> {h}@{addr} (legacy)")
        else:
            print('  (none)')

    def set_host(self, host: str, address: str):
        old = self.hosts.get(host)
        self.hosts[host] = address
        self.save()
        if old and old != address:
            print(f"[oRoute] SavedHost: updated '{host}' from {old} to {address}")
        elif not old:
            print(f"[oRoute] SavedHost: added '{host}' -> {address}")

    def remove_host(self, host: str):
        if host in self.hosts:
            del self.hosts[host]
            # Do NOT remove aliases: aliases carry their own (user, address) and are independent now
            self.save()
            print(f"[oRoute] SavedHost: removed host '{host}'")
        else:
            print(f"[oRoute] SavedHost: host '{host}' not found")

    def set_alias(self, alias: str, user: str, address: str = None):
        """Create/update an alias that independently maps to (user, address).
        If address is None, will try to use saved hosts[user].
        """
        if not user:
            print(f"[oRoute] SavedHost: cannot set alias '{alias}' without a username")
            return
        if address is None:
            address = self.hosts.get(user)
            if not address:
                print(f"[oRoute] SavedHost: no address provided and no saved host for '{user}'")
                return
        prev = self.aliases.get(alias)
        self.aliases[alias] = {"user": user, "address": address}
        self.save()
        if prev and prev != self.aliases[alias]:
            # Summarize previous target
            if isinstance(prev, dict):
                prev_desc = f"{prev.get('user','?')}@{prev.get('address','?')}"
            else:
                prev_desc = f"{prev}@{self.hosts.get(str(prev), '?')}"
            print(f"[oRoute] SavedHost: alias '{alias}' retargeted {prev_desc} -> {user}@{address}")
        elif not prev:
            print(f"[oRoute] SavedHost: alias '{alias}' -> {user}@{address}")

    def set_alias_to_host(self, alias: str, host: str):
        """Convenience: point alias at an existing saved host (username)."""
        addr = self.hosts.get(host)
        if not addr:
            print(f"[oRoute] SavedHost: host '{host}' not found for alias '{alias}'")
            return
        self.set_alias(alias, host, addr)

    def remove_alias(self, alias: str):
        if alias in self.aliases:
            del self.aliases[alias]
            self.save()
            print(f"[oRoute] SavedHost: removed alias '{alias}'")
        else:
            print(f"[oRoute] SavedHost: alias '{alias}' not found")

    def resolve_name(self, name: str):
        """Resolve a name that may be a host or alias into (user, tailscale_address).
        Returns (user, address) or (None, None) if not found.
        """
        # Alias takes priority
        if name in self.aliases:
            val = self.aliases[name]
            if isinstance(val, dict) and 'user' in val and 'address' in val:
                return val['user'], val['address']
            else:
                # Legacy alias -> host (username)
                host = str(val)
                addr = self.hosts.get(host)
                if addr:
                    return host, addr
        # Direct host (username)
        if name in self.hosts:
            return name, self.hosts[name]
        return None, None

    def can_resolve(self, name: str) -> bool:
        h, a = self.resolve_name(name)
        return bool(h and a)

    def record_host(self, user: str, address: str):
        """Record mapping user -> tailscale address. If changed, notify.
        """
        if not user or not address:
            return
        old = self.hosts.get(user)
        if old != address:
            self.hosts[user] = address
            self.save()
            if old:
                print(f"[oRoute] SavedHost: '{user}' address changed {old} -> {address}")
            else:
                print(f"[oRoute] SavedHost: saved '{user}' -> {address}")

    def cli(self):
        print('SavedHostLayer CLI')
        print(f"Storage: {self.path}")
        while True:
            print('\nOptions:')
            print(' 1) List')
            print(' 2) Add/Update host')
            print(' 3) Remove host')
            print(' 4) Add/Update alias')
            print(' 5) Remove alias')
            print(' 0) Exit')
            choice = input('Select: ').strip()
            if choice == '1':
                self.print_summary()
            elif choice == '2':
                host = input(' Host (username): ').strip()
                addr = input(' Tailscale address (e.g., 100.x.y.z or name): ').strip()
                if host and addr:
                    self.set_host(host, addr)
            elif choice == '3':
                host = input(' Host to remove: ').strip()
                if host:
                    self.remove_host(host)
            elif choice == '4':
                alias = input(' Alias name: ').strip()
                user = input(' Username to use when connecting (e.g., pi): ').strip()
                addr = input(' Tailscale address for this alias (leave blank to use saved host mapping): ').strip()
                if alias and user:
                    self.set_alias(alias, user, addr or None)
            elif choice == '5':
                alias = input(' Alias to remove: ').strip()
                if alias:
                    self.remove_alias(alias)
            elif choice == '0':
                break
            else:
                print('Invalid selection.')


class FastPathClient:
    def __init__(self, host, port=9800, timeout=5):
        self.host = host
        self.port = port
        self.timeout = timeout

    def send_request(self, request_type: str):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            s.sendall(request_type.encode('utf-8'))
            response = s.recv(4096)
        try:
            decoded = response.decode('utf-8')
            listed_ips =  json.loads(decoded)
            # drop all addresses in the 100.xx.x range (tailscale)
            filtered = [ip for ip in listed_ips if not ip.startswith('100.')]
            return filtered

        except json.JSONDecodeError:
            return decoded

def check_for_local_connection(host, port=9800):
    print('Connecting via {}:{}'.format(host, port))
    try:
        client = FastPathClient(host, port)
        local_ips = client.send_request('GET_LOCAL_IP')
        server_id = client.send_request('GET_SERVER_ID')
        print(f"Local IPs: {local_ips}")
        print(f"Server ID: {server_id}")
        print('Checking for local connection...')
        for ip in local_ips:
            print(f'Trying {ip}:{port}...')
            try:
                local_client = FastPathClient(ip, port)
                local_server_id = local_client.send_request('GET_SERVER_ID')
                if local_server_id == server_id:
                    print(f'Local connection successful via {ip}:{port}')
                    return ip
            except socket.error:
                print(f'Failed to connect via {ip}:{port}')
        print('No local connection available.')

    except socket.error as e:
        print(f"Socket error: {e}")

    return False

def parse_ssh(host):
    """Parses a username@hostname string into its components."""
    if '@' in host:
        user, hostname = host.split('@', 1)
    else:
        user = os.getenv('USER')  # Default to current user
        hostname = host
    return user, hostname

def search_for_servers():
    os.system("""ifconfig | grep -E "([0-9]{1,3}\\.){3}[0-9]{1,3}" | grep -v 127.0.0.1 | awk '{ print $2 }' | cut -f2 -d: > local_ip.txt""")
    with open("local_ip.txt", "r") as f:
        ips = f.read().splitlines()
    os.remove("local_ip.txt")
    found_servers = []
    max_last_octet = 255

    @runAsThread
    def _scan_addr(ip_addr):
        try:
            client = FastPathClient(ip_addr, 9800, timeout=0.5)
            server_id = client.send_request('GET_SERVER_ID')
            server_ip = client.send_request('GET_LOCAL_IP')
            if server_id and server_id != 'INVALID_REQUEST':
                # print(f'Found oRoute server at {ip_addr} with ID {server_id}')
                found_servers.append((ip_addr, server_id, server_ip))
        except socket.error:
            found_servers.append(None)

    print(f'Scanning {len(ips)} local networks for oRoute servers...')
    print('IPs to scan:', ips)
    total_addrs_to_scan = len(ips) * (max_last_octet - 1)
    progress = tqdm(total=total_addrs_to_scan, desc='Scanning', unit='addr')
    for ip in ips:
        threads = []
        base_ip = '.'.join(ip.split('.')[:-1]) + '.'
        for i in range(1, max_last_octet):
            scan_ip = base_ip + str(i)
            threads.append(_scan_addr(scan_ip))

        for t in threads:
            t.join()
            progress.update(1)
    progress.close()

    found_servers = [s for s in found_servers if s]
    if found_servers:
        print('Found oRoute servers:')
        for server in found_servers:
            msg = f'\tIP: {server[0]}, ID: {server[1]}, Local IPs: {server[2]}'
            try:
                hostname = socket.gethostbyaddr(server[0])[0]
                msg += f', Hostname: {hostname}'
            except socket.herror:
                pass
            print(msg)
            print('\t\tTo connect via local network, use: {}'.format(server[0]))
            if server[0] not in server[2]:
                print('\t\tNote: The following server is lying about its local IP {} !=  {}'.format(server[0], server[2]))

def help_msg():
    print('oRoute Client Help')
    print('Available services:')
    print('  ssh        - Optimised SSH connection (default)')
    print('  rsync      - Optimised rsync (SSH or rsync:// daemon)')
    print('  search     - Search for oRoute servers on the local network')
    print('  resolve    - Output JSON with tailscale/local addresses, reachability, and server UUID')
    print('  update     - Update oRoute to the latest version from GitHub')
    print('  help       - Show this help message')
    print('\nSavedHostLayer (persistent saved hosts):')
    print('  Storage file: ~/.cache/oRoute.json')
    print('  Use cases:')
    print('   - Save automatically when you run: oRoute user@<tailscale> (maps user -> tailscale)')
    print('   - Connect using saved user or alias: oRoute <user-or-alias>  (resolves to user@<saved-tailscale>)')
    print('  Aliases provide anti-collision on usernames:')
    print('   - Each alias stores its own (user, tailscale) pair, independent of hosts.')
    print('   - Example: alias pi1 -> pi@100.64.0.10 and alias pi2 -> pi@100.64.0.11; both coexist.')
    print('  CLI manager:')
    print('   --saved-host-cli        Open an interactive menu to add/remove hosts and aliases')
    print('   --list-saved-hosts      Print saved hosts and aliases and exit')
    print('\nrsync usage examples:')
    print('  oRoute <tailscale-host> --service rsync --src ./local/dir --dst user@<tailscale-host>:/remote/dir')
    print('  oRoute <tailscale-host> --service rsync --src rsync://<tailscale-host>/module/path --dst ./local/dir')
    print('  You can omit the host in rsync daemon URLs using rsync:///module/path. oRoute will inject the <host>')
    print('    you pass (or a discovered local IP), then swap it for the fast local IP if available.')
    print('  Example: oRoute 100.65.205.20 -s rsync --src . --dst rsync:///Argus')
    print("  Add custom args with --rsync-args (default: -av --exclude='.venv' --progress --stats)")


def update():
    print('Updating oRoute (suite)...')
    os.system('gh repo clone The-Sal/oRoute; {} ./oRoute/installer.py'.format(sys.executable))

def _replace_host_in_rsync_endpoint(endpoint: str, original_host: str, new_host: str) -> str:
    """Replace the hostname part in an rsync endpoint with a new host.
    Supports:
      - SSH form: [user@]host:path
      - Daemon form: rsync://host[:port]/module/path
    Leaves local paths untouched.
    """
    if not endpoint:
        return endpoint

    # rsync daemon URL
    if endpoint.startswith('rsync://'):
        rest = endpoint[len('rsync://'):]  # host[:port]/...
        # Split host[:port] and remainder
        if '/' in rest:
            hostport, tail = rest.split('/', 1)
        else:
            hostport, tail = rest, ''
        # If the original host is present as hostname in hostport, replace it (preserve :port if any)
        # hostport may be host or host:port
        if hostport.startswith(original_host):
            suffix = hostport[len(original_host):]
            hostport = new_host + suffix
        else:
            # If not a simple startswith, try to replace hostname before optional :port precisely
            parts = hostport.split(':', 1)
            if parts[0] == original_host:
                hostport = new_host + (':' + parts[1] if len(parts) == 2 else '')
        return 'rsync://' + hostport + ('/' + tail if tail else '')

    # SSH-like remote path [user@]host:path (note: beware Windows paths with colon, but assume POSIX)
    if ':' in endpoint and not endpoint.startswith('/'):
        left, right = endpoint.split(':', 1)
        # left can be host or user@host
        if '@' in left:
            user, host = left.rsplit('@', 1)
            if host == original_host:
                left = f"{user}@{new_host}"
        else:
            if left == original_host:
                left = new_host
        return f"{left}:{right}"

    # Local path, return as-is
    return endpoint


def _inject_host_if_missing_in_rsync_endpoint(endpoint: str, host: str) -> str:
    """If endpoint is an rsync daemon URL missing host (rsync:///...), inject the given host.
    Otherwise return endpoint unchanged.
    """
    if not endpoint:
        return endpoint
    prefix = 'rsync:///'
    if endpoint.startswith(prefix):
        tail = endpoint[len(prefix):]
        return f"rsync://{host}/{tail}"
    return endpoint


def resolve_connectivity(hostname: str, port: int = 9800, timeout: float = 5.0) -> dict:
    """Return a JSON-serializable dict describing connectivity resolve.
    Fields:
      - tailscale_address: the provided Tailscale address/hostname
      - local_address: discovered reachable local IP if any, else None
      - reachable: True if a local address was verified reachable (server UUID match)
      - server_uuid: UUID reported by the server (or None if unreachable)
    This function is quiet (no prints) and performs minimal probing.
    """
    server_uuid = None
    local_address = None
    reachable = False
    try:
        client = FastPathClient(hostname, port, timeout=timeout)
        local_ips = client.send_request('GET_LOCAL_IP')

        # remove the tailscale address from local_ips if present
        if hostname in local_ips:
            local_ips.remove(hostname)

        server_uuid = client.send_request('GET_SERVER_ID')
        # Ensure local_ips is iterable
        if isinstance(local_ips, (list, tuple)):
            for ip in local_ips:
                try:
                    lc = FastPathClient(ip, port, timeout=timeout)
                    sid = lc.send_request('GET_SERVER_ID')
                    if sid == server_uuid:
                        local_address = ip
                        reachable = True
                        break
                except socket.error:
                    continue
    except socket.error:
        # Could not reach tailscale host; keep defaults
        pass
    return {
        'tailscale_address': hostname,
        'local_address': local_address,
        'reachable': reachable,
        'server_uuid': server_uuid,
    }


def main():
    parser = argparse.ArgumentParser(description='oRoute Client - Automatic routing from Tailscale to local network if available.')
    parser.add_argument('host', type=str, nargs='?', help='Tailscale host/IP (or saved username / alias). For SSH you can also pass user@tailscale to auto-save this mapping.')
    parser.add_argument('--port', type=int, default=9800, help='The port number of the server (default: 9800)')
    parser.add_argument('-s', '--service', default='ssh', type=str,
                        help='The service to use the fastest path for (default: ssh). Use --service help for more info.')
    # SavedHostLayer helpers
    parser.add_argument('--saved-host-cli', action='store_true', help='Open the Saved Host interactive manager (add/remove hosts and aliases).')
    parser.add_argument('--list-saved-hosts', action='store_true', help='List saved hosts and aliases and exit.')
    # rsync specific args
    parser.add_argument('--src', type=str, help="rsync source path (local or remote). For rsync daemon URLs you can omit the host using rsync:///module/path; oRoute will inject the <host> you pass as the first argument (or a discovered local IP).")
    parser.add_argument('--dst', type=str, help="rsync destination path (local or remote). For rsync daemon URLs you can omit the host using rsync:///module/path; oRoute will inject the <host> you pass as the first argument (or a discovered local IP).")
    parser.add_argument('--rsync-args', dest='rsync_args', type=str,
                        default="-av --exclude='.venv' --progress --stats",
                        help="Arguments to pass to rsync. Default: -av --exclude='.venv' --progress --stats")

    args = parser.parse_args()

    # SavedHostLayer integration
    sHL = SavedHostLayer.load_default()
    if args.saved_host_cli:
        sHL.cli()
        return
    if args.list_saved_hosts:
        sHL.print_summary()
        return

    # Some services don't require a host
    services_no_host = {'help', 'search', 'update', 'version'}
    if args.service not in services_no_host and not args.host:
        print('Error: host argument is required unless using --service help/search/update/version or SavedHost CLI flags.')
        sys.exit(2)

    # Resolve host argument via SavedHostLayer
    resolved_user = None
    resolved_hostname = None
    if args.host:
        if '@' in args.host:
            # user@tailscale form → record mapping and use directly
            resolved_user, resolved_hostname = parse_ssh(args.host)
            sHL.record_host(resolved_user, resolved_hostname)
        else:
            # May be a saved username or alias, else treat as given
            if sHL.can_resolve(args.host):
                base_host, addr = sHL.resolve_name(args.host)
                resolved_user = base_host  # for SSH we will use this as the username
                resolved_hostname = addr
                print(f"[oRoute] SavedHost resolved '{args.host}' -> {base_host}@{addr}")
            else:
                resolved_hostname = args.host

    if args.service == 'ssh':
        if resolved_user is None:
            user, hostname = parse_ssh(resolved_hostname)
        else:
            user, hostname = resolved_user, resolved_hostname
        local_ip = check_for_local_connection(hostname, args.port)
        if local_ip:
            print('Directly connecting via local IP...')
            os.system(f'ssh {user}@{local_ip}')
        else:
            print(f'Connecting via Tailscale IP {hostname}...')
            os.system(f'ssh {user}@{hostname}')
    elif args.service == 'rsync':
        if not args.src or not args.dst:
            print('Error: --src and --dst are required for rsync service.')
            sys.exit(2)
        # Determine if a local fast path is available
        hostname = resolved_hostname
        local_ip = check_for_local_connection(hostname, args.port)
        src = args.src
        dst = args.dst
        if local_ip:
            print(f'Using local IP for rsync: {local_ip}')
            # Inject local IP if host is omitted in rsync daemon URLs
            src = _inject_host_if_missing_in_rsync_endpoint(src, local_ip)
            dst = _inject_host_if_missing_in_rsync_endpoint(dst, local_ip)
            # If endpoints explicitly contain the Tailscale host, replace with local IP
            src = _replace_host_in_rsync_endpoint(src, hostname, local_ip)
            dst = _replace_host_in_rsync_endpoint(dst, hostname, local_ip)
        else:
            print(f'No local IP path found, using Tailscale host {hostname} for rsync')
            # Inject the provided host if omitted in rsync daemon URLs
            src = _inject_host_if_missing_in_rsync_endpoint(src, hostname)
            dst = _inject_host_if_missing_in_rsync_endpoint(dst, hostname)
        cmd = f"rsync {args.rsync_args} {src} {dst}"
        print(f'Executing: {cmd}')
        os.system(cmd)
    elif args.service == 'search':
        print('Searching for oRoute servers on the local network...')
        search_for_servers()
    elif args.service == 'resolve':
        # Output a single JSON line with resolve info
        hostname = resolved_hostname
        result = resolve_connectivity(hostname, args.port)
        print(json.dumps(result))
    elif args.service == 'help':
        help_msg()
    elif args.service == 'update':
        update()
    elif args.service == 'version':
        print(f'oRoute Client version {CLIENT_VERSION}')
    else:
        print(f'Service {args.service} not supported yet.')
        exit(2)


if __name__ == '__main__':
    main()