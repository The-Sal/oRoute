#!/usr/bin/env python3
"""
oRoute - Optimised Routing Client. Automatic routing from tailscale to local network if available.
Supports SSH for now.

Because sometimes Tailscale routing is not the fastest i.e. USB-SSH, VMs, etc... etc... and you
just need shit to work
"""

CLIENT_VERSION = 2.9

import os
import sys
import json
import socket
import argparse
from tqdm import tqdm
from utils3 import runAsThread



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
            # Try to parse JSON if it’s IP list
            return json.loads(decoded)
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
    print('  resolve - Output JSON with tailscale/local addresses, reachability, and server UUID')
    print('  update     - Update oRoute to the latest version from GitHub')
    print('  help       - Show this help message')
    print("\nrsync usage examples:")
    print("  oRoute.py <tailscale-host> --service rsync --src ./local/dir --dst user@<tailscale-host>:/remote/dir")
    print("  oRoute.py <tailscale-host> --service rsync --src rsync://<tailscale-host>/module/path --dst ./local/dir")
    print("  You can omit the host in rsync daemon URLs using rsync:///module/path. oRoute will inject the <tailscale-host>\n    and, if a local IP fast path is found, it will inject the discovered local IP instead.")
    print("  Example: oRoute.py 100.65.205.20 -s rsync --src . --dst rsync:///Argus")
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
    parser.add_argument('host', type=str, help='The Tailscale IP address of the server')
    parser.add_argument('--port', type=int, default=9800, help='The port number of the server (default: 9800)')
    parser.add_argument('-s', '--service', default='ssh', type=str,
                        help='The service to use the fastest path for (default: ssh) use -s help for more info',)
    # rsync specific args
    parser.add_argument('--src', type=str, help="rsync source path (local or remote). For rsync daemon URLs you can omit the host using rsync:///module/path; oRoute will inject the <host> you pass as the first argument (or a discovered local IP).")
    parser.add_argument('--dst', type=str, help="rsync destination path (local or remote). For rsync daemon URLs you can omit the host using rsync:///module/path; oRoute will inject the <host> you pass as the first argument (or a discovered local IP).")
    parser.add_argument('--rsync-args', dest='rsync_args', type=str,
                        default="-av --exclude='.venv' --progress --stats",
                        help="Arguments to pass to rsync. Default: -av --exclude='.venv' --progress --stats")

    args = parser.parse_args()
    if args.service == 'ssh':
        user, hostname = parse_ssh(args.host)
        local_ip = check_for_local_connection(hostname, args.port)
        if local_ip:
            print('Directly connecting via local IP...')
            os.system(f'ssh {user}@{local_ip}')
        else:
            print(f'Connecting via Tailscale IP {hostname}...')
            os.system(f'ssh {args.host}')
    elif args.service == 'rsync':
        if not args.src or not args.dst:
            print('Error: --src and --dst are required for rsync service.')
            sys.exit(2)
        # Determine if a local fast path is available
        _, hostname = parse_ssh(args.host)
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
        _, hostname = parse_ssh(args.host)
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