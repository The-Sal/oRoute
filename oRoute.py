#!/usr/bin/env python3
"""
oRoute - Optimised Routing Client. Automatic routing from tailscale to local network if available.
Supports SSH for now.

Because sometimes Tailscale routing is not the fastest i.e. USB-SSH, VMs, etc... etc... and you
just need shit to work
"""

CLIENT_VERSION = 2.7

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
    print('  ssh     - Optimised SSH connection (default)')
    print('  search  - Search for oRoute servers on the local network')

def update():
    print('Updating oRoute (suite)...')
    os.system('gh repo clone The-Sal/oRoute; {} ./oRoute/installer.py'.format(sys.executable))

def main():
    print('oRoute Client - Version:', CLIENT_VERSION)
    parser = argparse.ArgumentParser(description='oRoute Client - Automatic routing from Tailscale to local network if available.')
    parser.add_argument('host', type=str, help='The Tailscale IP address of the server')
    parser.add_argument('--port', type=int, default=9800, help='The port number of the server (default: 9800)')
    parser.add_argument('-s', '--service', default='ssh', type=str,
                        help='The service to use the fastest path for (default: ssh)')

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
    elif args.service == 'search':
        print('Searching for oRoute servers on the local network...')
        search_for_servers()
    else:
        print(f'Service {args.service} not supported yet.')


if __name__ == '__main__':
    main()