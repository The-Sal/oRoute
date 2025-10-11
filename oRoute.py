#!/usr/bin/env python3
"""
oRoute - Optimised Routing Client. Automatic routing from tailscale to local network if available.
Supports SSH for now.

Because sometimes Tailscale routing is not the fastest i.e. USB-SSH, VMs, etc... etc... and you
just need shit to work
"""


CLIENT_VERSION = 0.1

import os
import json
import socket
import argparse

class FastPathClient:
    def __init__(self, host, port=9800):
        self.host = host
        self.port = port

    def send_request(self, request_type: str):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
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
            os.system(f'ssh {user}@{hostname}')
    else:
        print(f'Service {args.service} not supported yet.')


if __name__ == '__main__':
    main()