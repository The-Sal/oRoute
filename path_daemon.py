"""
OSSH - Optimised SSH. Automatic routing from tailscale to local network if available.
"""
import os
import json
import uuid
from utils3.networking.sockets import Server


class FastPathServer:
    def __init__(self, host='0.0.0.0', port=9800):
        self.server = Server(host=host, port=port, on_recv=self.on_recv, on_disconnect=self.on_disconnect)
        self.local_ip = self.get_local_ip()
        self.server_id = uuid.uuid4().__str__()

    @staticmethod
    def on_disconnect(client, address):
        print(f"Client {address} disconnected")
        _ = client

    def on_recv(self, client, address, data):
        print(f"Received data from {address}: {data}")
        if data == b'GET_LOCAL_IP':
            client.sendall(json.dumps(self.local_ip).encode('utf-8'))
            client.close()
        elif data == b'GET_SERVER_ID':
            client.sendall(self.server_id.encode('utf-8'))
            client.close()
        else:
            client.sendall(b'INVALID_REQUEST')
            client.close()


    @staticmethod
    def get_local_ip() -> list[str]:
        """Get the local IP address of the server."""
        os.system("""ifconfig | grep -E "([0-9]{1,3}\\.){3}[0-9]{1,3}" | grep -v 127.0.0.1 | awk '{ print $2 }' | cut -f2 -d: > local_ip.txt""")
        with open("local_ip.txt", "r") as f:
            ips = f.read().splitlines()
        return ips



if __name__ == '__main__':
    server = FastPathServer()
    server.server.start()

