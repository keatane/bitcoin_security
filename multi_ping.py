import time
import socket
import random
import hashlib
import logging
import threading
from typing import List
from dataclasses import dataclass, field

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')

# --- Constants ---
MAGICS = {
    'main': b'\xf9\xbe\xb4\xd9',
    'test': b'\x0b\x11\x09\x07',
}
DEFAULT_PORTS = {
    'main': 8333,
    'test': 18333,
}


# --- Helper Functions ---
def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def decode_int(s, nbytes, encoding='little') -> int:
    return int.from_bytes(s.read(nbytes), encoding)


def encode_int(i, nbytes, encoding='little') -> bytes:
    return i.to_bytes(nbytes, encoding)


def decode_varint(s) -> int:
    prefix = decode_int(s, 1)
    if prefix == 0xfd:
        return decode_int(s, 2)
    elif prefix == 0xfe:
        return decode_int(s, 4)
    elif prefix == 0xff:
        return decode_int(s, 8)
    return prefix


def encode_varint(i: int) -> bytes:
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + encode_int(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + encode_int(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + encode_int(i, 8)
    raise ValueError(f"Integer too large: {i}")


def generate_public_ipv4(n: int) -> List['NetAddrStruct']:
    addresses = set()
    while len(addresses) < n:
        ip = f"150.145.22.{random.randint(1, 254)}"
        addresses.add(ip)

    logging.debug(f"Generated IPs: {addresses}")
    return [NetAddrStruct(services=1, ip=socket.inet_aton(ip), port=8333) for ip in addresses]


# --- Data Structures ---
@dataclass
class NetAddrStruct:
    services: int = 0
    ip: bytes = b'\x00\x00\x00\x00'
    port: int = 8333

    def encode(self) -> bytes:
        return (
            self.services.to_bytes(8, 'little') +
            b'\x00' * 10 + b'\xff\xff' + self.ip +
            self.port.to_bytes(2, 'big')
        )


@dataclass
class NetworkEnvelope:
    command: bytes
    payload: bytes
    net: str

    def __repr__(self):
        return f"[NetworkEnvelope] Command: {self.command.decode()}, Payload: {self.payload.hex()}"

    @classmethod
    def decode(cls, s, net: str) -> 'NetworkEnvelope':
        magic = s.read(4)
        assert magic != b'', "Connection reset: no magic bytes"
        assert magic == MAGICS[net], f"Invalid magic {magic.hex()}"
        command = s.read(12).strip(b'\x00')
        payload_length = decode_int(s, 4)
        checksum = s.read(4)
        payload = s.read(payload_length)
        assert checksum == double_sha256(payload)[:4], "Invalid checksum"
        return cls(command, payload, net)

    def encode(self) -> bytes:
        return (
            MAGICS[self.net] +
            self.command.ljust(12, b'\x00') +
            len(self.payload).to_bytes(4, 'little') +
            double_sha256(self.payload)[:4] +
            self.payload
        )


@dataclass
class AddrMessage:
    addresses: List[NetAddrStruct]
    command: bytes = field(init=False, default=b'addr')

    def encode(self) -> bytes:
        payload = encode_varint(len(self.addresses))
        timestamp = int(time.time())
        for addr in self.addresses:
            payload += timestamp.to_bytes(4, 'little') + addr.encode()
        return payload


@dataclass
class VersionMessage:
    version: int = 70015
    services: int = 0
    timestamp: int = field(default_factory=lambda: int(time.time()))
    receiver: NetAddrStruct = field(default_factory=NetAddrStruct)
    sender: NetAddrStruct = field(default_factory=NetAddrStruct)
    nonce: bytes = b'\x00' * 8
    user_agent: bytes = b'/programmingbitcoin:0.1/'
    latest_block: int = 0
    relay: bool = False
    command: bytes = field(init=False, default=b'version')

    def encode(self) -> bytes:
        return b''.join([
            self.version.to_bytes(4, 'little'),
            self.services.to_bytes(8, 'little'),
            self.timestamp.to_bytes(8, 'little'),
            self.receiver.encode(),
            self.sender.encode(),
            self.nonce,
            encode_varint(len(self.user_agent)) + self.user_agent,
            self.latest_block.to_bytes(4, 'little'),
            b'\x01' if self.relay else b'\x00',
        ])


@dataclass
class VerAckMessage:
    command: bytes = field(init=False, default=b'verack')

    def encode(self) -> bytes:
        return b''


@dataclass
class PingMessage:
    nonce: bytes
    command: bytes = field(init=False, default=b'ping')

    def encode(self) -> bytes:
        return self.nonce


@dataclass
class PongMessage:
    nonce: bytes
    command: bytes = field(init=False, default=b'pong')

    def encode(self) -> bytes:
        return self.nonce
    

@dataclass
class GetHeadersMessage:
    version: int = 70015
    locator_hashes: List[bytes] = field(default_factory=list)
    stop_hash: bytes = b'\x00' * 32
    command: bytes = field(init=False, default=b'getheaders')

    def encode(self) -> bytes:
        result = self.version.to_bytes(4, 'little')
        result += encode_varint(len(self.locator_hashes))
        for h in self.locator_hashes:
            result += h
        result += self.stop_hash
        return result

    

@dataclass
class GetBlocksMessage:
    command: bytes = field(init=False, default=b'getblocks')

    def encode(self) -> bytes:
        return b''


# --- Node Class ---
@dataclass
class CustomNode:
    host: str
    net: str
    verbose: int = 0
    wait_time: int = 5
    last_ping_time: float = None

    def __post_init__(self):
        self.reconnect()

    def log(self, message: str):
        if self.verbose:
            logging.info(message)

    def reconnect(self):
        while True:
            try:
                if hasattr(self, 'socket'):
                    self.socket.close()
                resolved_ip = socket.gethostbyname(self.host)
                port = DEFAULT_PORTS[self.net]
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((resolved_ip, port))
                self.stream = self.socket.makefile('rb', None)
                self.log(f"Connected to {resolved_ip}:{port}")
                break
            except Exception as e:
                self.log(f"Reconnect failed: {e}")
                # time.sleep(1)
                break

    def send(self, message):
        envelope = NetworkEnvelope(message.command, message.encode(), net=self.net)
        self.log(f"Sending: {envelope}")
        self.socket.sendall(envelope.encode())

    def listen_message(self):
        self.send(VersionMessage())
        index = 1
        while True:
            try:
                envelope = NetworkEnvelope.decode(self.stream, net=self.net)
                command = envelope.command
                self.log(f"[{index}] Received: {command.decode()}")
                index += 1

                if command == b'version':
                    self.send(VerAckMessage())
                elif command == b'verack':
                    self.log("Handshake complete.")
                elif command == b'ping': # it comes approximately every 2 minutes
                    if self.last_ping_time:
                        delta = time.time() - self.last_ping_time
                        self.log(f"Time since last ping: {delta:.2f} sec")
                    # time.sleep(60 * 18)
                    self.send(PongMessage(envelope.payload))
                    self.last_ping_time = time.time()
                    
                    self.log("<-- Sending getheaders")
                    genesis_hash = bytes.fromhex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")[::-1]
                    self.send(GetHeadersMessage(locator_hashes=[genesis_hash]))
                elif command == b'inv':
                    self.log("--> inv received")
                elif command == b'headers':
                    self.log("--> headers received")
                time.sleep(self.wait_time)
            except Exception as e:
                self.log(f"Error: {e}")
                break
                # self.log(f"Error: {e}. Reconnecting...")
                # self.reconnect()

# Function to initialize and run each client in a separate thread
def send_request_in_thread(host, net, verbose):
    node = CustomNode(host=host, net=net, verbose=verbose)
    node.listen_message()

# Main function to create multiple request threads
def start_multiple_requests(num_requests, host, net='main', verbose=1):
    threads = []
    
    for i in range(num_requests):
        # Create a new thread for each request
        thread = threading.Thread(target=send_request_in_thread, args=(host, net, verbose))
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to complete
    print("Waiting for threads to finish...")
    for thread in threads:
        thread.join()

# Specify the host and number of requests directly here
if __name__ == "__main__":
    host = '10.20.80.131'  # Specify the desired host
    num_requests = 114     # Specify the desired number of connections
    start_multiple_requests(num_requests=num_requests, host=host)
