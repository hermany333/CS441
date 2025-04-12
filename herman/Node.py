from dhparams import shared_dh_parameters
import os
import random
import socket
import time
import selectors
import sys
import pickle
import binascii
import base64
from network import Frame, IPpacket, TCPHeader
from typing import cast
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.dh import DHPublicKey
from cryptography.hazmat.primitives import serialization

# config
LISTENING_IP = "127.0.0.1"
PROTO_TLS = 2
PROTO_SECURE = 3

class Node:
    def __init__(self, ip, mac_addr, listening_port, arp_table={}, targets=[], sniff=False):
        self.ip = ip
        self.mac_addr = mac_addr
        self.listening_port = listening_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((LISTENING_IP, self.listening_port))
        self.sock.setblocking(False)
        self.sel = selectors.DefaultSelector()

        self.sel.register(self.sock, selectors.EVENT_READ, self.handle_network_event)
        self.sel.register(sys.stdin, selectors.EVENT_READ, self.handle_input_event)
        self.arp_table = arp_table
        self.targets = targets
        self.firewall = {}
        self.sniff = sniff

        # TLS parameters 
        self.dh_parameters = shared_dh_parameters
        self.ephemeral_keys = {}
        self.shared_keys = {}
        self.handshake_in_progress = set() 


    def send_frame(self, rcving_node_ip, msg, hc_port, is_reply=False):
        if is_reply:
            packet = IPpacket(self.ip, rcving_node_ip, 0, msg, is_reply=True)
        else:
            packet = IPpacket(self.ip, rcving_node_ip, 0, msg)

        frame = Frame(self.mac_addr, self.arp_table[rcving_node_ip], packet)
        self.sock.sendto(pickle.dumps(frame), ("127.0.0.1", hc_port))

    def handle_incoming_frame(self, frame: Frame):

        if self.sniff:
            if frame.dst_mac != self.mac_addr:
                print(f"[{self.mac_addr}] Sniffing: ")
                self.print_frame(frame)
                return
            
        elif frame.dst_mac != self.mac_addr:
            print(f"[{self.mac_addr}] Dropping Frame")
            print("Dropping frame")
            self.print_frame(frame)
            return

        if frame.packet.src in self.firewall:
            print(f"[{self.mac_addr}] Dropping frame from {frame.packet.src} due to firewall")
            return

        if frame.packet.protocol == PROTO_TLS:
            self.handle_tls_hello(frame.packet)
            return

        if frame.packet.protocol == PROTO_SECURE:
            self.handle_encrypted_message(frame.packet)
            return

        print(f"[{self.mac_addr}] Received:")
        self.print_frame(frame)

        if frame.packet.is_reply:
            return

        print(f"[{self.mac_addr}] Replying to ping from {frame.src_mac}...\n")
        for target in self.targets:
            self.send_frame(frame.packet.src, frame.packet.data, target, is_reply=True)

    def ping(self, cmd: str):
        rcving_node_ip = int(cmd.split()[1], 16)
        msg = cmd.split()[2]
        count = int(cmd.split()[3])

        for _ in range(count):
            if rcving_node_ip in self.arp_table:
                for target in self.targets:
                    self.send_frame(rcving_node_ip, msg, target)
                time.sleep(1)
            else:
                print("Receiving node does not exist")
                break

    @staticmethod
    def print_frame(frame: Frame):
        print(
            f"frame: {frame.data_length} bytes from {frame.src_mac} → {frame.dst_mac} | "
            f"packet: {frame.packet.data_length} bytes from {hex(frame.packet.src)} → {hex(frame.packet.dest)} - "
            f"protocol = {frame.packet.protocol}\n"
        )

    def print_menu(self, opts=None):
        print("\n[-- What would you like to do? --]")
        print("Type 'exit' to quit.")
        print("Nodes: N1 0x1A, N2 0x2A, N3 0x2B")
        print("Router: R1 0x11, R2 0x21")
        print("To ping, type: ping <Destination IP> <Message> <Count>")
        print("Example: 'ping 0x2B Hello 5' (sends 5 'Hello's to Node3)")
        print("block [ip] to block a specific ip")
        print("To establish TLS handshake: tls <Destination IP>")
        print("To securely communicate with another Node: sc <Destination IP> \"<String>\"")
        if opts:
            for opt in opts:
                opt()
        print("-------------------------------------------")

    def handle_network_event(self):
        data, _ = self.sock.recvfrom(1024)
        frame = cast(Frame, pickle.loads(data))
        self.handle_incoming_frame(frame)

    def handle_input_event(self):
        cmd = sys.stdin.readline().strip()
        self.process_input_command(cmd)

    def process_input_command(self, cmd: str):

        if len(cmd) == 0:
            return

        if cmd.split()[0] == "ping":
            self.ping(cmd)

        if cmd.split()[0] == "block" or cmd.split()[0] == "unblock":
            self.toggle_firewall(cmd)

        if cmd.split()[0] == "firewall":
            self.view_firewall()

        if cmd.split()[0] == "tls":
            self.initiate_tls(cmd)

        if cmd.split()[0] == "sc":
          # cmd = sc 0x2B "hello friend"
          _, hex_ip, message = cmd.split(" ", 2)
          dest_ip = int(hex_ip, 16)
          for target in self.targets:
              self.send_encrypted_message(dest_ip, message, target)

    def send_encrypted_message(self, dest_ip, message, hc_port):

        if dest_ip not in self.shared_keys:
            print(f"[{self.mac_addr}] No shared key with {hex(dest_ip)}")
            return

        key = self.shared_keys[dest_ip]
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)

        ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
        combined = nonce + ciphertext
        encoded_payload = base64.b64encode(combined).decode()

        tcp_segment = TCPHeader(
            src_port=random.randint(49152, 65535),
            dst_port=443,
            payload=encoded_payload
        )

        packet = IPpacket(self.ip, dest_ip, PROTO_SECURE, tcp_segment)
        frame = Frame(self.mac_addr, self.arp_table[dest_ip], packet)
        self.sock.sendto(pickle.dumps(frame), (LISTENING_IP, hc_port))
        print(f"[{self.mac_addr}] Sent encrypted message to {hex(dest_ip)}")

    def handle_encrypted_message(self, packet: IPpacket):
        if not isinstance(packet.data, TCPHeader):
            print("Invalid secure packet structure.")
            return

        print(f"[{self.mac_addr}] Received encrypted message from {hex(packet.src)}")
        print(f"[{self.mac_addr}] Handling encrypted message from {hex(packet.src)}")

        if packet.src not in self.shared_keys:
            print(f"[{self.mac_addr}] No shared key with {hex(packet.src)} — cannot decrypt.")
            return

        try:
            key = self.shared_keys[packet.src]
            aesgcm = AESGCM(key)

            encrypted_bytes = base64.b64decode(packet.data.payload.encode())
            nonce = encrypted_bytes[:12]
            ciphertext = encrypted_bytes[12:]

            plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode()
            print(f"[{self.mac_addr}] Decrypted message from {hex(packet.src)}: {plaintext}")

        except Exception as e:
            print(f"[{self.mac_addr}] Decryption failed: {e}")


    def toggle_firewall(self, cmd: str):

        command = cmd.lower().split()[0]
        ipAddr = cmd.split()[1]

        base16Addr = int(ipAddr, 16)

        if command == "block":
            self.firewall[base16Addr] = ipAddr
            print(f"Blocking {ipAddr}")
        else:
            if base16Addr in self.firewall:
                del self.firewall[base16Addr]
                print(f"Unblocking {ipAddr}")

    def view_firewall(self):
        print("Firewall:")
        for _,v in enumerate(self.firewall):
            print(v)

    def toggleSpoof(self, spoof_ip):
        if self.spoof_ip != 0:
            self.spoof_ip = 0
        else:
            self.spoof_ip = int(spoof_ip, 16)

    def process_event(self, key):
        callback = key.data
        callback()

    def initiate_tls(self, cmd):
        dest_ip = int(cmd.split()[1], 16)
        # Generate private key
        private_key = self.dh_parameters.generate_private_key()
        public_key = private_key.public_key()
        self.ephemeral_keys[dest_ip] = private_key # Store it in a dictionary
        self.handshake_in_progress.add(dest_ip)

        print(f"[{self.mac_addr}] Sent TLS Hello")
        for target in self.targets:
            self.send_tls_hello(dest_ip, target, public_key)

    def send_tls_hello(self, dest_ip, hc_port, public_key):
        # Generate public key
        pubkey_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        tcp_segment = TCPHeader(
            src_port=random.randint(49152, 65535),
            dst_port=443,
            payload=pubkey_bytes.decode(),
        )

        # Flood public key
        packet = IPpacket(self.ip, dest_ip, PROTO_TLS, data=tcp_segment)
        frame = Frame(self.mac_addr, self.arp_table[dest_ip], packet)
        self.sock.sendto(pickle.dumps(frame), (LISTENING_IP, hc_port))  

    def handle_tls_hello(self, packet: IPpacket):
        if not isinstance(packet.data, TCPHeader):
            print("Invalid TLS packet structure.")
            return
        
        print(f"Handling TLS from {hex(packet.src)}")
        if packet.src in self.handshake_in_progress:
            # Received a TLS Hello response — I initiated this handshake.
            private_key = self.ephemeral_keys[packet.src]
            shared_key = self.derive_tls_shared_key(packet, private_key);
        else:
            # Received a TLS Hello initiation — I'm the responder.
            private_key = self.dh_parameters.generate_private_key()
            public_key = private_key.public_key()
            self.ephemeral_keys[packet.src] = private_key # Store it in a dictionary
            self.handshake_in_progress.add(packet.src)

            for target in self.targets:
                self.send_tls_hello(packet.src, target, public_key)
            
            shared_key = self.derive_tls_shared_key(packet, private_key);
        
        if shared_key:
            self.shared_keys[packet.src] = shared_key
            self.handshake_in_progress.discard(packet.src)

    def derive_tls_shared_key(self, packet, private_key):
        try:
            peer_pubkey = serialization.load_pem_public_key(
                    packet.data.payload.encode(),
                    backend=default_backend()
            )

            if not isinstance(peer_pubkey, DHPublicKey):
                    print("Received key is not a valid Diffie-Hellman public key.")
                    return None

            shared_key = private_key.exchange(peer_pubkey)

            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'tls-handshake',
                backend=default_backend()
            ).derive(shared_key)

            print(f"Established shared TLS key with {hex(packet.src)}")
            print(f"Derived key: {binascii.hexlify(derived_key).decode()}")

            return derived_key

        except Exception as e:
            print(f"Error during TLS key derivation: {e}")
            return None

    def run(self):
        self.print_menu()
        try:
            while True:
                events = self.sel.select(timeout=None)
                for key, _ in events:
                    self.process_event(key)

        except KeyboardInterrupt:
            print("\nCaught keyboard interrupt, exiting.")
        finally:
            self.sel.close()
