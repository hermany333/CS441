from dhparams import shared_dh_parameters
import os
import random
import socket
import time
import selectors
import sys
import pickle
import binascii
import random
import re 
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
PROTO_COVERT = 0xCC  # Special protocol for covert channel
COVERT_METHOD_TIMING = "timing"
COVERT_METHOD_STEG = "steg"

PROTO_SECURE = 3

class Node:
    def __init__(self, ip, mac_addr, listening_port, arp_table={}, targets=[]):
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

        # TLS parameters 
        self.dh_parameters = shared_dh_parameters
        self.ephemeral_keys = {}
        self.shared_keys = {}
        self.handshake_in_progress = set()
        
        # Covert channel parameters
        self.covert_channel_active = False
        self.covert_message = ""
        self.covert_bits_sent = 0
        self.covert_target = None
        self.receiving_covert_channel = False
        self.covert_received_bits = ""
        self.last_packet_time = None
        self.recovered_messages = []
        
        # Defense features (available to all nodes)
        self.firewall = {}
        self.sniff_mode = False

    def send_frame(self, rcving_node_ip, msg, hc_port, is_reply=False, protocol=0):
        if is_reply:
            packet = IPpacket(self.ip, rcving_node_ip, protocol, msg, is_reply=True)
        else:
            packet = IPpacket(self.ip, rcving_node_ip, protocol, msg)

        frame = Frame(self.mac_addr, self.arp_table[rcving_node_ip], packet)
        self.sock.sendto(pickle.dumps(frame), ("127.0.0.1", hc_port))

    def handle_incoming_frame(self, frame: Frame):
        if self.sniff_mode:
            if frame.dst_mac != self.mac_addr:
                print(f"[{self.mac_addr}] Sniffing: ")
                self.print_frame(frame)
            else:
                print("Dropping frame")

            return
            
        if frame.dst_mac != self.mac_addr:
            print(f"[{self.mac_addr}] Dropping Frame")
            print(f"frame: {frame.data_length} bytes from {frame.src_mac} → {frame.dst_mac}")
            return

        if frame.packet.src in self.firewall:
            print(f"[{self.mac_addr}] Dropping frame from {frame.packet.src} due to firewall")
            return

        # Check for covert channel data - do this early to not print covert messages
        if self.receiving_covert_channel:
            # Process all incoming frames when in covert receive mode - covert data uses regular protocol
            if self.process_covert_channel_data(frame):
                return  # Only return if this was actually a covert message

        # Handle TLS protocol
        if frame.packet.protocol == PROTO_TLS:
            self.handle_tls_hello(frame.packet)
            return

        print("Received:")
        if frame.packet.protocol == PROTO_SECURE:
            self.handle_encrypted_message(frame.packet)
            return

        print(f"[{self.mac_addr}] Received:")
        self.print_frame(frame)

        # Don't reply to replies to avoid ping-pong
        if frame.packet.is_reply:
            return

        print(f"[{self.mac_addr}] Replying to ping from {frame.src_mac}...\n")
        for target in self.targets:
            self.send_frame(frame.packet.src, frame.packet.data, target, is_reply=True)

    def ping(self, cmd: str):
        parts = cmd.split()
        if len(parts) < 2:
            print("Error: Invalid ping command format")
            print("Usage: ping <Destination IP> \"<Message>\" <Count>")
            return
            
        rcving_node_ip = int(parts[1], 16)
        
        # Find the message part (may be in quotes)
        if cmd.count('"') >= 2:
            # Extract the message between first and second quotes
            msg_start = cmd.find('"') + 1
            msg_end = cmd.find('"', msg_start)
            msg = cmd[msg_start:msg_end]
            # Count should be after the second quote
            remaining = cmd[msg_end+1:].strip()
            count_parts = remaining.split()
            if count_parts:
                count = int(count_parts[0])
            else:
                count = 1
        else:
            # Fallback to old method
            if len(parts) < 3:
                print("Error: Missing message parameter")
                print("Usage: ping <Destination IP> <Message> <Count>")
                return
            msg = parts[2]
            count = int(parts[3]) if len(parts) > 3 else 1

        for _ in range(count):
            if rcving_node_ip in self.arp_table:
                for target in self.targets:
                    self.send_frame(rcving_node_ip, msg, target)
                print(f"Sent ping to {hex(rcving_node_ip)}: {msg}")
                time.sleep(1)
            else:
                print(f"Error: Destination {hex(rcving_node_ip)} not found in ARP table")
                break

    @staticmethod
    def print_frame(frame: Frame):
        print(
            f"frame: {frame.data_length} bytes from {frame.src_mac} → {frame.dst_mac} | "
            f"packet: {frame.packet.data_length} bytes from {hex(frame.packet.src)} → {hex(frame.packet.dest)} - "
            f"protocol = {frame.packet.protocol}\n"
            f"data: {frame.packet.data}\n"
        )

    #
    # Defense Features (available to all nodes)
    #
    
    def toggle_firewall(self, cmd):
        """Add/remove IP addresses to/from the firewall"""
        command = cmd.lower().split()[0]
        ipAddr = cmd.split()[1]
        base16Addr = int(ipAddr, 16)

        if command == "block":
            self.firewall[base16Addr] = ipAddr
            print(f"🛡️ Blocking {ipAddr}")
        else:
            if base16Addr in self.firewall:
                del self.firewall[base16Addr]
                print(f"🛡️ Unblocking {ipAddr}")

    def view_firewall(self):
        """Display currently blocked IPs"""
        print("🛡️ Firewall:")
        for ip in self.firewall:
            print(f"0x{ip:X}")
        if not self.firewall:
            print("No blocked IPs")

    def toggle_sniff(self):
        """Toggle sniffing mode"""
        self.sniff_mode = not self.sniff_mode
        print(f"🔍 Sniffing mode: {'ON' if self.sniff_mode else 'OFF'}")

    def toggle_ids(self):
        """Toggle intrusion detection system"""
        self.ids_active = not self.ids_active
        print(f"🛡️ Intrusion Detection System: {'ACTIVE' if self.ids_active else 'INACTIVE'}")

    def print_menu(self, opts=None):
        print("\n[-- What would you like to do? --]")
        print("Type 'exit' to quit.")
        print("Nodes: N1 0x1A, N2 0x2A, N3 0x2B")
        print("Router: R1 0x11, R2 0x21")
        print("To ping, type: ping <Destination IP> <Message> <Count>")
        print("Example: 'ping 0x2B Hello 5' (sends 5 'Hello's to Node3)")
        print("\n========== DEFENSIVE FEATURES ==========")
        print("Firewall commands: block <IP>, unblock <IP>, firewall")
        # print("IDS commands: ids (toggle IDS), suspicious (view detected IPs)")
        # print("Traffic Analysis: analyze (start) | report (view statistics)")
        print("\n========== TLS FEATURES ==========")
        print("To establish TLS handshake: tls <Destination IP>")
        print("To securely communicate with another Node: sc <Destination IP> \"<String>\"")
        print("\n========== COVERT FEATURES ==========")
        print("Covert Channel: covert <target_ip> <message> [method] | listen-covert [method]")
        print("   Methods: timing (default), steg (steganography)")
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
        if cmd.lower() == "exit":
            print("Exiting...")
            sys.exit(0)
        self.process_input_command(cmd)

    def process_input_command(self, cmd: str):
        if not cmd:
            return
            
        cmd_parts = cmd.split()
        if not cmd_parts:
            return
            
        command = cmd_parts[0].lower()
        
        if command == "ping":
            self.ping(cmd)
        elif command == "tls":
            if len(cmd_parts) < 2:
                print("Usage: tls <Destination IP>")
                return
            self.initiate_tls(cmd)
        # Defensive commands - available to all nodes
        elif command == "block" or command == "unblock":
            if len(cmd_parts) < 2:
                print("Usage: block/unblock <IP>")
                return
            self.toggle_firewall(cmd)
        elif command == "firewall":
            self.view_firewall()
        elif command == "sniff":
            self.toggle_sniff()
        elif command == "ids":
            self.toggle_ids()
        # Covert channel commands - available to all nodes
        elif command == "covert":
            if len(cmd_parts) < 3:
                print("Usage: covert <target_ip> <secret_message> [method]")
                print("Methods: timing (default), steg (steganography)")
                return
            
            # Check if the last part is a method name
            if len(cmd_parts) > 3 and cmd_parts[-1] in [COVERT_METHOD_TIMING, COVERT_METHOD_STEG]:
                method = cmd_parts[-1]
                secret_message = " ".join(cmd_parts[2:-1])
            else:
                method = COVERT_METHOD_TIMING
                secret_message = " ".join(cmd_parts[2:])
            
            self.start_covert_channel(cmd_parts[1], secret_message, method)
        elif command == "listen-covert":
            method = cmd_parts[1] if len(cmd_parts) > 1 and cmd_parts[1] in [COVERT_METHOD_TIMING, COVERT_METHOD_STEG] else COVERT_METHOD_TIMING
            self.receive_covert_channel(method)
        elif command == "show-covert":
            self.show_covert_messages()
        elif command == "help" or command == "menu":
            self.print_menu()

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

    # Covert Channel Implementation (available to all nodes)
    def start_covert_channel(self, target_ip, secret_message, method=COVERT_METHOD_TIMING):
        """
        Establish a covert channel that hides data using the specified method
        
        Methods:
        - timing: Hide data in timing between packets
        - steg: Hide data in packet contents using steganography
        """
        target_ip = int(target_ip, 16)
        print(f"🕵️ Establishing covert channel with {hex(target_ip)}")
        
        # Convert message to binary
        binary_message = ''.join(format(ord(c), '08b') for c in secret_message)
        self.covert_message = binary_message
        self.covert_bits_sent = 0
        self.covert_channel_active = True
        self.covert_target = target_ip
        self.covert_method = method
        
        print(f"🕵️ Using covert channel method: {method}")
        print(f"🕵️ Message converted to {len(binary_message)} bits")
        print(f"🕵️ Begin covert transmission...")
        
        # Send a synchronization marker for easier recovery
        if method == COVERT_METHOD_STEG:
            # Send a header packet to indicate start of transmission
            for target in self.targets:
                header_packet = f"PING seq=1 ttl=64 time=0.5ms"  # Looks like a normal ping
                # Add a subtle marker that indicates covert start
                header_packet += f" id={self._gen_covert_marker('START')}"
                self.send_frame(self.covert_target, header_packet, target, protocol=0)
            
            # Slight delay before starting transmission
            time.sleep(0.1)
        
        # Start the transmission process
        if method == COVERT_METHOD_TIMING:
            self._send_next_covert_bit_timing()
        else:
            self._send_next_covert_bits_steg(8)  # Send 8 bits (1 byte) per packet

    def _gen_covert_marker(self, marker_type):
        """Generate a marker that looks like a random ID but contains a signature"""
        timestamp = int(time.time()) & 0xFFFF  # Last 16 bits of current timestamp
        marker = (timestamp << 16) | 0xC0DE    # Combine with signature 0xC0DE
        return f"{marker:x}"  # Return as hex

    def _send_next_covert_bit_timing(self):
        """Send the next bit in the covert channel using timing method with randomization"""
        if not self.covert_channel_active or self.covert_bits_sent >= len(self.covert_message):
            if self.covert_channel_active:
                print("🕵️ Covert message transmission complete")
                self.covert_channel_active = False
            return
            
        bit = self.covert_message[self.covert_bits_sent]
        
        # Use randomized timing to make pattern detection harder
        # but maintain enough distinction for reliable decoding
        if bit == '1':
            delay = random.uniform(0.09, 0.11)  # 90-110ms for bit 1
        else:
            delay = random.uniform(0.04, 0.06)  # 40-60ms for bit 0
        
        # Create a packet with random size to avoid size-based detection
        payload_size = random.randint(5, 50)  # Random content length
        random_padding = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(payload_size))
        
        # Add the bit information to the packet payload for sniffing visibility
        packet_content = f"ECHO request seq={self.covert_bits_sent+1} ttl={random.randint(40, 128)} data={random_padding}"
        
        # Only add bit marker if sniffing is enabled
        if self.sniff_mode:
            packet_content += f" [COVERT-BIT:{bit}]"
            
        # Send seemingly innocent packet
        for target in self.targets:
            self.send_frame(
                self.covert_target, 
                packet_content, 
                target, 
                protocol=0
            )
        
        print(f"🕵️ Sending covert bit: {bit}")
        
        self.covert_bits_sent += 1
        progress = (self.covert_bits_sent / len(self.covert_message)) * 100
        if self.covert_bits_sent % 8 == 0:  # Show progress every byte
            print(f"🕵️ Covert transmission: {progress:.1f}% complete")
        
        # Schedule the next bit
        time.sleep(delay)
        
        # Send the next bit if there are more to send
        if self.covert_bits_sent < len(self.covert_message):
            self._send_next_covert_bit_timing()
        else:
            # Send end marker with random delay
            time.sleep(random.uniform(0.15, 0.25))
            
            # Create end packet with random data
            payload_size = random.randint(5, 50)
            random_padding = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(payload_size))
            end_packet = f"ECHO request seq={self.covert_bits_sent+2} ttl={random.randint(40, 128)} data={random_padding} LAST"
            
            if self.sniff_mode:
                end_packet += " [COVERT-END]"
                
            for target in self.targets:
                self.send_frame(
                    self.covert_target, 
                    end_packet, 
                    target, 
                    protocol=0
                )
            print("🕵️ Covert message transmission complete")
            print("🎧 Use 'show-covert' on the receiving node to see the message")
            self.covert_channel_active = False

    def _encode_bits_in_text(self, bits, length=8):
        """Encode bits in text that looks like normal traffic with high variability"""
        # Only use as many bits as we have left
        bits_to_encode = bits[:length]
        if not bits_to_encode:
            return None
            
        # Pad with zeros if needed
        if len(bits_to_encode) < length:
            bits_to_encode = bits_to_encode.ljust(length, '0')
        
        # Take 8 bits and convert to a number
        byte_val = int(bits_to_encode, 2)
        
        # Create a legitimate-looking packet payload with high variability
        traffic_types = [
            f"PING seq={random.randint(1, 9999)} ttl={byte_val} size={random.randint(32, 1024)}",
            f"DATA offset={byte_val} length={random.randint(32, 1024)} flags={random.randint(0, 15)}",
            f"QUERY type={random.choice(['A', 'AAAA', 'MX', 'TXT'])} host=server{byte_val}.{random.choice(['com', 'net', 'org', 'io'])}",
            f"STATUS code={byte_val} message=\"{random.choice(['OK', 'Error', 'Warning', 'Info', 'Debug'])}-{random.randint(100, 999)}\"",
            f"INFO server_id={random.randint(1, 99)} load={byte_val/100} users={random.randint(1, 500)}"
        ]
        
        # Choose a random template
        message = random.choice(traffic_types)
        
        # Add a subtle marker that looks like normal metadata
        marker_formats = [
            f" id={self._gen_covert_marker('')}{random.randint(100, 999)}",
            f" session={self._gen_covert_marker('')}",
            f" ref={self._gen_covert_marker('')}{random.choice(['a', 'b', 'c', 'd', 'e', 'f'])}"
        ]
        message += random.choice(marker_formats)
        
        # Add random padding to vary packet size unpredictably
        if random.random() > 0.5:
            padding_chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
            padding = ''.join(random.choice(padding_chars) for _ in range(random.randint(0, 20)))
            message += f" extra={padding}"
        
        # Add covert bits marker only when sniffing is enabled
        if self.sniff_mode:
            message += f" [COVERT-BITS:{bits_to_encode}]"
        
        return message

    def _send_next_covert_bits_steg(self, bits_per_packet=8):
        """Send bits using steganography in packet contents"""
        if not self.covert_channel_active or self.covert_bits_sent >= len(self.covert_message):
            if self.covert_channel_active:
                # Send end marker
                for target in self.targets:
                    end_packet = f"PING seq={random.randint(1, 9999)} ttl=64 time=0.5ms"
                    end_packet += f" id={self._gen_covert_marker('END')}"
                    self.send_frame(self.covert_target, end_packet, target, protocol=0)
                print("🕵️ Covert message transmission complete")
                self.covert_channel_active = False
            return
        
        # Get the next bits to send
        remaining_bits = len(self.covert_message) - self.covert_bits_sent
        bits_to_send = min(bits_per_packet, remaining_bits)
        current_bits = self.covert_message[self.covert_bits_sent:self.covert_bits_sent+bits_to_send]
        
        # Encode the bits in a regular-looking packet
        encoded_message = self._encode_bits_in_text(current_bits, bits_to_send)
        if not encoded_message:
            print("🕵️ Covert message transmission complete")
            self.covert_channel_active = False
            return
        
        # Send the packet
        for target in self.targets:
            self.send_frame(
                self.covert_target, 
                encoded_message, 
                target, 
                protocol=0  # Use regular IP, not covert protocol
            )
        
        self.covert_bits_sent += bits_to_send
        progress = (self.covert_bits_sent / len(self.covert_message)) * 100
        if self.covert_bits_sent % 8 == 0:  # Show progress every byte
            print(f"🕵️ Covert transmission: {progress:.1f}% complete")
        
        # Small random delay for realism
        time.sleep(random.uniform(0.05, 0.2))
        
        # Send the next bits if there are more to send
        if self.covert_bits_sent < len(self.covert_message):
            self._send_next_covert_bits_steg(bits_per_packet)
        else:
            # Send end marker
            for target in self.targets:
                end_packet = f"PING seq={random.randint(1, 9999)} ttl=64 time=0.5ms"
                end_packet += f" id={self._gen_covert_marker('END')}"
                self.send_frame(self.covert_target, end_packet, target, protocol=0)
            print("🕵️ Covert message transmission complete")
            self.covert_channel_active = False

    def receive_covert_channel(self, method=COVERT_METHOD_TIMING):
        """
        Start listening for covert channel data using the specified method
        """
        print(f"🎧 Listening for covert channel data using {method} method...")
        self.receiving_covert_channel = True
        self.covert_received_bits = ""
        self.last_packet_time = None
        self.covert_receive_method = method
        self.covert_steg_started = False

    def process_covert_channel_data(self, frame):
        """Process incoming data for covert channel messages"""
        if not self.receiving_covert_channel:
            return False
        
        # Process based on the detection method
        if hasattr(self, 'covert_receive_method') and self.covert_receive_method == COVERT_METHOD_STEG:
            return self._process_steg_covert(frame)
        else:
            return self._process_timing_covert(frame)

    def _process_timing_covert(self, frame):
        """Process covert channel data using timing between packets"""
        # Check if this looks like a covert packet
        data_str = str(frame.packet.data)
        if not ("ECHO request seq=" in data_str or "LAST" in data_str):
            return False  # Not a covert packet
            
        current_time = time.time()
        
        # Check for end marker first
        if "LAST" in data_str:
            print("🎧 Detected end of covert transmission")
            self._process_received_covert_message()
            return True
    
        # Skip the first packet since we don't have a reference time yet
        if self.last_packet_time is None:
            self.last_packet_time = current_time
            return True
            
        time_diff = current_time - self.last_packet_time
        self.last_packet_time = current_time
        
        # Decode the bit based on timing
        if time_diff >= 0.075:  # Threshold to distinguish 0 from 1
            received_bit = "1"
            print(f"🎧 Received bit: 1 (delay: {time_diff*1000:.2f}ms)")
        else:
            received_bit = "0"
            print(f"🎧 Received bit: 0 (delay: {time_diff*1000:.2f}ms)")
            
        self.covert_received_bits += received_bit
        
        # Every 8 bits, try to convert to a character
        if len(self.covert_received_bits) % 8 == 0:
            self._process_covert_byte()

    def _process_steg_covert(self, frame):
        """Process covert channel data using steganography"""
        # Check if we get a packet with our special marker
        data_str = str(frame.packet.data)
        
        # Check for start/end markers
        if not hasattr(self, 'covert_steg_started') or not self.covert_steg_started:
            # Look for start marker
            if " id=" in data_str and "c0de" in data_str.lower():
                print("🎧 Detected start of steganographic covert transmission")
                self.covert_steg_started = True
                return True
            return False  # Not a covert packet
        
        # Check for end marker
        if " id=" in data_str and "c0de" in data_str.lower() and "END" in data_str:
            print("🎧 Detected end of steganographic covert transmission")
            self._process_received_covert_message()
            self.covert_steg_started = False
            return
        
        # Extract hidden data from packet
        bits = self._extract_bits_from_text(data_str)
        if bits:
            print(f"🎧 Decoded bits: {bits}")
            self.covert_received_bits += bits
            
            # Process every 8 bits as they arrive
            while len(self.covert_received_bits) >= 8:
                self._process_covert_byte()

        return True  # Indicate that we processed a covert packet

    def _extract_bits_from_text(self, text):
        """Extract hidden bits from the packet text"""
        # Various patterns to extract hidden values
        patterns = [
            r"ttl=(\d+)",
            r"offset=(\d+)",
            r"server(\d+)",
            r"code=(\d+)",
            r"load=(\d+\.\d+)"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                # Extract the value
                value = match.group(1)
                if "." in value:  # Handle float values
                    value = int(float(value) * 100)
                else:
                    value = int(value)
                    
                # Convert to 8-bit binary
                binary = format(value & 0xFF, '08b')
                return binary
                
        return None

    def _process_covert_byte(self):
        """Process a complete byte from the covert channel"""
        try:
            # Process as many complete bytes as we have
            while len(self.covert_received_bits) >= 8:
                # Take 8 bits from the front
                byte_bits = self.covert_received_bits[:8]
                self.covert_received_bits = self.covert_received_bits[8:]
                
                # Convert to character
                char = chr(int(byte_bits, 2))
                print(f"🎧 Decoded character: '{char}' from bit pattern {byte_bits}")
                
                # Store in recovered message
                if not hasattr(self, 'current_message'):
                    self.current_message = ""
                self.current_message += char
                
                # Show the message so far
                print(f"🎧 Message so far: '{self.current_message}'")
                    
        except Exception as e:
            print(f"🎧 Error processing covert byte: {e}")

    def _process_received_covert_message(self):
        """Process a complete covert message"""
        # Initialize recovered_messages if it doesn't exist
        if not hasattr(self, 'recovered_messages'):
            self.recovered_messages = []
        
        # If we have a current message, store it
        if hasattr(self, 'current_message') and self.current_message:
            # Add to recovered messages
            self.recovered_messages.append(self.current_message)
            print(f"🎧 Recovered complete message: '{self.current_message}'")
            
            # Print command to view messages
            print("🎧 Use 'show-covert' to see all recovered messages")
            
            # Reset for next message
            self.current_message = ""
            self.covert_received_bits = ""
            self.last_packet_time = None
            
            # Automatically stop listening after successful reception
            self.receiving_covert_channel = False
    
    # Add the show_covert method to the Node class

    def show_covert_messages(self):
        """Display all recovered covert messages"""
        print("\n🎧 === RECOVERED COVERT MESSAGES ===")
        
        # Check if recovered_messages exists and has items
        if hasattr(self, 'recovered_messages') and self.recovered_messages:
            for i, message in enumerate(self.recovered_messages):
                print(f"  Message {i+1}: '{message}'")
        # Also check for a current message in progress
        elif hasattr(self, 'current_message') and self.current_message:
            print(f"  Current message (in progress): '{self.current_message}'")
        else:
            print("  No covert messages recovered yet")
        
        print("====================================\n")

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
