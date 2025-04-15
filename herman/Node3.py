from Node import Node, PROTO_COVERT
import time
import random
import socket
import pickle
from network import Frame, IPpacket, TCPHeader

# Node3 network details
LISTENING_PORT = 50030

class Node3(Node):
    def __init__(self, ip, mac_addr):
        # 0x1A -> R2 since we send it to Router to be routed to Node1
        super().__init__(
            ip=ip,
            mac_addr=mac_addr,
            listening_port=LISTENING_PORT,
            arp_table={
                0x1A: "R2", 0x2A: "N2", 0x11: "R1", 0x21: "R2"
            },
            targets=[50020, 50040]
        )
        
        # Attack Features (Node3 only)
        self.spoof_ip = 0
        self.mitm_mode = False
        self.mitm_victims = ()
        self.packet_injection_targets = {}
        self.ddos_attack_active = False
        self.capture_credentials = False
        self.captured_data = []
        self.arp_poisoning_active = False
        self.honeypot_active = False
        self.attack_logs = []
        self.dns_spoofing_targets = {}

    def send_frame(self, rcving_node_ip, msg, hc_port, is_reply=False, protocol=0):
        """Override to support IP spoofing"""
        src_ip = self.spoof_ip if self.spoof_ip != 0 else self.ip
        if is_reply:
            packet = IPpacket(src_ip, rcving_node_ip, protocol, msg, is_reply=True)
        else:
            packet = IPpacket(src_ip, rcving_node_ip, protocol, msg)

        frame = Frame(self.mac_addr, self.arp_table[rcving_node_ip], packet)
        self.sock.sendto(pickle.dumps(frame), ("127.0.0.1", hc_port))

    def send_raw_packet(self, packet, hc_port):
        """Send a raw packet without worrying about ARP lookups"""
        dst_mac = self.arp_table.get(packet.dest, "FF:FF")  # Default broadcast if unknown
        frame = Frame(self.mac_addr, dst_mac, packet)
        self.sock.sendto(pickle.dumps(frame), ("127.0.0.1", hc_port))

    def handle_incoming_frame(self, frame):
        # Check MITM interception first
        if self.mitm_mode and frame.packet.src in self.mitm_victims and frame.packet.dest in self.mitm_victims:
            print("\n🔴 === INTERCEPTED TRAFFIC ===")
            print(f"From: {hex(frame.packet.src)} To: {hex(frame.packet.dest)}")
            print(f"Data: {frame.packet.data}")
            
            # Check if we need to do packet injection
            if frame.packet.dest in self.packet_injection_targets:
                inject_info = self.packet_injection_targets[frame.packet.dest]
                if isinstance(frame.packet.data, str) and inject_info["trigger"] in frame.packet.data:
                    print(f"🔴 Injecting malicious packet!")
                    # Replace the packet data with our injected payload
                    frame.packet.data = frame.packet.data.replace(
                        inject_info["trigger"], 
                        inject_info["replacement"]
                    )
            
            # Capture credentials if enabled
            if self.capture_credentials:
                data_str = str(frame.packet.data).lower()
                if "password" in data_str or "user" in data_str or "login" in data_str:
                    self.captured_data.append({
                        "timestamp": time.strftime("%H:%M:%S"),
                        "source": hex(frame.packet.src),
                        "destination": hex(frame.packet.dest),
                        "data": frame.packet.data
                    })
                    print("🔴 Potentially captured credentials!")
            
            # Forward the potentially modified packet
            for target in self.targets:
                self.send_frame(
                    frame.packet.dest, 
                    frame.packet.data, 
                    target,
                    protocol=frame.packet.protocol
                )
            return

        # Check for honeypot probes
        if self.honeypot_active:
            data_str = str(frame.packet.data).lower()
            if "password" in data_str or "login" in data_str:
                self.log_attack("Credential Theft Attempt", frame.packet.src, frame.packet.data)
            elif "select" in data_str and ("from" in data_str or "where" in data_str):
                self.log_attack("SQL Injection Attempt", frame.packet.src, frame.packet.data)
            elif "../" in data_str or "/.." in data_str:
                self.log_attack("Directory Traversal", frame.packet.src, frame.packet.data)

        # Normal processing
        super().handle_incoming_frame(frame)

    #
    # Attack Features (Node3 only)
    #
    
    def toggle_spoof(self, spoof_ip):
        """Toggle IP spoofing mode"""
        if self.spoof_ip != 0:
            self.spoof_ip = 0
            print("🔴 IP spoofing disabled")
        else:
            self.spoof_ip = int(spoof_ip, 16)
            print(f"🔴 Now spoofing as IP: {hex(self.spoof_ip)}")

    def arp_poison(self, target_ip, spoofed_ip):
        """
        Send fake ARP messages to associate our MAC with another node's IP
        """
        target_ip = int(target_ip, 16)
        spoofed_ip = int(spoofed_ip, 16)
        
        print(f"🔴 ARP poisoning: Associating our MAC with {hex(spoofed_ip)}")
        
        # Create a special ARP packet (using protocol 0xAA for ARP)
        arp_packet = IPpacket(
            src=self.ip,
            dest=target_ip,
            protocol=0xAA,  # Using 0xAA as ARP protocol
            data=f"ARP|{hex(spoofed_ip)}|{self.mac_addr}"
        )
        
        # Send to target through all routes
        for target in self.targets:
            self.send_raw_packet(arp_packet, target)
        
        print(f"🔴 ARP poison attack launched against {hex(target_ip)}")
        self.arp_poisoning_active = True

    def mitm_attack(self, victim1, victim2):
        """
        Perform Man-in-the-Middle attack between two nodes
        """
        victim1 = int(victim1, 16)
        victim2 = int(victim2, 16)
        
        print(f"🔴 Starting MITM attack between {hex(victim1)} and {hex(victim2)}")
        
        # First poison ARP for both victims
        self.arp_poison(hex(victim1), hex(victim2))
        self.arp_poison(hex(victim2), hex(victim1))
        
        # Set up MITM mode
        self.mitm_mode = True
        self.mitm_victims = (victim1, victim2)
        print("🔴 MITM attack active - all traffic will be intercepted")
    
    def start_ddos(self, target_ip, packets_per_second=5, duration=10):
        """
        Start a DDoS attack against a target using this node's real IP
        """
        target_ip = int(target_ip, 16)
        print(f"🔴 Starting DDoS attack against {hex(target_ip)}")
        

        self.ddos_attack_active = True
        start_time = time.time()
        
        try:
            while time.time() - start_time < duration and self.ddos_attack_active:
                # Generate varying data for the attack
                for _ in range(packets_per_second):
                    # Create different sized payloads to simulate different packets
                    payload_size = random.randint(10, 100)
                    payload = "X" * payload_size
                    
                    protocol = 0
                    
                    # Always send from real IP
                    for target in self.targets:
                        self.send_frame(target_ip, payload, target, protocol=protocol)
                    
                    # Small delay between packets
                    time.sleep(0.1)
                
                print(f"🔴 Sent {packets_per_second} attack packets from {hex(self.ip)}")
                time.sleep(1)  # Wait before the next batch
                
            print("🔴 DDoS attack completed")
            # Restore original spoofing settings
            self.ddos_attack_active = False
            
        except KeyboardInterrupt:
            print("🔴 DDoS attack interrupted")
            # Restore original spoofing settings
            self.ddos_attack_active = False

    def inject_packet(self, target_ip, payload, replacement=None):
        """
        Set up packet injection for a specific target
        """
        target_ip = int(target_ip, 16)
        self.packet_injection_targets[target_ip] = {
            "trigger": payload,
            "replacement": replacement or f"INJECTED_PAYLOAD_{random.randint(1000, 9999)}"
        }
        print(f"🔴 Packet injection set up for {hex(target_ip)}")
        print(f"   Trigger: '{payload}'")
        print(f"   Replacement: '{self.packet_injection_targets[target_ip]['replacement']}'")

    def toggle_credential_capture(self):
        """Toggle credential capture mode"""
        self.capture_credentials = not self.capture_credentials
        print(f"🔴 Credential capture: {'ENABLED' if self.capture_credentials else 'DISABLED'}")

    def show_captured_data(self):
        """Display captured sensitive data"""
        if not self.captured_data:
            print("No sensitive data captured")
            return
            
        print("\n🔴 === CAPTURED SENSITIVE DATA ===")
        for item in self.captured_data:
            print(f"[{item['timestamp']}] {item['source']} → {item['destination']}")
            print(f"Data: {item['data']}")
        print("============================\n")
        
    def dns_spoof(self, domain, fake_ip):
        """
        Set up DNS spoofing for a specific domain
        """
        self.dns_spoofing_targets[domain] = fake_ip
        print(f"🔴 DNS spoofing set: {domain} → {fake_ip}")

    def enable_honeypot(self):
        """
        Enable honeypot mode to attract and log attacks
        """
        self.honeypot_active = True
        self.attack_logs = []
        print("🍯 Honeypot activated - appearing vulnerable to attract attacks")
        
        # Advertise vulnerable services
        vulnerable_service_ad = IPpacket(
            src=self.ip,
            dest=0xFF,  # Broadcast
            protocol=0x88,  # Service advertisement protocol
            data="SERVICE|TELNET:open|FTP:open|SQL:open"
        )
        
        for target in self.targets:
            self.send_raw_packet(vulnerable_service_ad, target)

    def log_attack(self, attack_type, source_ip, details):
        """
        Log attack attempts against the honeypot
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "type": attack_type,
            "source": hex(source_ip),
            "details": details
        }
        
        self.attack_logs.append(log_entry)
        print(f"🍯 Attack detected: {attack_type} from {hex(source_ip)}")

    def view_attack_logs(self):
        """
        Display attack logs from honeypot
        """
        if not self.attack_logs:
            print("No attacks logged")
            return
            
        print("\n🍯 === HONEYPOT ATTACK LOGS ===")
        for log in self.attack_logs:
            print(f"[{log['timestamp']}] {log['type']} from {log['source']}")
            print(f"  Details: {log['details']}")
        print("================================\n")

    # Advanced feature: Polymorphic Packet Attack
    def launch_polymorphic_attack(self, target_ip, count=10):
        """
        Launch an attack that continuously changes its network signature
        to evade detection by signature-based security systems
        """
        target_ip = int(target_ip, 16)
        print(f"🧬 Launching polymorphic attack against {hex(target_ip)}")
        
        payload_templates = [
            "GET /index.html HTTP/1.1",
            "POST /login.php HTTP/1.1",
            "HEAD /admin HTTP/1.1"
        ]
        
        for i in range(count):
            # Create a unique signature for this iteration
            mutation_seed = random.randint(1000, 9999)
            random.seed(mutation_seed)
            
            # Mutate the payload
            payload = random.choice(payload_templates)
            payload = self._mutate_payload(payload, mutation_level=i % 3 + 1)
            
            # Vary protocol fields
            protocol = random.randint(0x20, 0x30)  # Random custom protocol
            
            # Send the polymorphic packet
            print(f"🧬 Sending mutation #{i+1}: {payload[:20]}...")
            self.send_frame(target_ip, payload, 50040, protocol=protocol)
            time.sleep(random.uniform(0.1, 0.5))  # Random timing
        
        print("🧬 Polymorphic attack sequence completed")

    def _mutate_payload(self, payload, mutation_level=1):
        """Apply different mutations to the payload based on level"""
        if mutation_level == 1:
            # Case mutations and character substitutions
            return ''.join(c.upper() if random.random() > 0.5 else c for c in payload)
        elif mutation_level == 2:
            # Add random data and comments
            insertions = random.randint(1, 3)
            for _ in range(insertions):
                pos = random.randint(0, len(payload))
                payload = payload[:pos] + f"/*{random.randint(1000,9999)}*/" + payload[pos:]
            return payload
        else:
            # Protocol obfuscation and encoding tricks
            return payload.replace(' ', '%20').replace('/', '%2F') + f"&id={random.randint(1000,9999)}"

    # Advanced Feature: Protocol Confusion Attack
    def protocol_confusion_attack(self, target_ip):
        """
        Execute an attack that exploits ambiguities in how protocols are interpreted
        by different systems or layers of the network stack
        """
        target_ip = int(target_ip, 16)
        print(f"🔀 Launching protocol confusion attack against {hex(target_ip)}")
        
        # Create a packet that can be interpreted differently at different network layers
        # For example, a packet that is valid HTTP but also contains SQL or shell commands
        
        # Dual-use payload that appears innocent at one layer but malicious at another
        dual_payload = "GET /search?q=<script>/*\nSELECT * FROM users--*/</script> HTTP/1.1"
        
        # Add multiple headers that create ambiguity
        dual_payload += "\nContent-Length: 100"  # First content-length
        dual_payload += "\nContent-Length: 200"  # Conflicting content-length
        
        # Add payload with deliberate format confusion
        dual_payload += "\n\n{'user':null}<!--"  # Looks like JSON but has HTML comment
        dual_payload += "\nmalicious_command();"  # Hidden in comment for some parsers
        dual_payload += "-->"
        
        print("🔀 Sending protocol-ambiguous packet")
        self.send_frame(target_ip, dual_payload, 50040, protocol=0x80)
        
        print("🔀 Protocol confusion attack executed")

    def process_input_command(self, cmd):
        if not cmd:
            return
            
        cmd_parts = cmd.split()
        if not cmd_parts:
            return
            
        command = cmd_parts[0].lower()
        
        # Attack commands (Node3 only)
        if command == "spoof":
            if len(cmd_parts) < 2:
                print("Usage: spoof <target_ip>")
                return
            self.toggle_spoof(cmd_parts[1])
        elif command == "arppoison":
            if len(cmd_parts) < 3:
                print("Usage: arppoison <target_ip> <spoofed_ip>")
                return
            self.arp_poison(cmd_parts[1], cmd_parts[2])
        elif command == "mitm":
            if len(cmd_parts) < 3:
                print("Usage: mitm <victim1_ip> <victim2_ip>")
                return
            self.mitm_attack(cmd_parts[1], cmd_parts[2])
        elif command == "mitm-stop":
            self.mitm_mode = False
            print("🔴 MITM attack stopped")
        elif command == "ddos":
            if len(cmd_parts) < 2:
                print("Usage: ddos <target_ip> [packets_per_second] [duration]")
                return
            pps = int(cmd_parts[2]) if len(cmd_parts) > 2 else 5
            duration = int(cmd_parts[3]) if len(cmd_parts) > 3 else 10
            self.start_ddos(cmd_parts[1], pps, duration)
        elif command == "ddos-stop":
            self.ddos_attack_active = False
            print("🔴 DDoS attack stopped")
        elif command == "inject":
            if len(cmd_parts) < 3:
                print("Usage: inject <target_ip> <trigger_text> [replacement_text]")
                return
            replacement = " ".join(cmd_parts[3:]) if len(cmd_parts) > 3 else None
            self.inject_packet(cmd_parts[1], cmd_parts[2], replacement)
        elif command == "capture":
            self.toggle_credential_capture()
        elif command == "show-captured":
            self.show_captured_data()
        elif command == "dns-spoof":
            if len(cmd_parts) < 3:
                print("Usage: dns-spoof <domain> <fake_ip>")
                return
            self.dns_spoof(cmd_parts[1], cmd_parts[2])
        elif command == "honeypot":
            self.enable_honeypot()
        elif command == "logs":
            self.view_attack_logs()
        elif command == "polymorphic":
            if len(cmd_parts) < 2:
                print("Usage: polymorphic <target_ip> [count]")
                return
            count = int(cmd_parts[2]) if len(cmd_parts) > 2 else 10
            self.launch_polymorphic_attack(cmd_parts[1], count)
        elif command == "confusion":
            if len(cmd_parts) < 2:
                print("Usage: confusion <target_ip>")
                return
            self.protocol_confusion_attack(cmd_parts[1])
        else:
            # Handle defense and core commands via parent class
            super().process_input_command(cmd)

    def print_menu(self):
        super().print_menu([
            lambda: print("\n=========== ATTACK FEATURES ==========="),
            lambda: print("Sniffing: sniff <Target IP>"),
            lambda: print("Sniffing: sniff OFF"),
            # lambda: print("IP Spoofing: spoof <IP> | spoof 0 (disable)"),
            # lambda: print("ARP Poisoning: arppoison <target_ip> <spoofed_ip>"),
            # lambda: print("MITM Attack: mitm <victim1_ip> <victim2_ip> | mitm-stop"),
            # lambda: print("DDoS Attack: ddos <target_ip> [pps] [duration] | ddos-stop"),
            # lambda: print("Packet Injection: inject <target_ip> <trigger> [replacement]"),
            # lambda: print("Credential Capture: capture (toggle) | show-captured"),
            # lambda: print("DNS Spoofing: dns-spoof <domain> <fake_ip>"),
            # lambda: print("\n========= ADVANCED ATTACK FEATURES ========="),
            # lambda: print("Polymorphic Attack: polymorphic <target_ip> [count]"),
            # lambda: print("Protocol Confusion: confusion <target_ip>"),
            # lambda: print("\n========= MONITORING FEATURES ========="),
            # lambda: print("Honeypot: honeypot (enable) | logs (view attack logs)"),
        ])


if __name__ == "__main__":
    node = Node3(0x2B, "N3") # Initialize Node3 with emulation values
    node.run()
