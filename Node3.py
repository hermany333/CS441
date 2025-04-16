from Node import Node

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

    def print_menu(self, opts=None):
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
