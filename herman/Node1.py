from Node import Node

import sys
import selectors
import pickle
from network import Frame, IPpacket

# Node1 network details
LISTENING_PORT = 50010

class Node1(Node):
    def __init__(self, ip, mac_addr):
        # 0x2A/2B -> R1 since we send it to Router to be routed to Node1
        super().__init__(
            ip=ip,
            mac_addr=mac_addr,
            listening_port=LISTENING_PORT,
            arp_table={
                0x2A: "R1", 0x2B: "R1", 0x11: "R1", 0x21: "R2"
            },
            targets=[50040]
        )
        self.spoof_ip=0

    def send_frame(self, rcving_node_ip, msg, hc_port, is_reply=False):
        src_ip = self.spoof_ip if self.spoof_ip != 0 else self.ip
        if is_reply:
            packet = IPpacket(src_ip, rcving_node_ip, 0, msg, is_reply=True)
        else:
            packet = IPpacket(src_ip, rcving_node_ip, 0, msg)

        frame = Frame(self.mac_addr, self.arp_table[rcving_node_ip], packet)
        self.sock.sendto(pickle.dumps(frame), ("127.0.0.1", hc_port))

    def toggleSpoof(self, spoof_ip):
        if self.spoof_ip != 0:
            self.spoof_ip = 0
        else:
            self.spoof_ip = int(spoof_ip, 16)

    def process_input_command(self, cmd):
        if cmd.split()[0] == "spoof":
            self.toggleSpoof(cmd.split()[1])
            print(f"Spoofing: {self.spoof_ip != 0}")
        else:
            super().process_input_command(cmd)

if __name__ == "__main__":
    node = Node1(0x1A, "N1") # Initialise Node1 with emulation values
    node.run()
