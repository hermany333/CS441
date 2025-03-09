import socket
import time
import selectors
import sys
import pickle
from network import Frame, IPpacket
from typing import cast

LISTENING_IP = "127.0.0.1"

class Node:
    def __init__(self, ip, mac_addr, listening_port, arp_table={}, targets=[]):
        self.ip = ip
        self.mac_addr = mac_addr
        self.listening_port = listening_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((LISTENING_IP, self.listening_port))
        self.sock.setblocking(False)
        self.sel = selectors.DefaultSelector()

        self.sel.register(self.sock, selectors.EVENT_READ, data="network")
        self.sel.register(sys.stdin, selectors.EVENT_READ, data="input")
        self.arp_table = arp_table
        self.targets = targets

    def send_frame(self, rcving_node_ip, msg, hc_port, is_reply=False):
        if is_reply:
            packet = IPpacket(self.ip, rcving_node_ip, 0, msg, is_reply=True)
        else:
            packet = IPpacket(self.ip, rcving_node_ip, 0, msg)

        frame = Frame(self.mac_addr, self.arp_table[rcving_node_ip], packet)
        self.sock.sendto(pickle.dumps(frame), ("127.0.0.1", hc_port))

    def handle_incoming_frame(self, frame: Frame):
        if frame.dst_mac != self.mac_addr:
            print("Dropping frame")
            self.print_frame(frame)
            return

        print("Received:")
        self.print_frame(frame)

        if frame.packet.is_reply:
            return

        print(f"Replying to ping from {frame.src_mac}...\n")
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

    @staticmethod
    def print_menu():
        print("\n[-- What would you like to do? --]")
        print("Type 'exit' to quit.")
        print("Nodes: N1 0x1A, N2 0x2A, N3 0x2B")
        print("Router: R1 0x11, R2 0x21")
        print("To ping, type: ping <Destination IP> <Message> <Count>")
        print("Example: 'ping 0x2B Hello 5' (sends 5 'Hello's to Node3)")
        print("-------------------------------------------")

    def run(self):
        self.print_menu()
        try:
            while True:
                events = self.sel.select(timeout=None)
                for key, _ in events:
                    if key.data == "network":
                        data, _ = self.sock.recvfrom(1024)
                        frame = cast(Frame, pickle.loads(data))
                        self.handle_incoming_frame(frame)

                    elif key.data == "input":
                        cmd = sys.stdin.readline().strip()
                        if cmd.split()[0] == "ping":
                            self.ping(cmd)

        except KeyboardInterrupt:
            print("\nCaught keyboard interrupt, exiting.")
        finally:
            self.sel.close()

    def get_hc_port(self):
        # To be implemented by subclasses
        raise NotImplementedError

