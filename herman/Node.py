import socket
import time
import selectors
import sys
import pickle
from network import Frame, IPpacket
from typing import cast
import threading

LISTENING_IP = "127.0.0.1"

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
                print("Sniffing:")
                self.print_frame(frame)
                return
            
        elif frame.dst_mac != self.mac_addr:
            print("Dropping frame")
            self.print_frame(frame)
            return
        

        if frame.packet.src in self.firewall:
            print(f"Dropping frame from {frame.packet.src} due to firewall")
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

    def print_menu(self, opts=None):
        print("\n[-- What would you like to do? --]")
        print("Type 'exit' to quit.")
        print("Nodes: N1 0x1A, N2 0x2A, N3 0x2B")
        print("Router: R1 0x11, R2 0x21")
        print("To ping, type: ping <Destination IP> <Message> <Count>")
        print("Example: 'ping 0x2B Hello 5' (sends 5 'Hello's to Node3)")
        print("block [ip] to block a specific ip")
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
