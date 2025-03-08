import socket
import selectors
import pickle
from typing import cast
from network import Frame, IPpacket

# UDP port mapping for Node1, Node2, Node3

# Router listens on its own port
ROUTER_LISTEN_PORT = 50040
LISTENING_IP = "127.0.0.1"

class Router:
    def __init__(self):
        self.iplan1 = 0x11
        self.mac_addrlan1 = "R1"
        self.iplan2 = 0x21
        self.mac_addrlan2 = "R2"
        self.arp_table = {0x1A: "N1", 0x2A: "N2", 0x2B: "N3"}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((LISTENING_IP, ROUTER_LISTEN_PORT))
        self.sock.setblocking(False)

        self.sel = selectors.DefaultSelector()
        self.sel.register(self.sock, selectors.EVENT_READ, data="network")

    def handle_incoming_frame(self, frame: Frame):
        if frame.dst_mac not in [self.mac_addrlan1, self.mac_addrlan2]:
            print(f"Dropping frame")
            Router.print_frame(frame)
            return
        
        ip_pkt = frame.packet
        dest_ip = ip_pkt.dest

        # Receive ping for ourselves and reply back to node accordingly
        if dest_ip in [self.iplan1, self.iplan2]:
          print("Received:")
          Router.print_frame(frame)

          print(f"Replying to ping from {frame.src_mac}...\n")
          if ip_pkt.src in [0x2A, 0x2B]:
            # Reply back to node in LAN2
            self.send_frame(self.mac_addrlan2, self.iplan2, frame.packet.src, frame.packet.data, 50020, True)
            self.send_frame(self.mac_addrlan2, self.iplan2, frame.packet.src, frame.packet.data, 50030, True)
          elif ip_pkt.src in [0x1A]:
            self.send_frame(self.mac_addrlan1, self.iplan1, frame.packet.src, frame.packet.data, 50030, True)

        elif dest_ip in [0x2A, 0x2B]:
          # route to LAN2 changing src_mac of frame
          print(f"Routing packet sent by {hex(frame.packet.src)} to {hex(frame.packet.dest)} \n")
          self.send_frame(self.mac_addrlan2, frame.packet.src, frame.packet.dest, frame.packet.data, 50020, frame.packet.is_reply)
          self.send_frame(self.mac_addrlan2, frame.packet.src, frame.packet.dest, frame.packet.data, 50030, frame.packet.is_reply)
        elif dest_ip in [0x1A]:
          print(f"Routing packet sent by {hex(frame.packet.src)} to {hex(frame.packet.dest)}\n")
          # route to LAN1 changing src_mac of frame
          self.send_frame(self.mac_addrlan1, frame.packet.src, frame.packet.dest, frame.packet.data, 50010, frame.packet.is_reply)
        else:
            print(f"[Router] Unknown IP dest={hex(dest_ip)}, dropping frame.")

    # has an extra src_mac, src_ip argument (comapred to send_frame in node as router has 2 ips attached to it)
    def send_frame(self, src_mac, src_ip, rcving_node_ip, msg, hc_port, is_reply = False):
        if is_reply:
            packet = IPpacket(src_ip, rcving_node_ip, 0, msg, is_reply = True)
            frame = Frame(src_mac, self.arp_table[rcving_node_ip], packet)  
        else:
            packet = IPpacket(src_ip, rcving_node_ip, 0, msg)
            frame = Frame(src_mac, self.arp_table[rcving_node_ip], packet)  

        self.sock.sendto(pickle.dumps(frame), ("127.0.0.1", hc_port))  

    @staticmethod
    def print_frame(frame: Frame):
        print(
          f"frame: {frame.data_length} bytes from {frame.src_mac} → {frame.dst_mac} | "
          f"packet: {frame.packet.data_length} bytes from {hex(frame.packet.src)} → {hex(frame.packet.dest)} - "
          f"protocol = {frame.packet.protocol}\n"
        )

    def run(self):
        print(
            f"[Router] Listening on {LISTENING_IP}:{ROUTER_LISTEN_PORT}\n"
            f"LAN1 (R1, IP=0x11) | LAN2 (R2, IP=0x21)\n"
        )

        try:
            while True:
                events = self.sel.select(timeout=None)
                for key, _ in events:
                    if key.data == "network":
                      data, _ = self.sock.recvfrom(1024)
                      frame = cast(Frame, pickle.loads(data))
                      self.handle_incoming_frame(frame)

        except KeyboardInterrupt:
            print("\n[Router] Caught keyboard interrupt, exiting.")
        finally:
            self.sel.close()

if __name__ == "__main__":
    router = Router()
    router.run()

