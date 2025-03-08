import socket
import time
import selectors
import sys
import pickle
from network import Frame, IPpacket
from typing import cast

# Node2 network details
LISTENING_IP = "127.0.0.1"
LISTENING_PORT = 50020

class Node2:
    def __init__(self, ip, mac_addr):
        self.ip = ip
        self.mac_addr = mac_addr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((LISTENING_IP, LISTENING_PORT))
        self.sock.setblocking(False)
        self.sel = selectors.DefaultSelector()

        self.sel.register(self.sock, selectors.EVENT_READ, data="network")
        self.sel.register(sys.stdin, selectors.EVENT_READ, data="input")
        # 0x1A -> R2 since we send it to Router to be routed to Node1
        self.arp_table = {0x1A: "R2", 0x2B: "N3", 0x11: "R1", 0x21: "R2"}

    def send_frame(self, rcving_node_ip, msg, hc_port, is_reply = False):
        if is_reply:
            packet = IPpacket(self.ip, rcving_node_ip, 0, msg, is_reply = True)
        else:
            packet = IPpacket(self.ip, rcving_node_ip, 0, msg)

        frame = Frame(self.mac_addr, self.arp_table[rcving_node_ip], packet)  
        self.sock.sendto(pickle.dumps(frame), ("127.0.0.1", hc_port))     
 

    def handle_incoming_frame(self, frame: Frame):
        if frame.dst_mac != self.mac_addr:
            print("Dropping frame")
            Node2.print_frame(frame)
            return

        print("Received:")
        Node2.print_frame(frame)

        # If the packet coming is a reply, we don't need to reply back to it  
        if frame.packet.is_reply:
           return

        # Else if its not a reply, let's reply and send the data back to the sender
        print(f"Replying to ping from {frame.src_mac}...\n")
        self.send_frame(frame.packet.src, frame.packet.data, 50030, True)
        self.send_frame(frame.packet.src, frame.packet.data, 50040, True)

    def ping(self, cmd: str):
        rcving_node_ip = int(cmd.split()[1], 16)
        msg = cmd.split()[2]
        count = int(cmd.split()[3])
          
        for _ in range(count):
            if(rcving_node_ip == 0x1A): # ping Node1
                self.send_frame(rcving_node_ip, msg, 50030) # send to Node3 -> Node3 will drop
                self.send_frame(rcving_node_ip, msg, 50040) # send to Router 
                time.sleep(1)
            elif(rcving_node_ip == 0x2B):
                self.send_frame(rcving_node_ip, msg, 50030) # send to Node3
                self.send_frame(rcving_node_ip, msg, 50040) # send to Router -> Router will drop
                time.sleep(1)
            elif rcving_node_ip in [0x11, 0x21]: # ping router
                self.send_frame(rcving_node_ip, msg, 50030) # send to Node3 -> Node3 will drop
                self.send_frame(rcving_node_ip, msg, 50040) # send to Router 
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
        print("To ping, type: ping <Destination IP> <Message> <Count>")
        print("Example: 'ping 0x1A Hello 5' (sends 5 'Hello's to Node1)")
        print("-------------------------------------------") 
          

    def run(self):
      Node2.print_menu()
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
                      if(cmd.split()[0] == "ping"): 
                        self.ping(cmd)

      except KeyboardInterrupt:
          print("\nCaught keyboard interrupt, exiting.")
      finally:
          self.sel.close()


if __name__ == "__main__":
    node = Node2(0x2A, "N2") # Initialise Node2 with emulation values
    node.run()
