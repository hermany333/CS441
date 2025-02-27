import socket
import selectors
import sys
import pickle
from network import Frame, IPpacket
from typing import cast

# Node3 network details
listening_ip = "127.0.0.1"
port = 50030

class Node3:
    def __init__(self, ip, mac_addr):
        self.ip = ip
        self.mac_addr = mac_addr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((listening_ip, port))
        self.sock.setblocking(False)
        self.sel = selectors.DefaultSelector()

        self.sel.register(self.sock, selectors.EVENT_READ, data="network")
        self.sel.register(sys.stdin, selectors.EVENT_READ, data="input")

    def send_frame(self, cmd):
        rcving_node = cmd.split()[0]
        data = cmd.split()[1]

        if(rcving_node == "N2"):
          n2_packet = IPpacket(0x2B, 0x2A, 0, data)
          n2_frame = Frame("N3", "N2", n2_packet)  
          self.sock.sendto(pickle.dumps(n2_frame), ("127.0.0.1", 50020))
        elif(rcving_node == "N1"):
          # broadcast to router and N2
          pass
        else:
          print(f"{rcving_node} does not exist!")

    
    def handle_incoming_frame(self, frame: Frame):
        ## logic to drop frames 
        print("Received:")
        Node3.print_frame(frame)

 
    def parse_frame(self):
        return 0

    @staticmethod
    def print_frame(frame: Frame):
        print(
          f"frame: {frame.data_length} bytes from {frame.src_mac} → {frame.dst_mac} | "
          f"packet: {frame.packet.data_length} bytes from {hex(frame.packet.src)} → {hex(frame.packet.dest)} - "
          f"proto = {frame.packet.protocol}"
        )

    @staticmethod
    def print_menu():
        print("\n[-- What would you like to do? --]")
        print("Type 'exit' to quit.")
        print("To send a frame, type: <destination MAC> <message>")
        print("Example: 'N1 Hello' (sends 'Hello' to Node1)")
        print("-------------------------------------------") 
          

    def run(self):
      print(f"[{self.mac_addr}] Listening on {listening_ip}:{port}")

      Node3.print_menu()
      try:
          while True:
              events = self.sel.select(timeout=None)
              for key, _ in events:
                  if key.data == "network":

                      data, _ = self.sock.recvfrom(1024)
                      frame = cast(Frame, pickle.loads(data))
                      self.handle_incoming_frame(frame);

                  elif key.data == "input":

                      cmd = sys.stdin.readline().strip()
                      self.send_frame(cmd)

      except KeyboardInterrupt:
          print("\nCaught keyboard interrupt, exiting.")
      finally:
          self.sel.close()


if __name__ == "__main__":
    node = Node3(0x2B, "N3") # Initialise Node2 with emulation values
    node.run()
