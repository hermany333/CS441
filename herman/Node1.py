from Node import Node

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

if __name__ == "__main__":
    node = Node1(0x1A, "N1") # Initialise Node1 with emulation values
    node.run()
