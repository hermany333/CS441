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
                0x1A: "R2", 0x2B: "N2", 0x11: "R1", 0x21: "R2"
            },
            targets=[50020, 50040]
        )


if __name__ == "__main__":
    node = Node3(0x2B, "N3") # Initialise Node2 with emulation values
    node.run()
