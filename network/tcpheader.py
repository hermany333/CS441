class TCPHeader:
    def __init__(self, src_port, dst_port, payload=""):
        self.src_port = src_port
        self.dst_port = dst_port
        self.payload = payload  # the actual app data

    def __repr__(self):
        return (f"TCP(src_port={self.src_port}, dst_port={self.dst_port}, payload={self.payload}")
                

    def get_len(self):
        return 20
