class IPpacket:
    def __init__(self, src: int, dest: int, protocol: int, data, is_reply=False):
        self.src = src
        self.dest = dest
        self.protocol = protocol
        self.data_length = len(data)
        self.data = data
        self.is_reply = is_reply

    def __repr__(self):
        return (f"IPpacket({self.src} → {self.dest}, proto={self.protocol}, len={self.data_length}, data={self.data})")

    def get_len(self):
      # src + dest + protocol + dataLength + data_length
      return 4 + len(self.data)
