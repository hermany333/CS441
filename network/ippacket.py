from .tcpheader import TCPHeader

class IPpacket:
    def __init__(self, src: int, dest: int, protocol: int, data, is_reply=False):
        self.src = src
        self.dest = dest
        self.protocol = protocol

        if isinstance(data, TCPHeader):
            self.data_length = len(str(data.payload))  # or len(data.payload.encode()) for bytes
        else:
            self.data_length = len(str(data))

        self.is_reply = is_reply
        self.data = data # can be actual data or TCPHeader

    def __repr__(self):
        return (f"IPpacket({self.src} → {self.dest}, proto={self.protocol}, len={self.data_length}, data={self.data})")

    def get_len(self):
        if isinstance(self.data, TCPHeader):
            return 4 + self.data.get_len()
        else:
          return 4 + len(self.data)

