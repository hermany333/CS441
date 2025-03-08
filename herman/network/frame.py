from .ippacket import IPpacket

class Frame:
  def __init__(self, src_mac: str, dst_mac: str, packet: IPpacket):
    self.src_mac = src_mac
    self.dst_mac = dst_mac
    self.data_length = 5 + packet.get_len()
    self.packet = packet;

    def __repr__(self):
        return f"Frame({self.src_mac} → {self.dest_mac}, len={self.data_length}, data={self.data})"
