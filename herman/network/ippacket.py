class IPpacket:
  def __init__(self, src: int, dest: int, protocol: int, data):
    self.src = src
    self.dest = dest
    self.protocol = protocol
    self.data_length = 9
    self.data = data

  def __repr__(self):
        return f"IPpacket({self.src} → {self.dest}, proto={self.protocol} len={self.data_length}, data={self.data})" 
