# represents Transport Layer

from struct import unpack
from src.color import Color as c


class ICMP:
    name = 'ICMP'

    # [  1  ][  1 ][     2   ][              4            ]
    # [type][code][checksum][ other message-specific-info ]
    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'\
            + c.YELLOW + '--> TODO' + c.END


class IGMP:
    name = 'IGMP'

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'\
            + c.YELLOW + '--> TODO' + c.END


class TCP:

    name = 'TCP'

    # ports to analyze:
    # 80 == HTTP data
    # 443 == HTTPs data
    # 21 == FTP
    # 22 == SSH
    def __init__(self, buffer):
        self.src_port = None
        self.dest_port = None
        self.seq_num = None
        self.ack_num = None
        self.data_off = None
        self.flags = None
        # TODO implement Flags
        self.buffer = buffer

        self.parse()

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'\
            + '\t' + 'src_Port: ' + c.GREEN + str(self.src_port) + c.END + '\n'\
            + '\t' + 'dst_Port: ' + c.GREEN + str(self.dest_port) + c.END + '\n'\
            + '\t' + 'Seq No.: ' + str(self.seq_num) + '\n'\
            + '\t' + 'ACK No.: ' + str(self.ack_num) + '\n'\
            + '\t' + 'Flags: ' + str(self.flags)

    def parse(self):
        self.src_port, self.dest_port, self.seq_num, self.ack_num, self.flags\
            = unpack('!H H L L H', self.buffer[:14])  # last == off_res_flags
        # TODO parse off, res, flags


class UDP:

    name = 'UDP'

    # ports to analyze:
    def __init__(self, buffer):
        self.src_port = None
        self.dest_port = None
        self.len = None  # means header + payload
        self.buffer = buffer
        self.payload = None

        self.parse()

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'\
            + '\t' + 'src_Port: ' + c.GREEN + str(self.src_port) + c.END + '\n'\
            + '\t' + 'dst_Port: ' + c.GREEN + str(self.dest_port) + c.END + '\n'\
            + '\t' + 'Length: ' + str(self.len)

    # TODO ports are stored as int values ... no-conversion pls
    def parse(self):
        self.src_port, self.dest_port, self.len = unpack('!H H H 2x', self.buffer[:8])
