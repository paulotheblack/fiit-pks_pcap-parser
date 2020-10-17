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
    def __init__(self, buffer, consts):
        self.buffer = buffer
        self.consts = consts

        self.src_port = None
        self.dest_port = None
        self.seq_num = None
        self.ack_num = None
        self.data_off = None
        self.flags = None
        self.data_type = None
        # TODO implement Flags


        self.parse()

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'\
            + '\t' + 'src_Port: ' + c.GREEN + str(self.src_port) + c.END + '\n'\
            + '\t' + 'dst_Port: ' + c.GREEN + str(self.dest_port) + c.END + '\n'\
            + '\t' + 'Seq No.: ' + str(self.seq_num) + '\n'\
            + '\t' + 'ACK No.: ' + str(self.ack_num) + '\n'\
            + '\t' + 'Flags: ' + str(self.flags) + '\n'\
            + '\t' + 'Data type: ' + c.CYAN + str(self.data_type) + c.END

    def parse(self):
        self.src_port, self.dest_port, self.seq_num, self.ack_num, self.flags\
            = unpack('!H H L L H', self.buffer[:14])  # last == off_res_flags

        self.get_data_type()

    def get_data_type(self):
        for prtcl in self.consts['tcp']:
            if prtcl['port'] == self.src_port:
                self.data_type = prtcl['name']

            elif prtcl['port'] == self.dest_port:
                self.data_type = prtcl['name']

            elif prtcl['port'] is not self.src_port or self.dest_port:
                self.data_type = 'Unknown'


class UDP:

    name = 'UDP'

    # ports to analyze:
    def __init__(self, buffer, consts):
        self.buffer = buffer
        self.consts = consts

        self.src_port = None
        self.dest_port = None
        self.len = None  # means header + payload
        self.payload = None
        self.data_type = None

        self.parse()

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'\
            + '\t' + 'src_Port: ' + c.GREEN + str(self.src_port) + c.END + '\n'\
            + '\t' + 'dst_Port: ' + c.GREEN + str(self.dest_port) + c.END + '\n'\
            + '\t' + 'Length: ' + str(self.len) + '\n'\
            + '\t' + 'Data type: ' + c.CYAN + str(self.data_type) + c.END

    # TODO ports are stored as int values ... no-conversion pls
    def parse(self):
        self.src_port, self.dest_port, self.len = unpack('!H H H 2x', self.buffer[:8])
        self.get_data_type()

    def get_data_type(self):
        for prtcl in self.consts['udp']:
            if prtcl['port'] == self.src_port:
                self.data_type = prtcl['name']

            elif prtcl['port'] == self.dest_port:
                self.data_type = prtcl['name']

            elif prtcl['port'] is not self.src_port or self.dest_port:
                self.data_type = 'Unknown'
