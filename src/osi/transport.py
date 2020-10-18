# represents Transport Layer

from struct import unpack
from src.color import Color as c


class ICMP:
    name = 'ICMP'

    def __init__(self, buffer, consts):
        self.buffer = buffer
        self.consts = consts

        self.type = None
        self.code = None
        self.identifier = None
        self.sequence = None
        self.details = None

        self.parse()

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'\
            + '\t' + 'Type: ' + str(self.type) + '\n'\
            + '\t' + 'Code: ' + str(self.code) + '\n'\
            + '\t' + 'Details: ' + c.PURPLE + str(self.details) + c.END + '\n'\
            + '\t' + 'Identifier: ' + str(self.identifier) + '\n'\
            + '\t' + 'Sequence: ' + str(self.sequence)

    def parse(self):
        self.type, self.code, self.identifier, self.sequence = unpack('! B B 2x H H', self.buffer[:8])

        for icmp_type in self.consts['ICMP']:
            if icmp_type['type'] == self.type:
                self.details = icmp_type['name']


class IGMP:
    name = 'IGMP'

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'\
            + c.YELLOW + '--> TODO' + c.END


class TCP:

    name = 'TCP'

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

        self.f_ack = False
        self.f_rst = False
        self.f_syn = False
        self.f_fin = False

        self.parse()

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'\
            + '\t' + 'src_Port: ' + c.GREEN + str(self.src_port) + c.END + '\n'\
            + '\t' + 'dst_Port: ' + c.GREEN + str(self.dest_port) + c.END + '\n'\
            + '\t' + 'Seq No.: ' + str(self.seq_num) + '\n'\
            + '\t' + 'ACK No.: ' + str(self.ack_num) + '\n'\
            + '\t' + 'Flags: ' + str(self.flags) + '\n'\
            + '\t\t' + 'ACK: ' + str(self.f_ack) + '\n'\
            + '\t\t' + 'RST: ' + str(self.f_rst) + '\n'\
            + '\t\t' + 'SYN: ' + str(self.f_syn) + '\n'\
            + '\t\t' + 'FIN: ' + str(self.f_fin) + '\n'\
            + 'Data type: ' + c.PURPLE + str(self.data_type) + c.END

    def parse(self):
        self.src_port, self.dest_port, self.seq_num, self.ack_num\
            = unpack('!H H L L', self.buffer[:12])  # last == off_res_flags

        self.get_flags()
        self.get_data_type()

    def get_data_type(self):
        for prtcl in self.consts['TCP']:
            if prtcl['port'] == self.src_port:
                self.data_type = prtcl['name']

            elif prtcl['port'] == self.dest_port:
                self.data_type = prtcl['name']

            if self.data_type is None:
                self.data_type = 'Unknown'

    def get_flags(self):
        self.flags = unpack('! b', self.buffer[13:14])[0] & 0b00111111

        if (self.flags >> 4) & 1:
            self.f_ack = True

        if (self.flags >> 2) & 1:
            self.f_rst = True

        if (self.flags >> 1) & 1:
            self.f_syn = True

        if self.flags & 1:
            self.f_fin = True


class UDP:

    name = 'UDP'

    # ports to analyze:
    def __init__(self, buffer, consts):
        self.buffer = buffer
        self.consts = consts

        self.src_port = None
        self.dest_port = None
        self.len = None
        self.payload = None
        self.data_type = None

        self.parse()

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'\
            + '\t' + 'src_Port: ' + c.GREEN + str(self.src_port) + c.END + '\n'\
            + '\t' + 'dst_Port: ' + c.GREEN + str(self.dest_port) + c.END + '\n'\
            + '\t' + 'Length: ' + str(self.len) + ' B\n'\
            + '\t' + 'Data type: ' + c.PURPLE + str(self.data_type) + c.END

    # TODO ports are stored as int values ... no-conversion pls
    def parse(self):
        self.src_port, self.dest_port, self.len = unpack('!H H H 2x', self.buffer[:8])
        self.get_data_type()

    def get_data_type(self):
        for prtcl in self.consts['UDP']:
            if prtcl['port'] == self.src_port:
                self.data_type = prtcl['name']

            elif prtcl['port'] == self.dest_port:
                self.data_type = prtcl['name']

            if self.data_type is None:
                self.data_type = 'Unknown'
