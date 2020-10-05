from struct import unpack
from src.color import Color as c

T0 = '    '


def ipv4_format(raw):
    return '.'.join(map(str, raw))


class IPv4:
    """
    not covering:   Type Of Service, ID, Flags, Fragment Offset, Header Checksum
                    ID: used when 2 and more Fragments are created (MTU > 1300)
    """

    name = 'IPv4'

    def __init__(self, buffer):
        self.buffer = buffer

        self.version = None
        self.header_len = None
        self.header_struct = '! 3x B 4x B B 2x 4s 4s'
        self.total_len = None
        self.ttl = None
        self.protocol = None
        self.src_ip = None
        self.dest_ip = None

        self.options = None
        self.opt_type = None
        self.opt_len = None
        self.opt_info = None

        self.pdu = None

        self.parse()

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'\
            + T0 + 'Header Length: ' + str(self.header_len) + '\n'\
            + T0 + 'Total Length: ' + str(self.total_len) + '\n'\
            + T0 + 'TTL: ' + str(self.ttl) + '\n'\
            + T0 + 'src_IP: ' + c.GREEN + ipv4_format(self.src_ip) + c.END + '\n'\
            + T0 + 'dst_IP: ' + c.GREEN + ipv4_format(self.dest_ip) + c.END + '\n'\
            + T0 + 'Options ' + self.options_str() + '\n'\
            + T0 + 'PDU: ' + c.PURPLE + self.pdu + c.END  # CHANGE according to PDU

    def options_str(self):
        if self.options is not None:
            return 'Type: ' + str(self.opt_type) + '\n'\
                + T0 + 'Options Length: ' + str(self.opt_len) + '\n'\
                + T0 + 'Info: ' + str(self.opt_info) + '\n'
        else:
            return 'Nan'

    def parse(self):
        v_h = self.buffer[0]  # version_header_len
        self.header_len = (v_h & 0b00001111) * 4

        if self.header_len > 20:
            bts = str(self.header_len - 20)
            self.header_struct = self.header_struct + ' ' + bts + 's'

            self.total_len, self.ttl, self.protocol, self.src_ip, self.dest_ip, self.options = \
                unpack(self.header_struct, self.buffer[:self.header_len])
            # self.buffer[self.header_len:]

            self.opt_type = self.options[0]
            self.opt_len = self.options[1]
            self.opt_info = self.options[2:].hex().upper()
        else:
            self.total_len, self.ttl, self.protocol, self.src_ip, self.dest_ip = \
                unpack(self.header_struct, self.buffer[:self.header_len])

        self.get_pdu()

    def get_pdu(self):
        if self.protocol == 1:  # ICMP
            self.pdu = 'ICMP'
        elif self.protocol == 2:  # IGMP
            self.pdu = 'IGMP'
        elif self.protocol == 6:  # TCP
            self.pdu = 'TCP'
        elif self.protocol == 9:  # IGRP
            self.pdu = 'IGRP'
        elif self.protocol == 17:  # UDP
            self.pdu = 'UDP'
        elif self.protocol == 47:  # GRE
            self.pdu = 'GRE'
        elif self.protocol == 50:  # ESP
            self.pdu = 'ESP'
        elif self.protocol == 51:  # AH
            self.pdu = 'AH'
        elif self.protocol == 57:  # AH
            self.pdu = 'SKIP'
        elif self.protocol == 88:  # EIGRP
            self.pdu = 'EIGRP'
        elif self.protocol == 89:  # OSPF
            self.pdu = 'OSPF'
        elif self.protocol == 115:  # L2TP
            self.pdu = 'L2TP'
        else:
            self.pdu = 'Unknown'


"""
    Add ICMP
"""