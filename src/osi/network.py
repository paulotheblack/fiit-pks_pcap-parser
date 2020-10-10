# represents Network Layer

from .transport import *


def ipv4_format(raw):
    return '.'.join(map(str, raw))


class IPv4:
    """
    not covering:   Type Of Service, ID, Flags, Fragment Offset, Header Checksum
    """
    name = 'IPv4'

    def __init__(self, buffer):
        self.buffer = buffer

        self.version = None
        self.header_len = None
        self.total_len = None
        self.ttl = None
        self.trans_protocol = None
        self.src_ip = None
        self.dest_ip = None

        self.options = None
        self.opt_type = None
        self.opt_len = None
        self.opt_info = None

        self.header_struct = '! 3x B 4x B B 2x 4s 4s'
        self.parse()

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n' \
               + '\t' + 'Header Length: ' + str(self.header_len) + '\n' \
               + '\t' + 'Total Length: ' + str(self.total_len) + '\n' \
               + '\t' + 'TTL: ' + str(self.ttl) + '\n' \
               + '\t' + 'src_IP: ' + c.GREEN + ipv4_format(self.src_ip) + c.END + '\n' \
               + '\t' + 'dst_IP: ' + c.GREEN + ipv4_format(self.dest_ip) + c.END + '\n' \
               + '\t' + 'Options ' + self.get_options_str() + '\n' \
               + 'Transport Protocol: ' + str(self.trans_protocol)

    def get_options_str(self):
        if self.options is not None:
            return 'Type: ' + str(self.opt_type) + '\n'\
                + '\t' + 'Options Length: ' + str(self.opt_len) + '\n'\
                + '\t' + 'Info: ' + str(self.opt_info)
        else:
            return 'Nan'

    def parse(self):
        v_h = self.buffer[0]  # version_header_len
        self.header_len = (v_h & 0b00001111) * 4

        if self.header_len > 20:
            bts = str(self.header_len - 20)
            self.header_struct = self.header_struct + ' ' + bts + 's'

            self.total_len, self.ttl, self.trans_protocol, self.src_ip, self.dest_ip, self.options = \
                unpack(self.header_struct, self.buffer[:self.header_len])

            self.opt_type = self.options[0]
            self.opt_len = self.options[1]
            self.opt_info = self.options[2:].hex().upper()
        else:
            self.total_len, self.ttl, self.trans_protocol, self.src_ip, self.dest_ip = \
                unpack(self.header_struct, self.buffer[:self.header_len])

        self.get_prtcl()

    def get_prtcl(self):
        if self.trans_protocol == 1:  # ICMP
            self.trans_protocol = ICMP()
        elif self.trans_protocol == 2:  # IGMP
            self.trans_protocol = IGMP()
        elif self.trans_protocol == 6:  # TCP
            self.trans_protocol = TCP(self.buffer[self.header_len:])

        # elif self.protocol == 9:  # IGRP
        #     self.protocol = 'IGRP'

        elif self.trans_protocol == 17:  # UDP
            self.trans_protocol = UDP(self.buffer[self.header_len:])

        # elif self.protocol == 47:  # GRE
        #     self.protocol = 'GRE'
        # elif self.protocol == 50:  # ESP
        #     self.protocol = 'ESP'
        # elif self.protocol == 51:  # AH
        #     self.protocol = 'AH'
        # elif self.protocol == 57:  # AH
        #     self.protocol = 'SKIP'
        # elif self.protocol == 88:  # EIGRP
        #     self.protocol = 'EIGRP'
        # elif self.protocol == 89:  # OSPF
        #     self.protocol = 'OSPF'
        # elif self.protocol == 115:  # L2TP
        #     self.protocol = 'L2TP'
        else:
            self.trans_protocol = 'Unknown'


# TODO -> <- communication:: TASK 4
class ARP:
    name = 'ARP'

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'


class Loopback:
    name = 'Loopback'

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'


class StdX:
    name = 'IEEE Std 802.1X'

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'


class StdSTag:
    name = 'IEEE Std 802.1Q (S-Tag)'

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'


class StdI:
    name = 'IEEE Std 802.11i (pre-Auth)'

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'


class StdAB:
    name = 'IEEE Std 802.1AB (LLDP)'

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'
