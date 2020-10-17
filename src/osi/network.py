# represents Network Layer

from .transport import *


def ipv4_format(raw):
    return '.'.join(map(str, raw))


class IPv4:
    """
    not covering:   Type Of Service, ID, Flags, Fragment Offset, Header Checksum
    """
    name = 'IPv4'

    def __init__(self, buffer, consts):
        self.buffer = buffer
        self.consts = consts

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
               + '\t' + 'Header Length: ' + str(self.header_len) + 'B\n' \
               + '\t' + 'Total Length: ' + str(self.total_len) + 'B\n' \
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
            self.opt_info = self.options[2:]
        else:
            self.total_len, self.ttl, self.trans_protocol, self.src_ip, self.dest_ip = \
                unpack(self.header_struct, self.buffer[:self.header_len])

        self.get_prtcl()

    def get_prtcl(self):
        for ip in self.consts['IP']:
            if ip['addr_dec'] == self.trans_protocol:
                if ip['name'] == 'ICMP':
                    self.trans_protocol = ICMP(self.buffer[self.header_len:], self.consts)
                elif ip['name'] == 'IGMP':
                    self.trans_protocol = IGMP()
                elif ip['name'] == 'TCP':
                    self.trans_protocol = TCP(self.buffer[self.header_len:], self.consts)
                elif ip['name'] == 'UDP':
                    self.trans_protocol = UDP(self.buffer[self.header_len:], self.consts)
                else:
                    self.trans_protocol = 'Unknown: ' + str(self.trans_protocol)

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
