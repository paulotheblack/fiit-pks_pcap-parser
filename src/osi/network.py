# represents Network Layer

from .transport import *


def mac_format(mac):
    mac_str = map('{:02x}'.format, mac)
    return ':'.join(mac_str).upper()


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
               + '\t' + 'Header Length: ' + str(self.header_len) + ' B\n' \
               + '\t' + 'Total Length: ' + str(self.total_len) + ' B\n' \
               + '\t' + 'TTL: ' + str(self.ttl) + '\n' \
               + '\t' + 'src_IP: ' + c.GREEN + ipv4_format(self.src_ip) + c.END + '\n' \
               + '\t' + 'dst_IP: ' + c.GREEN + ipv4_format(self.dest_ip) + c.END + '\n' \
               + '\t' + 'Options ' + self.get_options_str() + '\n' \
               + 'Transport Protocol: ' + str(self.trans_protocol)

    def get_options_str(self):
        if self.options is not None:
            return 'Type: ' + str(self.opt_type) + '\n'\
                + '\t' + 'Options Length: ' + str(self.opt_len) + '\n'\
                + '\t' + 'Info: ' + str(self.opt_info.hex().upper())
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
                # elif ip['name'] == 'IGMP':
                #     self.trans_protocol = IGMP()
                elif ip['name'] == 'TCP':
                    self.trans_protocol = TCP(self.buffer[self.header_len:], self.consts)
                elif ip['name'] == 'UDP':
                    self.trans_protocol = UDP(self.buffer[self.header_len:], self.consts)
                else:
                    self.trans_protocol = c.RED + ip['name'] + c.END


class ARP:
    name = 'ARP'

    def __init__(self, buffer, consts):
        self.buffer = buffer
        self.consts = consts

        self.htype = None  # Hardware Type (2)
        self.ptype = None  # Protocol Type (2)
        self.hlen = None  # Hardware address length (1)
        self.plen = None  # Protocol address length (1)
        self.oper = None  # Operation (2)
        self.type = None  # Operation message 1 == Request ; 2 == Reply
        self.sha = None  # Src/ Sender hardware address (6) [MAC]
        self.spa = None  # Src/ Sender protocol address (4) [IP]
        self.tha = None  # Dest/ Target hardware address (6) [MAC]
        self.tpa = None  # Dest/ Target protocol address (4) [IP]

        self.parse()

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'\
            + '\t' + 'Hardware Type: ' + c.PURPLE + str(self.htype) + c.END + '\n'\
            + '\t' + 'Protocol Type: ' + c.PURPLE + str(self.ptype) + c.END + '\n'\
            + '\t' + 'Hardware Address Len: ' + str(self.hlen) + '\n'\
            + '\t' + 'Protocol Address Len: ' + str(self.plen) + '\n'\
            + '\t' + 'Operation: ' + c.PURPLE + str(self.oper) + c.END + '\n'\
            + '\t' + 'OP Type: ' + c.PURPLE + str(self.type) + c.END + '\n'\
            + '\t' + 'Sender MAC: ' + c.GREEN + mac_format(self.sha) + c.END + '\n'\
            + '\t' + 'Sender IP:  ' + c.GREEN + ipv4_format(self.spa) + c.END + '\n'\
            + '\t' + 'Target MAC: ' + c.GREEN + mac_format(self.tha) + c.END + '\n'\
            + '\t' + 'Target IP:  ' + c.GREEN + ipv4_format(self.tpa) + c.END

    def parse(self):
        self.htype, self.ptype, self.hlen, self.plen, self.oper,\
            self.sha, self.spa, self.tha, self.tpa\
            = unpack('!H H B B H 6s 4s 6s 4s', self.buffer[:28])

        # HTYPE
        if self.htype == 1:
            self.htype = 'Ethernet (1)'

        # PROTOCOL TYPE
        if self.ptype == 2048:
            self.ptype = 'IPv4'

        # OPERATION CODE
        if self.oper == 1:
            self.type = 'Request'
        elif self.oper == 2:
            self.type = 'Reply'
        else:
            self.type = 'Unknown'


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
