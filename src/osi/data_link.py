# represents Data Link Layer

from datetime import datetime
from .network import *


def get_epoch(ts):
    return datetime.utcfromtimestamp(ts).strftime('%d-%m-%Y %H:%M:%S.%f')[:-3] + ' UTC'


def mac_format(mac):
    mac_str = map('{:02x}'.format, mac)
    return ':'.join(mac_str).upper()


class Frame:

    def __init__(self, index, ts, buffer):
        self.index = index
        self.timestamp = get_epoch(ts)
        self.api_len = len(buffer)
        self.phys_len = self.get_length()
        self.buffer = buffer

        self.dest_mac = None
        self.src_mac = None
        self.protocol = None
        self.frame_type = None
        self.ether_type = None

        # Object of encapsulated packet
        # self.pdu_l = None

        # Parsing
        self.get_dll()

    def __repr__(self):
        return c.RED + '\n# ------------ #\n' + '   Frame: ' + str(self.index) + '\n' \
               + '# ------------ #' + c.END + '\n' \
               + 'Timestamp: ' + self.timestamp + '\n' \
               + 'PCAP API Length: ' + str(self.api_len) + '\n' \
               + 'Physical Length: ' + str(self.phys_len) + '\n' \
               + 'DLL Protocol: ' + c.CYAN + self.frame_type + c.END + '\n' \
               + T0 + 'dst_MAC: ' + c.GREEN + mac_format(self.dest_mac) + c.END + '\n' \
               + T0 + 'src_MAC: ' + c.GREEN + mac_format(self.src_mac) + c.END + '\n' \
               + 'Network Protocol: ' + str(self.protocol) + '\n'

    def get_length(self):
        if self.api_len < 64:
            physical_len = 64
        else:
            physical_len = self.api_len + 4
        return physical_len

    def get_dll(self):
        self.dest_mac, self.src_mac, self.protocol = unpack('! 6s 6s H', self.buffer[:14])
        self.get_frame_type()# TODO change, no need to use 6s

    def get_frame_type(self):
        if self.protocol < 512:
            self.frame_type = 'IEEE Std 802.3 RAW or LLC or LLC + SNAP'
            self.get_8023_type()

        else:
            self.frame_type = 'Ethernet II'
            self.get_ether_type()

    def get_ether_type(self):
        # if self.protocol == 512:
        #     self.pdu_l = 'XEROX PUP'
        # elif self.protocol == 513:
        #     self.pdu_l = 'PUP Addr Trans'

        if self.protocol == 2048:
            self.protocol = IPv4(self.buffer[14:])

        # elif self.protocol == 2049:
        #     'X.75 Internet'
        # elif self.protocol == 2053:
        #     'X.25 Level 3'

        elif self.protocol == 2054:
            self.protocol = ARP()

        # elif self.protocol == 32821:
        #     'Reverse ARP'
        # elif self.protocol == 34525:
        #     'IPv6'

        elif self.protocol == 34958:
            self.protocol = StdX()
        elif self.protocol == 34984:
            self.protocol = StdSTag()
        elif self.protocol == 35015:
            self.protocol = StdI()
        elif self.protocol == 35020:
            self.protocol = StdAB()
        elif self.protocol == 36864:
            self.protocol = Loopback()
        else:
            self.protocol = 'Unknown --> ' + str(self.protocol)

    def get_8023_type(self):
        fff = unpack('! B', self.buffer[14:15])
        ff = '{:0x}'.format(fff[0]).upper()

        if ff == 'FF':
            self.frame_type = 'IEEE Std 802.3 RAW'
            self.protocol = c.CYAN + 'IPXX' + c.END
        elif ff == 'AA':
            self.frame_type = 'IEEE Std 802.3 LLC + SNAP'
            self.protocol = c.CYAN + 'SNAP' + c.END
        else:
            self.frame_type = 'IEEE Std 802.3 LLC'
            self.protocol = c.CYAN + '?!.!?' + c.END

    # def get_8023_pdu(self):
    #     return
