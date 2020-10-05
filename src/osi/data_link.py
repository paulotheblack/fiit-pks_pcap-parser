# represents Data Link Layer and its PDUs
from datetime import datetime
from struct import unpack

from src.color import Color as c

from .network import IPv4

T0 = '    '


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
        self.pdu = None
        # Parsing
        self.get_dll()

    # TODO Frame formatted print
    def __repr__(self):
        return c.RED + '\n# ------------ #\n' + '#  Frame: ' + str(self.index) + '  #\n'\
            + '# ------------ #' + c.END + '\n'\
            + 'Timestamp: ' + self.timestamp + '\n'\
            + 'PCAP API Length: ' + str(self.api_len) + '\n'\
            + 'Physical Length: ' + str(self.phys_len) + '\n'\
            + c.CYAN + self.frame_type + c.END + '\n'\
            + T0 + 'dst_MAC: ' + c.GREEN + self.dest_mac + c.END + '\n'\
            + T0 + 'src_MAC: ' + c.GREEN + self.src_mac + c.END + '\n'\
            + str(self.pdu) + '\n'

    def get_length(self):
        if self.api_len < 64:
            physical_len = 64
        else:
            physical_len = self.api_len + 4
        return physical_len

    def get_dll(self):
        dest_mac, src_mac, self.protocol = unpack('! 6s 6s H', self.buffer[:14])
        self.dest_mac = mac_format(dest_mac)
        self.src_mac = mac_format(src_mac)

        self.get_frame_type()

    # TODO get frame types correctly Task-1
    def get_frame_type(self):
        if self.protocol < 512:
            self.frame_type = 'IEEE Std 802.3 RAW or LLC or LLC + SNAP'
            self. protocol = '802.3 length'

            self.pdu = '802.3 - Nan'
        else:
            self.frame_type = 'Ethernet II'
            self.get_ether_type()

    # ?? create etherII % 802.3
    def get_ether_type(self):
        if self.protocol == 512:
            self.pdu = 'XEROX PUP'
        elif self.protocol == 513:
            self.pdu = 'PUP Addr Trans'

        elif self.protocol == 2048:
            self.ether_type = 'IPv4'
            self.pdu = IPv4(self.buffer[14:])

        elif self.protocol == 2049:
            self.pdu = 'X.75 Internet'
        elif self.protocol == 2053:
            self.pdu = 'X.25 Level 3'
        elif self.protocol == 2054:
            self.pdu = 'ARP'  # TODO
        elif self.protocol == 32821:
            self.pdu = 'Reverse ARP'
        elif self.protocol == 34525:
            self.pdu = 'IPv6'  # TODO
        elif self.protocol == 34958:
            self.pdu = 'IEEE Std 802.1X'
        elif self.protocol == 34984:
            self.pdu = 'IEEE Std 802.1Q (S-Tag)'
        elif self.protocol == 35015:
            self.pdu = 'IEEE Std 802.11i (pre-Auth)'
        elif self.protocol == 35020:
            self.pdu = 'IEEE Std 802.1AB (LLDP)'
        elif self.protocol == 36864:
            self.pdu = 'Loopback'
        else:
            self.pdu = 'Unknown --> '
