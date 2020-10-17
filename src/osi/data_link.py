# represents Data Link Layer

from datetime import datetime
from .network import *


def get_epoch(ts):
    return datetime.utcfromtimestamp(ts).strftime('%d-%m-%Y %H:%M:%S.%f')[:-3] + ' UTC'


class Frame:

    def __init__(self, index, ts, buffer, consts):
        self.index = index
        self.timestamp = get_epoch(ts)
        self.api_len = len(buffer)
        self.phys_len = self.get_length()
        self.buffer = buffer
        self.consts = consts  # .yaml constants to analyze !!

        self.dest_mac = None
        self.src_mac = None
        self.net_protocol = None
        self.frame_type = None
        self.ether_type = None

        self.parse()

    def __repr__(self):
        return c.RED + '\n# ------------ #\n' + '   Frame: ' + str(self.index) + '\n' \
               + '# ------------ #' + c.END + '\n' \
               + 'Timestamp: ' + self.timestamp + '\n' \
               + 'PCAP API Length: ' + str(self.api_len) + ' B\n' \
               + 'Physical Length: ' + str(self.phys_len) + ' B\n' \
               + 'DLL Protocol: ' + c.CYAN + self.frame_type + c.END + '\n' \
               + '\t' + 'dst_MAC: ' + c.GREEN + mac_format(self.dest_mac) + c.END + '\n' \
               + '\t' + 'src_MAC: ' + c.GREEN + mac_format(self.src_mac) + c.END + '\n' \
               + 'Network Protocol: ' + str(self.net_protocol) + '\n'

    def get_length(self):
        if self.api_len <= 60:
            physical_len = 64
        else:
            physical_len = self.api_len + 4
        return physical_len

    def parse(self):
        self.dest_mac, self.src_mac, self.net_protocol = unpack('! 6s 6s H', self.buffer[:14])

        if self.net_protocol < 512:
            self.frame_type = 'IEEE Std 802.3 LLC'
            self.get_8023_type()
        else:
            self.frame_type = 'Ethernet II'
            self.get_ether_type()

    def get_ether_type(self):
        # search for protocol
        for et in self.consts['Ethertype']:
            if et['addr'] == self.net_protocol:
                if et['name'] == 'IPv4':
                    self.net_protocol = IPv4(self.buffer[14:], self.consts)
                elif et['name'] == 'ARP':
                    self.net_protocol = ARP(self.buffer[14:], self.consts)
                else:
                    self.net_protocol = c.RED + et['name'] + c.END

    def get_8023_type(self):
        sap = unpack('! c', self.buffer[14:15])
        sap = sap[0].hex().upper()

        for std in self.consts['SAP']:
            if sap == std['addr']:
                sap = std['name']
                self.frame_type = self.frame_type + ' + ' + c.RED + std['name'] + c.END
                self.net_protocol = c.RED + 'Unknown' + c.END

                if sap == 'IPXX':
                    self.frame_type = 'IEEE Std 802.3 RAW'
                    self.net_protocol = c.RED + 'IPXX' + c.END

                # Search for nested SNAP Ethertype
                if sap == 'SNAP':
                    # SNAP Header
                    vendor_code, ethertype = unpack('! 3s H', self.buffer[17:22])

                    for et in self.consts['Ethertype']:
                        if ethertype == et['addr']:
                            self.net_protocol = c.RED + et['name'] + c.END
                        else:
                            self.net_protocol = c.RED + 'Nested Ethertype ' + str(ethertype) + c.END
