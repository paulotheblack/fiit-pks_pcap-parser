from dpkt import pcap
import struct
from datetime import datetime
from src.color import Color as c

# ----- Misc ----- #

T0 = '    '
T1 = '        '


def get_path():
    path = input('Please provide full path to desired .pcap to analyze: \n')
    return path


# Beware !- UTC -!
def get_epoch(ts):
    return datetime.utcfromtimestamp(ts).strftime('%d-%m-%Y %H:%M:%S.%f')[:-3] + ' UTC'


def read_pcap(path):
    f = open(path, 'rb')
    src = pcap.Reader(f)
    data = []
    buffer_cpy = []

    for index, [ts, buf] in enumerate(src):
        # List of dictionaries
        data.append({
            'index': index + 1,  # to correlate with Wireshark indexing
            'ts': ts,
            'buf': buf
        })
        buffer_cpy.append(buf)

    return data, buffer_cpy


def petit_print(buffer):
    print()
    for i in range(1, len(buffer) + 1):
        print(f'{buffer[i - 1:i].hex().upper()}', end='')
        if i % 16 == 0:
            print('\n', end='')
        elif i % 8 == 0:
            print('   ', end='')
        else:
            print(' ', end='')
    print()


# TODO print buffer_copy at the end
def test_print(src, buffer_copy):
    for packet in src:
        # PCAP API
        print(c.RED + '\n# ------- #')
        print('Frame: ' + str(packet['index']) + c.END)
        print('Timestamp: ' + get_epoch(packet['ts']))
        print('PCAP API Length: ' + str(len(packet['buf'])))
        print('Physical Length: ' + str(len(packet['buf']) + 4))
        # ANALYZER
        get_frame(packet['buf'])
        petit_print(buffer_copy[packet['index'] - 1])


# ----- Formatting ----- #
# Done!
def mac_format(mac):
    mac_str = map('{:02x}'.format, mac)
    mac_addr = ':'.join(mac_str).upper()
    return mac_addr


# Done!
def ipv4_format(ipv4_raw):
    return '.'.join(map(str, ipv4_raw))


# ------ Frames processing ----- #
def get_frame(packet):
    dest_mac, src_mac, prtcl = struct.unpack('! 6s 6s H', packet[:14])
    print(f'{T0} dst_MAC: {c.GREEN} {mac_format(dest_mac)} {c.END}\n'
          f'{T0} src_MAC: {c.GREEN} {mac_format(src_mac)} {c.END}')
    frame_type(prtcl, packet[14:])


# Ethernet II   [dest][src][EtherType]
# 802.3         [dest][src][Length]
def frame_type(p, buf):
    # p == protocol received
    # t == type (802.3 RAW, 802.3 LLC, Ethernet II)

    if p < 512:
        t = 'IEEE Std 802.3 RAW or LLC + SNAP'
        if p < 256:
            t = 'IEEE 802.3 LLC'
        print(c.CYAN + t + c.END)
        analyze_8023(p, buf)
    else:
        t = 'Ethernet II'
        print(c.CYAN + t + c.END)
        eth_type(p, buf)


# ----- Ethernet II processing ----- #
def eth_type(p, buf):
    if p == 512:
        t = 'XEROX PUP'
        print(c.CYAN + 'EtherType: ' + t + c.END)
    elif p == 513:
        t = 'PUP Addr Trans'
        print(c.CYAN + 'EtherType: ' + t + c.END)

    elif p == 2048:
        t = 'IPv4'
        ipv4(buf)

    elif p == 2049:
        t = 'X.75 Internet'
        print(c.CYAN + 'EtherType: ' + t + c.END)
    elif p == 2053:
        t = 'X.25 Level 3'
        print(c.CYAN + 'EtherType: ' + t + c.END)
    elif p == 2054:
        t = 'ARP'  # TODO
        print(c.CYAN + 'EtherType: ' + t + c.END)
    elif p == 32821:
        t = 'Reverse ARP'
        print(c.CYAN + 'EtherType: ' + t + c.END)
    elif p == 34525:
        t = 'IPv6'  # TODO
        print(c.CYAN + 'EtherType: ' + t + c.END)
    elif p == 34958:
        t = 'IEEE Std 802.1X'
        print(c.CYAN + 'EtherType: ' + t + c.END)
    elif p == 34984:
        t = 'IEEE Std 802.1Q (S-Tag)'
        print(c.CYAN + 'EtherType: ' + t + c.END)
    elif p == 35015:
        t = 'IEEE Std 802.11i (pre-Auth)'
        print(c.CYAN + 'EtherType: ' + t + c.END)
    elif p == 35020:
        t = 'IEEE Std 802.1AB (LLDP)'  # TODO
        print(c.CYAN + 'EtherType: ' + t + c.END)
    elif p == 36864:
        t = 'Loopback'
        print(c.CYAN + 'EtherType: ' + t + c.END)
    else:
        t = f'Unknown --> {p}'
        print(c.CYAN + 'EtherType: ' + t + c.END)


def ipv4(buf):
    """
    not covering:   Type Of Service, ID, Flags, Fragment Offset, Header Checksum
                    ID: used when 2 and more Fragments are created (MTU > 1300)

    if header_len > 20:
        Options field is being used
        example: trace-26.eth -> frame: 98
    """
    info = buf[0]
    version = info >> 4
    header_len = (info & 0b00001111) * 4
    header_struct = '! 3x B 4x B B 2x 4s 4s'

    if header_len > 20:
        bts = str(header_len - 20)
        header_struct = header_struct + bts + 's'
        total_len, ttl, protocol, src_ip, dest_ip, options = struct.unpack(header_struct, buf[:header_len])

        options = f'Type: {options[0]}\n' \
                  f'{T0} Options Length: {options[1]}\n' \
                  f'{T0} Info: {options[2:].hex().upper()}'

    else:
        options = 'NaN'
        total_len, ttl, protocol, src_ip, dest_ip = struct.unpack(header_struct, buf[:header_len])

    print(f'{c.CYAN}EtherType:  IPv4 {c.END}\n'
          # f'{T0} Version: {version}\n'
          f'{T0} Header length: {header_len}\n'
          f'{T0} Total length: {total_len}\n'
          f'{T0} TTL: {ttl}\n'
          f'{T0} Protocol: {c.PURPLE}{get_ip_prtcl(protocol)} {c.END}\n'
          f'{T0} Source: {c.GREEN} {ipv4_format(src_ip)} {c.END}\n'
          f'{T0} Destination: {c.GREEN} {ipv4_format(dest_ip)} {c.END}\n'
          f'{T0} Options {options}')


# ----- IPv4 protocols processing ----- #
def get_ip_prtcl(p):
    if p == 1:
        p = 'ICMP'
        # TODO def_icmp()
    elif p == 2:
        p = 'IGMP'
    elif p == 6:
        p = 'TCP'
        # TODO def_tcp()
    elif p == 9:
        p = 'IGRP'
    elif p == 17:
        p = 'UDP'
        # TODO def_udp()
    elif p == 47:
        p = 'GRE'
    elif p == 50:
        p = 'ESP'
    elif p == 51:
        p = 'AH'
    elif p == 57:
        p = 'SKIP'
    elif p == 88:
        p = 'EIGRP'
    elif p == 89:
        p = 'OSPF'
    elif p == 115:
        p = 'L2TP'
    return p


# ----- 802.3 processing ----- #
def analyze_8023(p, buf):
    return 0
