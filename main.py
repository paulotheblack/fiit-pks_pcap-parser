from src.misc import *
from src.osi.data_link import Frame
from src.color import Color
import sys


if __name__ == '__main__':

    # TODO add comments whole code

    args = parse_args()

    if args['o'] == 'f':  # output selection
        f = open('stdout_test.txt', 'w')
        sys.stdout = f
        Color.disabled()
    else:
        Color.enabled()

    if not args['i']:  # if no input file was selected
        # args['i'] = 'pcap_src/trace_ip_nad_20_B.pcap'
        args['i'] = input('Please insert PCAP file path: ')

    pcap_data = read_pcap(args['i'])
    dump = []  # for future data manipulation

    consts = get_setup('src/analyse.yaml')
    [print(i) for i in consts['ethertype']]

    for i, fr in enumerate(pcap_data):
        dump.append(Frame(fr['index'], fr['ts'], fr['buf'], consts))
        print(dump[i])
        petit_print(dump[i].buffer)

    # TODO rest of processing.

    if args['o'] == 'f':
        f.close()
        sys.stdout = sys.__stdout__




