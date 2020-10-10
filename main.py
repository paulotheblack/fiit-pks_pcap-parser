from src.misc import read_pcap, petit_print, parse_args
from src.osi.data_link import Frame
from src.color import *
import sys

# path only for testing purpose
# test_path = 'pcap_src/trace_ip_nad_20_B.pcap'

if __name__ == '__main__':

    args = parse_args()

    if args['o'] == 'f':  # output selection
        f = open('stdout_test', 'w')
        sys.stdout = f
        Color.disabled()
    else:
        Color.enabled()

    if not args['i']:  # if no input file was selected
        args['i'] = 'pcap_src/trace_ip_nad_20_B.pcap'

    pcap_data = read_pcap(args['i'])
    dump = []  # for future data manipulation

    for i, fr in enumerate(pcap_data):
        dump.append(Frame(fr['index'], fr['ts'], fr['buf']))
        print(dump[i])
        petit_print(dump[i].buffer)

    #
    # TODO najcastesia ip_addr {key=addr, value=visits}
    #

    if args['o'] == 'f':
        f.close()
        sys.stdout = sys.__stdout__
