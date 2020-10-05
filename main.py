from src.helper import read_pcap, petit_print
from src.osi.data_link import Frame

# path only for testing purpose
test_path = 'pcap_src/trace-26.pcap'

if __name__ == '__main__':

    pcap_data, buffer_copy = read_pcap(test_path)

    for fr in pcap_data:
        x = Frame(fr['index'], fr['ts'], fr['buf'])
        print(x)
        petit_print(x.buffer)
