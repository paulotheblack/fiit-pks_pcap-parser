from src.helper import *

# path only for testing purpose
test_path = 'pcap_src/trace-26.pcap'

if __name__ == '__main__':
    data, buffer_copy = read_pcap(test_path)
    test_print(data, buffer_copy)