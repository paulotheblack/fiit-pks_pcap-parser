from src.helper import read_pcap, petit_print
from src.osi.data_link import Frame

# path only for testing purpose
test_path = 'pcap_src/trace_ip_nad_20_B.pcap'

if __name__ == '__main__':

    pcap_data = read_pcap(test_path)
    # storage = []

    for fr in pcap_data:
        dump = Frame(fr['index'], fr['ts'], fr['buf'])
        print(dump)
        petit_print(dump.buffer)

        # storage.append(dump)

    """
    TODO 
    Zoznam IP adries vsetych prijmajucich uzlov
    IP adresu uzla, kt. sumarne prijal najvacsi pocet paketov a ich pocet (iba IPv4)
    """