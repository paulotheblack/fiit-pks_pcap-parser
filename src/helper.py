from dpkt import pcap

T0 = '    '
T1 = '        '


def get_path():
    path = input('Please provide full path to desired .pcap to analyze: \n')
    return path


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

    f.close()
    return data, buffer_cpy


def petit_print(buffer):
    for i in range(1, len(buffer) + 1):
        print(f'{buffer[i - 1:i].hex().upper()}', end='')
        if i % 16 == 0:
            print('\n', end='')
        elif i % 8 == 0:
            print('   ', end='')
        else:
            print(' ', end='')
    print()
