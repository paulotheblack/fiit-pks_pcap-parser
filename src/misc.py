from dpkt import pcap
import textwrap
import argparse


def parse_args():
    # ap = argparse.ArgumentParser(
    #     prog='PCAP Analyzer Alfa',
    #     description='PCAP dump analyzer <--> PKS assigment 1',
    #     formatter_class=argparse.RawDescriptionHelpFormatter,
    #     epilog=textwrap.dedent('----------------------------------------------\n'
    #                            'Author --> \n'
    #                            'STU-FIIT: xpaulovicm1 \n'
    #                            'Github: paulotheblack \n'
    #                            'https://github.com/paulotheblack/pcap_parser')
    # )

    ap = argparse.ArgumentParser(
        prog='PROG',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''\
            # ----------------------------------------------- #
            #   PCAP Analyzer, PKS assigment 1. v0.1          #
            #       Author: Michal Paulovic                   #
            #       STU-FIIT: xpaulovicm1                     #
            #       Github: paulotheblack                     #
            #   https://github.com/paulotheblack/pcap_parser  #
            # ----------------------------------------------- #
        '''))

    ap.add_argument('-o', help='stdout (s), file (f)')
    ap.add_argument('-i', help='path to pcap file, RELATIVE to main.py or ABSOLUTE from root')
    ap.add_argument('-p', help='protocols to parse from file NOT IMPLEMENTED')

    args = ap.parse_args()
    return vars(args)


def get_path():
    path = input('Please provide full path to desired .pcap to analyze: \n')
    return path


# TODO change ...
def read_pcap(path):
    f = open(path, 'rb')
    src = pcap.Reader(f)
    data = []

    for index, [ts, buf] in enumerate(src):
        # List of dictionaries
        data.append({
            'index': index + 1,  # to correlate with Wireshark indexing
            'ts': ts,
            'buf': buf
        })

    f.close()
    return data


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
