from dpkt import pcap
import textwrap
import argparse
import yaml


def parse_args():
    ap = argparse.ArgumentParser(
        prog='PROG',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''\
            # ----------------------------------------------- #
            #   PCAP Analyzer, PKS assigment 1. v0.1          #
            #       Author:     Michal Paulovic               #
            #       STU-FIIT:   xpaulovicm1                   #
            #       Github:     paulotheblack                 #
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


def read_pcap(path):
    # TODO handle IOError
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


def get_setup(src):
    # yaml_src: $PATH/pcap_analyzer/src/analyse.yaml
    try:
        with open(src, 'r') as stream:
            const = yaml.safe_load(stream)

    except IOError:
        print('Unable to read file')
        exit(1)

    stream.close()
    return const
