**Python 3.8**

PCAP Reader used  
[dkpt](https://pypi.org/project/dpkt/) 
`pcap = dpkt.pcap.Reader(f)` 

    
```
usage: PROG [-h] [-o O] [-i I] [-p P]

# ----------------------------------------------- #
#   PCAP Analyzer, xxxxxxxxxxxxxxxxxxx v0.1       #
#       Author:     Michal Paulovic               #
#       STU-FIIT:   xxxxxxxxxxxx                  #
#       Github:     paulotheblack                 #
#   https://github.com/paulotheblack/pcap_parser  #
# ----------------------------------------------- #

optional arguments:
  -h, --help  show this help message and exit
  -o O        stdout (s), file (f)
  -i I        path to pcap file, RELATIVE to main.py or ABSOLUTE from root
  -p P        protocols to parse from file NOT IMPLEMENTED
```