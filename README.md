**Python 3.8**

**Dependency:**

PCAP Reader used : [dkpt](https://pypi.org/project/dpkt/) 

`$ pip install dkpt`

Usage:
`pcap = dpkt.pcap.Reader(f)` 

    
```
usage: PCAP Analyzer [-h] [-o O] [-i I] [-p P]

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
```

fe: 

(1)
`(venv)$ python3 main.py -o f -i $HOME/Downloads/pcap_src/trace-8.pcap`

`---> analyzer-stdout.txt`

`---> analytics-results.txt`

(2)
`(venv)$ python3 main.py -o s -i $HOME/Downloads/pcap_src/trace-8.pcap`

`---> stdout`

`---> analytics-results.txt`