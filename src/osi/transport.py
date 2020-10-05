# represents Transport Layer
from struct import unpack
from src.color import Color as c

T0 = '    '


class ICMP:
    name = 'ICMP'

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'\
            + c.YELLOW + '--> TODO' + c.END


class IGMP:
    name = 'IGMP'

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'\
            + c.YELLOW + '--> TODO' + c.END


class TCP:
    name = 'TCP'

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'\
            + c.YELLOW + '--> TODO' + c.END


class UDP:
    name = 'UDP'

    def __repr__(self):
        return c.CYAN + self.name + c.END + '\n'\
            + c.YELLOW + '--> TODO' + c.END
