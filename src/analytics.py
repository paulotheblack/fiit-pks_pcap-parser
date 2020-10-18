from .osi import data_link
from .osi.network import IPv4, ipv4_format
from src.color import Color as c


def ip_analytics(dump: [data_link.Frame]):
    top_dest = []
    top_src = []
    add_d = True
    add_s = True

    for frame in dump:

        if type(frame.net_protocol) is IPv4:
            # DEST_IP stats
            for entry in top_dest:
                # if IP already written raise count +1
                if entry['ip'] == frame.net_protocol.dest_ip:
                    entry['count'] += 1
                    add_d = False

            if add_d is True:
                top_dest.append({
                    'ip': frame.net_protocol.dest_ip,
                    'count': 1
                })
            add_d = True

            # SRC_IP stats
            for entry in top_src:
                if entry['ip'] == frame.net_protocol.src_ip:
                    entry['count'] += 1
                    add_s = False

            if add_s is True:
                top_src.append({
                    'ip': frame.net_protocol.src_ip,
                    'count': 1
                })
            add_s = True

    top_dest.sort(key=lambda k: k['count'], reverse=True)
    top_src.sort(key=lambda k: k['count'], reverse=True)

    # stdout: dest results
    print(c.RED + '''
# ------------------------------------- #
#           DEST_IPs sorted             #
# ------------------------------------- #''' + c.END)
    for i in top_dest:
        print('\t' + str(ipv4_format(i['ip'])) + '  (' + str(i['count']) + ')')

    print(c.RED + '''
# ------------------------------------- #
#           Most Used DEST_IP           #
# ------------------------------------- #''' + c.END)
    print('\t' + str(ipv4_format(top_dest[0]['ip'])) + ' (' + str(top_dest[0]['count']) + ')')

    # stdout: src results
    print(c.RED + '''
# ------------------------------------- #
#            SRC_IPs sorted             #
# ------------------------------------- #''' + c.END)
    for i in top_src:
        print('\t' + str(ipv4_format(i['ip'])) + '  (' + str(i['count']) + ')')

    print(c.RED + '''
# ------------------------------------- #
#           Most Used SRC_IP            #
# ------------------------------------- #''' + c.END)
    print('\t' + str(ipv4_format(top_src[0]['ip'])) + ' (' + str(top_src[0]['count']) + ')')