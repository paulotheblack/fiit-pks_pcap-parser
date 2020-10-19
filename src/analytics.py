from .osi import data_link
from .osi.network import IPv4, ipv4_format, ARP
from .osi.transport import ICMP, TCP, UDP
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

    # sort results
    top_dest.sort(key=lambda k: k['count'], reverse=True)
    top_src.sort(key=lambda k: k['count'], reverse=True)

    # stdout: dest results
    print(c.RED + '''
# ------------------------------------- #
#            DEST_IPs sorted            #
# ------------------------------------- #''' + c.END)
    for i in top_dest:
        print('\t\t\t' + str(ipv4_format(i['ip'])) + '  (' + str(i['count']) + ')')

    print(c.RED + '''
# ------------------------------------- #
#           Most Used DEST_IP           #
# ------------------------------------- #''' + c.END)
    print('\t\t\t' + str(ipv4_format(top_dest[0]['ip'])) + ' (' + str(top_dest[0]['count']) + ')')

    # stdout: src results
    print(c.RED + '''
# ------------------------------------- #
#            SRC_IPs sorted             #
# ------------------------------------- #''' + c.END)
    for i in top_src:
        print('\t\t\t' + str(ipv4_format(i['ip'])) + '  (' + str(i['count']) + ')')

    print(c.RED + '''
# ------------------------------------- #
#           Most Used SRC_IP            #
# ------------------------------------- #''' + c.END)
    print('\t\t\t' + str(ipv4_format(top_src[0]['ip'])) + ' (' + str(top_src[0]['count']) + ')\n')


def icmp_analytics(dump: [data_link.Frame]):

    coms = []  # [{'req' : Frame , 'reply': Frame}]
    add = True
    last_id = 0
    session = 0

    # stdout: src results
    print(c.PURPLE + '''
# ------------------------------------- #
#         ICMP Analytics (Ping)         #
# ------------------------------------- #''' + c.END)

    for frame in dump:

        if type(frame.net_protocol) is IPv4 and type(frame.net_protocol.trans_protocol) is ICMP:
            # aux var
            src = frame.net_protocol.src_ip
            icmp = frame.net_protocol.trans_protocol

            if icmp.type == 8:  # ECHO REQUEST

                if last_id != icmp.identifier:
                    if last_id == 0:
                        session = 1
                        last_id = icmp.identifier
                        print(f'\t{c.PURPLE}# ------ SESSION ({str(session)}) ----- #{c.END}')
                    else:
                        last_id = icmp.identifier
                        session += 1
                        print(f'\t{c.PURPLE}# ------ SESSION ({str(session)}) ----- #{c.END}')

                for entry in coms:
                    # later request found without reply, update request
                    if entry['req'].net_protocol.src_ip == src:
                        entry['req'] = frame
                        add = False

                if add is True:
                    coms.append({
                        'req': frame,
                        'reply': None
                    })
            add = True

            if icmp.type == 0:  # ECHO REPLY
                for i, entry in enumerate(coms):
                    # check corresponding IPs
                    if entry['req'].net_protocol.dest_ip == src:
                        # check if sequence no. is same
                        if entry['req'].net_protocol.trans_protocol.sequence == icmp.sequence:
                            print(c.BOLD + '--> ECHO REQUEST:' + c.END, end='')
                            print(entry['req'])
                            print(c.BOLD + '--> ECHO REPLY: ' + c.END, end='')
                            print(frame)
                            coms.pop(i)

    print(f'\n{c.PURPLE}ICMP Sessions ({session}) {c.END}')


def arp_analytics(dump: [data_link.Frame]):

    coms = []
    session = 0
    add = True

    # stdout: src results
    print(c.GREEN + '''
# ------------------------------------- #
#             ARP Analytics             #
# ------------------------------------- #''' + c.END)

    for frame in dump:

        if type(frame.net_protocol) is ARP:

            arp = frame.net_protocol

            if arp.oper == 1:  # REQUEST
                session += 1
                coms.append({
                    'req': frame,
                    'reply': None
                })

            if arp.oper == 2:  # REPLY
                if len(coms) != 0:
                    for entry in coms:
                        # if request is found
                        if entry['req'] is not None:
                            if entry['req'].net_protocol.spa == arp.tpa:
                                entry['reply'] = frame
                                add = False

                # for first entry
                else:
                    session += 1
                    coms.append({
                        'req': None,
                        'reply': frame
                    })
                    add = False

                if add is True:
                    session += 1
                    coms.append({
                        'req': None,
                        'reply': frame
                    })

        add = True

    for i, entry in enumerate(coms):
        print(f'\n\t{c.GREEN}# ------ SESSION ({str(i + 1)}) ----- #{c.END}')

        if entry['req'] is None:
            print(c.BOLD + '--> ARP REQUEST: None' + c.END)
        if entry['req']:
            print(c.BOLD + '--> ARP REQUEST:' + c.END, end='')
            print(entry['req'])

        if entry['reply'] is None:
            print(c.BOLD + '--> ARP REPLY: None' + c.END)
        if entry['reply']:
            print(c.BOLD + '--> ARP REPLY: ' + c.END, end='')
            print(entry['reply'])

    print(f'\n{c.GREEN}ARP Sessions ({session}) {c.END}')


def tcp_analytics(dump: [data_link.Frame]):

    storage = []
    session = 0

    # stdout: src results
    print(c.CYAN + '''
# ------------------------------------- #
#             TCP Analytics             #
# ------------------------------------- #''' + c.END)

    for frame in dump:

        if type(frame.net_protocol) == IPv4 and type(frame.net_protocol.trans_protocol) == TCP:
            tcp = frame.net_protocol.trans_protocol

            src_ip = frame.net_protocol.src_ip
            dest_ip = frame.net_protocol.dest_ip

            src_port = tcp.src_port
            dest_port = tcp.dest_port

            data = tcp.data_type

            # 1st entry of communication
            if tcp.f_syn and not tcp.f_ack:
                if len(storage) > 0:
                    for com in storage:
                        if src_ip == com[0]['ips'][0] or src_ip == com[0]['ips'][1]:
                            if data == com[0]['data']:
                                com.append({'frame': frame})
                        else:
                            session += 1
                            communication = [{
                                'ips': [src_ip, dest_ip],
                                'ports': [src_port, dest_port],
                                'data': data,
                                'frame': frame,
                                'full': False,
                                'session': session
                            }]
                            storage.append(communication)
                # if first entry
                if len(storage) == 0:
                    session += 1
                    communication = [{
                        'ips': [src_ip, dest_ip],
                        'ports': [src_port, dest_port],
                        'data': data,
                        'frame': frame,
                        'full': False,
                        'fin': False,
                        'session': session
                    }]
                    storage.append(communication)

            # end of communication
            if tcp.f_fin or tcp.f_rst:
                # check each communication
                for com in storage:
                    if src_ip == com[0]['ips'][0] or src_ip == com[0]['ips'][1]:
                        if src_port == com[0]['ports'][0] or src_port == com[0]['ports'][1]:
                            com[0]['full'] = True
                            com[0]['fin'] = True
                            com.append({
                                'frame': frame
                            })

            # add entry of same comm
            if tcp.f_ack and not tcp.f_rst:
                for com in storage:
                    if src_ip == com[0]['ips'][0] or src_ip == com[0]['ips'][1]:
                        if src_port == com[0]['ports'][0] or src_port == com[0]['ports'][1]:
                            com.append({
                                'frame': frame
                            })

    for com in storage:
        f_c = com[0]['frame'].index
        l_c = com[len(com) - 1]['frame'].index

        print(c.CYAN + '\t# ------ SESSION (' + str(com[0]['session']) + ') ----- #' + c.END)
        print(c.BOLD + '\tFirst packet index: ' + str(f_c))
        print('\tLast packet index: ' + str(l_c) + c.END)
        print('\tData Type: ' + str(com[0]['data']))
        print('\tClosed: ' + str(com[0]['full']))

        if len(com) <= 20:
            for entry in com:
                 print(entry['frame'])
        else:
            for entry in com[:10]:
                 print(entry['frame'])
            for entry in com[l_c - 10:]:
                 print(entry['frame'])

    if len(storage) != 0:
        last = len(storage) - 1
        print(c.CYAN + 'TCP Sessions (' + str(storage[last][0]['session']) + ')' + c.END)


def doimplementacia(dump: [data_link.Frame]):

    dns_dump = []

    for frame in dump:

        if type(frame.net_protocol) == IPv4 and type(frame.net_protocol.trans_protocol) == UDP:
            udp = frame.net_protocol.trans_protocol
            if udp.data_type == 'DNS':
                dns_dump.append(frame)

    print(c.RED + '''
# ------------------------------------- #
#      Doimplementacia DNS count        #
# ------------------------------------- #''' + c.END)

    print(f'# ---- DNS COUNT ({len(dns_dump)}) ---- #')


    for entry in dns_dump:
        print(entry)
