from collections import Counter
from datetime import datetime
import sys
import os

import matplotlib.pyplot as plt
from matplotlib.dates import date2num
from scapy.all import *


def bootstrap():
    os.system('python3 {} {} {} bstrap > {}'.format(
                                script_name, input_pcap_file, 
                                output_summary_file, output_summary_file))

def generate_summary(input_pcap_file):
    packets = rdpcap(input_pcap_file)   # Read PCAP file. 
    print(packets.summary())

def plot_ts(ts_data, title):
    dates = date2num(ts_data)
    plt.plot_date(
        dates, [1]*len(dates), marker="|", markersize=150)
    plt.ylim(0.97,1.2)
    plt.title(title)
    plt.yticks([])

    plt.show()
    # I know this is cheating. But seems to be the only way.

def dns_report(packets):
    query_count = 0
    dns_req_ts = []
    for packet in packets:
        if packet.haslayer(DNSRR):
            # Filtering packets with a DNS Round Robin layer. 
            if isinstance(packet.an, DNSRR):
                query_count += 1
                packet_ts = datetime.fromtimestamp(packet.time)
                dns_req_ts.append(packet_ts)
                print(packet.an.rrname.decode().strip('.')) 
                # Converting to unicode and stripping the root '.'

    print('\nTotal number of DNS Queries made is ' + str(query_count) + '\n')
    plot_ts(dns_req_ts, 'DNS Flow')

def arp_report(packets):
    arp_count = 0
    src_arp_mac = []
    src_arp_ip = []
    req_arp_ip = []
    req_arp_ts = []
    unique_src_arp_mac = {}
    unique_src_arp_ip = {}
    unique_req_arp_ip = {}

    for packet in packets:
        if packet.haslayer(ARP):
            arp_count += 1
            if packet[ARP].op == 1:  # ARP Request
                src_arp_mac.append(packet[ARP].hwsrc)
                src_arp_ip.append(packet[ARP].psrc)
                req_arp_ip.append(packet[ARP].pdst)
                packet_ts = datetime.fromtimestamp(packet.time)
                req_arp_ts.append(packet_ts)

    unique_src_arp_mac = set(src_arp_mac)
    unique_src_arp_ip = set(src_arp_ip)
    unique_req_arp_ip = set(req_arp_ip)
    req_arp_ip_dist = Counter(req_arp_ip)
    src_arp_ip_dist = Counter(src_arp_ip)
    src_arp_mac_dist = Counter(src_arp_mac)
    print(req_arp_ip_dist)
    print(src_arp_ip_dist)
    print(src_arp_mac_dist)
    print(req_arp_ts)
    
    plot_ts(req_arp_ts, 'ARP Flow')

def ip_report(packets):
    ip_ts = []
    src_ip = []
    dst_ip = []
    unique_src_ip = []
    unique_dst_ip = []
    unique_src_ip_count = 0
    unique_dst_ip_count = 0
    
    for packet in packets:
        if packet.haslayer(IP):
            src_ip.append(packet[IP].src)
            dst_ip.append(packet[IP].dst)
            packet_ts = datetime.fromtimestamp(packet.time)
            ip_ts.append(packet_ts)

    unique_src_ip = set(src_ip)
    unique_dst_ip = set(dst_ip)

    print('V----- Unique Source IPs -----V\n')
    print(unique_src_ip)
    print('\nV----- Unique Destination IPs -----V\n')
    print(unique_dst_ip)
    unique_src_ip_count = len(unique_src_ip)
    unique_dst_ip_count = len(unique_dst_ip)

    print('The number of unique source ips is ' 
                    + str(unique_src_ip_count) + '\n')
    print('The number of unique destination ips is ' 
                    + str(unique_dst_ip_count) + '\n')

    
    plot_ts(ip_ts, 'IP Flow')

def transport_report(packets):
    tcp_src_port = []
    tcp_dst_port = []
    udp_src_port = []
    udp_dst_port = []
    tcp_ts = []
    udp_ts = []
    unique_tcp_src_port = {}
    unique_tcp_dst_port = {}
    unique_udp_src_port = {}
    unique_udp_dst_port = {}
    tcp_src_port_count = 0
    tcp_dst_port_count = 0
    udp_src_port_count = 0
    udp_dst_port_count = 0
    tcp_count = 0
    udp_count = 0

    for packet in packets:
        if packet.haslayer(TCP):
            tcp_count += 1
            tcp_src_port.append(packet[IP].sport)
            tcp_dst_port.append(packet[IP].dport)
            packet_ts = datetime.fromtimestamp(packet.time)
            tcp_ts.append(packet_ts)

        elif packet.haslayer(UDP):
            udp_count += 1
            udp_src_port.append(packet[IP].sport)
            udp_dst_port.append(packet[IP].dport)
            packet_ts = datetime.fromtimestamp(packet.time)
            udp_ts.append(packet_ts)

    unique_tcp_src_port = set(tcp_src_port)
    unique_tcp_dst_port = set(tcp_dst_port)
    unique_udp_src_port = set(udp_src_port)
    unique_udp_dst_port = set(udp_dst_port)

    tcp_src_port_count = len(unique_tcp_src_port)
    tcp_dst_port_count = len(unique_tcp_dst_port)
    udp_src_port_count = len(unique_udp_src_port)
    udp_dst_port_count = len(unique_udp_dst_port)

    print('Total TCP packet count is ' + str(tcp_count) + '\n')
    print('V----- Unique TCP Source Ports -----V\n')
    print(unique_tcp_src_port)
    print('\nV----- Unique TCP Destination Ports -----V\n')
    print(unique_tcp_dst_port)
    
    print('\nTotal UDP packet count is ' + str(udp_count) + '\n')
    print('V----- Unique UDP Source Ports -----V\n')
    print(unique_udp_src_port)
    print('\nV----- Unique UDP Destination Ports -----V\n')
    print(unique_udp_dst_port)

    plot_ts(tcp_ts, 'TCP Flow')
    plot_ts(udp_ts, 'UDP Flow')

def main():
    print('<<<<<<<<<< Initialization Completed >>>>>>>>>>\n')

    print('Initiating Bootstraping Process to Dump Summary Report........\n')
    bootstrap()
    print('<<<<<<<<<< Bootstrapping Process Completed >>>>>>>>>>\n')
    print('####### Summary of packets has been successfuly written in {} #######\n'.format(output_summary_file))

    print('Reading pcap file......')
    packets = rdpcap(input_pcap_file)   # Read PCAP file.
    packet_count = len(packets)

    print('The numbers of packets in this pcap file is '
                                 + str(packet_count) + '\n')

    print('Generating DNS Report.....\n')
    dns_report(packets)

    print('Generating IP Layer Report....\n')
    ip_report(packets)

    print('Generating Transport Layer Report....\n')
    transport_report(packets)

    print('Generating ARP Report....\n')
    arp_report(packets)


if len(sys.argv) not in [3, 4]:
    print('''
****   Usage: python3 myra.py <pcap_file> <summary_output_file> [bstrap]   ****
        ''')
    exit()

script_name = sys.argv[0]
input_pcap_file = sys.argv[1]
output_summary_file = sys.argv[2]

if len(sys.argv) == 4 and sys.argv[3] == 'bstrap':
    generate_summary(input_pcap_file)
    exit()

print('''

    ,·'´¨;.  '                       ,-·-.          ,'´¨;         ,. -  .,                              ,.,   '      
    ;   ';:\           .·´¨';\       ';   ';\      ,'´  ,':\'     ,' ,. -  .,  `' ·,                     ;´   '· .,     
   ;     ';:'\      .'´     ;:'\       ;   ';:\   .'   ,'´::'\'    '; '·~;:::::'`,   ';\                .´  .-,    ';\   
   ;   ,  '·:;  .·´,.´';  ,'::;'       '\   ';::;'´  ,'´::::;'      ;   ,':\::;:´  .·´::\'             /   /:\:';   ;:'\' 
  ;   ;'`.    ¨,.·´::;'  ;:::;          \  '·:'  ,'´:::::;' '      ;  ·'-·'´,.-·'´:::::::';          ,'  ,'::::'\';  ;::'; 
  ;  ';::; \*´\:::::;  ,':::;           '·,   ,'::::::;'´      ;´    ':,´:::::::::::·´'       ,.-·'  '·~^*'´¨,  ';::; 
 ';  ,'::;   \::\;:·';  ;:::; '            ,'  /::::::;'  '       ';  ,    `·:;:-·'´            ':,  ,·:²*´¨¯'`;  ;::'; 
 ;  ';::;     '*´  ;',·':::;            ,´  ';\::::;'  '         ; ,':\'`:·.,  ` ·.,           ,'  / \::::::::';  ;::'; 
 \´¨\::;          \¨\::::;             \`*ª'´\\::/            \·-;::\:::::'`:·-.,';        ,' ,'::::\·²*'´¨¯':,'\:;  
  '\::\;            \:\;·'               '\:::::\';  '            \::\:;'` ·:;:::::\::\'      \`¨\:::/          \::\'  
    '´¨               ¨'                   `*ª'´                 '·-·'       `' · -':::''      '\::\;'            '\;'  '
                                            '                                                 `¨'                   
''')

if __name__ == '__main__':
    main()