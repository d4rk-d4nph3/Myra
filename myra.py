from collections import Counter
from datetime import datetime, date
import json
import os
import sys

import animation
from fpdf import FPDF
from geoip2 import database
import geopandas
import matplotlib.pyplot as plt
from matplotlib.dates import date2num
import pandas as pd
from scapy.all import *


@animation.wait('Reading pcap file')
def read_pcap(input_pcap_file):
    try:
        packets = rdpcap(input_pcap_file)  
        return packets
    except FileNotFoundError:
        return None


def generate_summary(packets, output_file):
    with open(output_file, 'w') as fp:
        try:
            original_stdout = sys.stdout
            sys.stdout = fp
            fp.write(packets.summary(
                        prn=lambda x: str(x.time) 
                                       + ' ' + x.summary()))
        except TypeError as e:
            sys.stdout = original_stdout


def pdf_init():
    pdf = FPDF(orientation='P', unit='mm', format='A4')
    pdf.add_page()
    pdf.set_font("Arial", size = 12)
    pdf.cell(200, 10, txt="Myra PCAP Report", ln=1, align="C")
    pdf.set_font_size(8)
    pdf.cell(200, 10, txt=str(date.today()), ln=1, align="C")
    pdf.image('myra.png', x=95, y=30, w=30)
    return pdf


def plot_ts(ts_data, title, color):
    dates = date2num(ts_data)
    plt.plot_date(
        dates, [1]*len(dates), marker="|", markersize=150, color=color)
    plt.ylim(0.97,1.2)
    plt.title(title)
    plt.yticks([])

    plt.show()
    # I know this is cheating. But seems to be the only way.


@animation.wait('Plotting GeoLocation Data')
def plot_geoloc(src_location):
    latitude = []
    longitude = []

    for each_pairs in src_location:
        latitude.append(float(each_pairs.split(',')[0]))
        longitude.append(float(each_pairs.split(',')[1]))
    df = pd.DataFrame(
                {'Latitude': latitude,
                'Longitude': longitude})

    gdf = geopandas.GeoDataFrame(
                         df, geometry = geopandas.points_from_xy(
                                        df.Longitude, df.Latitude))

    world = geopandas.read_file(
                geopandas.datasets.get_path(
                                    'naturalearth_lowres'))	

    ax = world.plot(color='white', edgecolor='black')
    gdf.plot(ax=ax, color='green')
    plt.show()


def query_geoip(ip_list):
    reader = database.Reader(GEOIP_DB)
    resolved_src_country = []

    for each_ip in ip_list:
        try:
            result = reader.city(each_ip)
            resolved_src_country.append(
                                    result.country.iso_code)
        except:
            continue    # Skip private IPs

    return resolved_src_country


@animation.wait('Resolving IP addresses to Location')
def obtain_geoip_info(src_ip_list, dst_ip_list):
    resolved_src_country = []
    resolved_dst_country = []
    src_location = []
    dst_location = []
    unique_src_country = {}
    unique_dst_country = {}

    query_geoip(src_ip_list)
    for each_ip in src_ip_list:
        src_country, locale = query_geoip(each_ip)
        if src_country is not None:
            resolved_src_country.append(src_country)
            src_location.append(locale)

    for each_ip in dst_ip_list:
        dst_country, locale = query_geoip(each_ip)
        if dst_country is not None:
            resolved_dst_country.append(dst_country)
            dst_location.append(locale)
    
    unique_src_country = set(resolved_src_country)
    unique_dst_country = set(resolved_dst_country)
    print('\nUnique Source Countries are ')
    print(unique_dst_country)
    print('Unique Destination Countries are ')
    print(unique_dst_country)

    plot_geoloc(dst_location)


def dns_report(packets):
    query_count = 0
    dns_req_ts = []
    dns_query = []

    for packet in packets:
        if packet.haslayer(DNSRR):
            # Filtering packets with a DNS Round Robin layer. 
            if isinstance(packet.an, DNSRR):
                query_count += 1
                packet_ts = datetime.fromtimestamp(packet.time)
                dns_req_ts.append(packet_ts)
                print(packet.an.rrname.decode().strip('.'))
                dns_query.append(packet.an.rrname.decode().strip('.'))
                # Converting to unicode and stripping the root '.'

    print('\nTotal number of DNS Queries made is '
                                     + str(query_count) + '\n')
    
    # plot_ts(dns_req_ts, 'DNS Flow', '#ea7369')
    return dns_query


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
    
    plot_ts(req_arp_ts, 'ARP Flow', "#7d3ac1")


@animation.wait('Generating IP Report')
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

    print('\nV----- Unique Source IPs -----V\n')
    print(unique_src_ip)
    print('\nV----- Unique Destination IPs -----V\n')
    print(unique_dst_ip)
    unique_src_ip_count = len(unique_src_ip)
    unique_dst_ip_count = len(unique_dst_ip)

    print('The number of unique source ips is ' 
                    + str(unique_src_ip_count) + '\n')
    print('The number of unique destination ips is ' 
                    + str(unique_dst_ip_count) + '\n')

    
    obtain_geoip_info(unique_src_ip, unique_dst_ip)
    # plot_ts(ip_ts, 'IP Flow', '#af4bce')
    return unique_src_ip, unique_dst_ip


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
    print(unique_udp_dst_port,'\n')

    plot_ts(tcp_ts, 'TCP Flow', '#db4cb2')
    plot_ts(udp_ts, 'UDP Flow' , '#ea7369')


def matcher(source_set, blacklist_set):
    match_list = []

    for each_candidate in source_set:
        if each_candidate in blacklist_set:
            match_list.append(each_candidate)
    return match_list


def threat_intel(src_ip_set, dst_ip_set, domain_set):
    blacklist_ip_count = 0
    blacklist_ad_domain_count = 0
    blacklist_trackers_count = 0
    blacklist_coin_miner_count = 0
    blacklist_corona_count = 0

    try:
        blacklist_ip_set = set(
                            map(str.strip, open(
                                            BLACKLIST_IP_DB)))
        blacklist_ad_domain_set = set(
                            map(str.strip, open(
                                            BLACKLIST_AD_DB)))
        blacklist_tracker_set = set(
                            map(str.strip, open(
                                            BLACKLIST_TRACKER_DB)))
        blacklist_coinminer_set = set(
                            map(str.strip, open(
                                            BLACKLIST_COINMINER_DB)))
        blacklist_covid_domain_set = set(
                            map(str.strip, open(
                                            BLACKLIST_COVID_DOMAIN_DB)))
        
        blacklist_src_ip = matcher(
                            src_ip_set, blacklist_ip_set)
        blacklist_dst_ip = matcher(
                                dst_ip_set, blacklist_ip_set)    
        blacklist_ad_domain = matcher(
                                domain_set, blacklist_ad_domain_set)
        blacklist_tracker = matcher(
                                domain_set, blacklist_trackers_set)
        blacklist_coinminer = matcher(
                                domain_set, blacklist_coin_miner_set)
        blacklist_corona_domain = matcher(
                                domain_set, blacklist_corona_set)

        print('Blacklisted Source IP match -> ' 
                        + str(len(blacklist_src_ip)))
        print('Blacklisted Destination IP match -> ' 
                        + str(len(blacklist_dst_ip)))
        print('Blacklisted Ad Server Domain match -> '
                        + str(len(blacklist_ad_domain)))
        print('Blacklisted Agressive Trackers Domain match -> '
                        + str(len(blacklist_trackers)))
        print('Blacklisted Coin Miner Domain match -> ' 
                        + str(len(blacklist_coin_miner)))
        print('Blacklisted COVID-19 Phising Domain match -> ' 
                        + str(len(blacklist_corona)))

    except FileNotFoundError:
        print('One of the Threat Intel Files doesnot exist!!\n'
              'Threat Intel process is skipped...')
    

def main():
    print('<<<<<<<<<< Initialization Completed >>>>>>>>>>\n')
    
    packets = read_pcap(input_pcap_file)
    if packets is None:
        print('The input pcap file does not exist!!\n'
              'Exiting the program...')
        exit()

    generate_summary(packets, output_summary_file)

    print('####### Summary of packets has been successfuly written in {}'
                                  ' #######'.format(output_summary_file))

    packet_count = len(packets)
    print('\nThe numbers of packets in this pcap file is '
                                 + str(packet_count) + '\n')
    
    TODO  PDF Generation 
    pdf = pdf_init()
    pdf.output('sample.pdf')
    
    print('Generating DNS Report.....\n')
    dns_query_list = dns_report(packets)

    print('Generating IP Layer Report....\n')
    src_ip, dst_ip = ip_report(packets)
    
    print('Generating Transport Layer Report....\n')
    transport_report(packets)

    print('Generating ARP Report....\n')
    arp_report(packets)

    threat_intel(src_ip, dst_ip, dns_query_list)
    

if len(sys.argv) not in [3, 4]:
    print('''

**** Usage: python3 myra.py <pcap_file> <summary_output_file> ****
            
        ''')
    exit()

script_name = sys.argv[0]
input_pcap_file = sys.argv[1]
output_summary_file = sys.argv[2]

# For GeoIP query
GEOIP_DB = 'GeoLite2-City.mmd'

# Threat Intel Feeds
BLACKLIST_IP_DB = 'blacklist/blacklist.ip'
BLACKLIST_AD_DB = 'blacklist/blacklist.ads'
BLACKLIST_TRACKER_DB = 'blacklist/blacklist.trackers'
BLACKLIST_COINMINER_DB = 'blacklist/blacklist.coinminer'
BLACKLIST_COVID_DOMAIN_DB = 'blacklist/blacklist.corona'

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