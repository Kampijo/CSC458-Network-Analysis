import pyshark

# this file was used to generate csv files that contain all the sizes
def analyze():
    cap = pyshark.FileCapture('univ1_pt17.pcap')

    # Link Layer statistics
    ethernet_count = 0
    ethernet_bytes = 0

    # Network Layer statistics
    ipv4_count = 0
    ipv6_count = 0
    arp_count = 0
    icmp_count = 0
    network_other_count = 0

    ipv4_bytes = 0
    ipv6_bytes = 0
    arp_bytes = 0
    icmp_bytes = 0
    network_other_bytes = 0

    # Transport Layer statistics
    tcp_count = 0
    udp_count = 0
    transport_other_count = 0

    tcp_bytes = 0
    udp_bytes = 0
    transport_other_bytes = 0

    for packet in cap:
        packetLength = int(packet.length)
        if 'ETH' in packet:
            ethernet_count+=1
            ethernet_bytes+=packetLength

            if 'ARP' in packet:
                arp_count+=1
                arp_bytes+=packetLength

            if 'IP' in packet:
                if packet.ip.version == '4':
                    ipv4_count+=1
                    ipv4_bytes+=packetLength
                if packet.ip.version == '6':
                    ipv6_count+=1
                    ipv6_bytes+=packetLength
                if 'ICMP' in packet:
                    icmp_count+=1
                    icmp_bytes+=packetLength
                if 'TCP' in packet:
                    tcp_count+=1
                    tcp_bytes+=packetLength
                if 'UDP' in packet:
                    udp_count+=1
                    udp_bytes+=packetLength
                if not (('UDP' in packet) or ('TCP' in packet) or ('ICMP' in packet)):
                    transport_other_count+=1
                    transport_other_bytes+=packetLength
            else:
                network_other_count+=1
                network_other_bytes+=packetLength

    print('Ethernet Count: %s\nTotal Bytes: %s' % (ethernet_count, ethernet_bytes))
    print('IPv6 Count: %s\nTotal Bytes: %s' % (ipv6_count, ipv6_bytes))
    print('IPv4 Count: %s\nTotal Bytes: %s' % (ipv4_count, ipv4_bytes))
    print('ARP Count: %s\nTotal Bytes: %s' % (arp_count, arp_bytes))
    print('ICMP Count: %s\nTotal Bytes: %s' % (icmp_count, icmp_bytes))
    print('Network Other Count: %s\nTotal Bytes: %s' % (network_other_count, network_other_bytes))
    print('TCP Count: %s\nTotal Bytes: %s' % (tcp_count, tcp_bytes))
    print('UDP Count: %s\nTotal Bytes: %s' % (udp_count, udp_bytes))
    print('Transport Other Count: %s\nTotal Bytes: %s' % (transport_other_count, transport_other_bytes))


if __name__ == '__main__':
    analyze()
