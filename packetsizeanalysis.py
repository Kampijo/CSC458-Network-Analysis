import pyshark
import numpy


def analyze():
    cap = pyshark.FileCapture('univ1_pt17.pcap')
    ethernet_sizes = []
    ip_sizes = []
    tcp_sizes = []
    udp_sizes = []
    non_ip_sizes = []

    ip_header_sizes = []
    tcp_header_sizes = []

    for packet in cap:
        packetLength = int(packet.length)
        if 'ETH' in packet:
            ethernet_sizes.append(packetLength)

            if 'IP' in packet:
                ip_sizes.append(packetLength)
                ip_header_sizes.append(int(packet.ip.hdr_len))
                if 'TCP' in packet:
                    tcp_sizes.append(packetLength)
                    tcp_header_sizes.append(int(packet.tcp.hdr_len))
                if 'UDP' in packet:
                    udp_sizes.append(packetLength)
            else:
                non_ip_sizes.append(packetLength)

    ethernet_sizes = numpy.asarray(ethernet_sizes)
    ip_sizes = numpy.asarray(ip_sizes)
    tcp_sizes = numpy.asarray(tcp_sizes)
    udp_sizes = numpy.asarray(udp_sizes)
    non_ip_sizes = numpy.asarray(non_ip_sizes)

    ip_header_sizes = numpy.asarray(ip_header_sizes)
    tcp_header_sizes = numpy.asarray(tcp_header_sizes)

    ethernet_sizes.sort()
    ip_sizes.sort()
    tcp_sizes.sort()
    udp_sizes.sort()
    non_ip_sizes.sort()
    ip_header_sizes.sort()
    tcp_header_sizes.sort()

    numpy.savetxt("ethernetsizes.csv", ethernet_sizes, delimiter=",", fmt="%d")
    numpy.savetxt("ipsizes.csv", ip_sizes, delimiter=",", fmt="%d")
    numpy.savetxt("tcpsizes.csv", tcp_sizes, delimiter=",", fmt="%d")
    numpy.savetxt("udpsizes.csv", udp_sizes, delimiter=",", fmt="%d")
    numpy.savetxt("nonipsizes.csv", non_ip_sizes, delimiter=",", fmt="%d")
    numpy.savetxt("ipheadersizes.csv", ip_header_sizes, delimiter=",", fmt="%d")
    numpy.savetxt("tcpheadersizes.csv", tcp_header_sizes, delimiter=",", fmt="%d")


if __name__ == '__main__':
    analyze()
