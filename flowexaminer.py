import os
import dpkt
import numpy
path = '/Users/nygellopez/Documents/CSC458/CourseProject/sessions'

# Grabs the number of tcp/udp flows and their respective packet counts and sum of their byte sizes
# as well as the duration of each flow
def getflowstats():
    allflowspackets = []
    tcpflowspackets = []
    udpflowspackets = []

    allflowsbytes = []
    tcpflowsbytes = []
    udpflowsbytes = []

    allflowsduration = []
    tcpflowsduration = []
    udpflowsduration = []

    tcpoverheadratios = []

    for filename in os.listdir(path):
        f = open(path+"/"+filename, 'rb')
        pcap = dpkt.pcap.Reader(f)

        packetcount = 0
        bytecount = 0
        layertype = 0
        timestamps = []

        tcpoverhead = 0
        tcpdatatransferred = 0

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            layertype = ip.p
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
                if not syn_flag:
                    tcpdatatransferred += (ip.len - ip.hl - tcp.off) # tcp payload length
                    tcpoverhead += (ip.hl + tcp.off + 14) # 14 size of ethernet header
            packetcount += 1
            bytecount += pcap
            timestamps.append(ts)

        flowduration = timestamps[-1] - timestamps[0]

        allflowspackets.append(packetcount)
        allflowsbytes.append(bytecount)
        allflowsduration.append(flowduration)

        if layertype == dpkt.ip.IP_PROTO_TCP:
            tcpflowspackets.append(packetcount)
            tcpflowsbytes.append(bytecount)
            tcpflowsduration.append(flowduration)

            if tcpdatatransferred > 0:
                tcpoverheadratios.append(tcpoverhead / tcpdatatransferred)

            elif tcpdatatransferred <= 0:
                tcpoverheadratios.append(9999)

        elif layertype == dpkt.ip.IP_PROTO_UDP:
            udpflowspackets.append(packetcount)
            udpflowsbytes.append(bytecount)
            udpflowsduration.append(flowduration)

        f.close()

    allflowspackets.sort()
    tcpflowspackets.sort()
    udpflowspackets.sort()

    allflowsbytes.sort()
    tcpflowsbytes.sort()
    udpflowsbytes.sort()

    allflowsduration.sort()
    tcpflowsduration.sort()
    udpflowsduration.sort()

    tcpoverheadratios.sort()

    numpy.savetxt("allflowspackets.csv", allflowspackets, delimiter=",", fmt="%d")
    numpy.savetxt("allflowsbytes.csv", allflowsbytes, delimiter=",", fmt="%d")
    numpy.savetxt("allflowsduration.csv", allflowsduration, delimiter=",", fmt="%f")
    numpy.savetxt("tcpflowspackets.csv", tcpflowspackets, delimiter=",", fmt="%d")
    numpy.savetxt("tcpflowsbytes.csv", tcpflowsbytes, delimiter=",", fmt="%d")
    numpy.savetxt("tcpflowsduration.csv", tcpflowsduration, delimiter=",", fmt="%f")
    numpy.savetxt("udpflowspackets.csv", udpflowspackets, delimiter=",", fmt="%d")
    numpy.savetxt("udpflowsbytes.csv", udpflowsbytes, delimiter=",", fmt="%d")
    numpy.savetxt("udpflowsduration.csv", udpflowsduration, delimiter=",", fmt="%f")
    numpy.savetxt("tcpoverheadratios.csv", tcpoverheadratios, delimiter=",", fmt="%f")

# inter-arrival times
def getinterarrivaltimes():
    allinterarrivaltimes = []
    tcpinterarrivaltimes = []
    udpinterarrivaltimes = []

    for filename in os.listdir(path):
        f = open(path+"/"+filename, 'rb')
        pcap = dpkt.pcap.Reader(f)
        flowtimestamps = dict()

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            layertype = ip.p
            ipsrc = ip.src
            if ipsrc in flowtimestamps:
                flowtimestamps[ipsrc].append(ts)
            else:
                flowtimestamps[ipsrc] = [ts, ]

        for value in flowtimestamps.values():
            interarrivaltimes = [t - s for s, t in zip(value, value[1:])]
            allinterarrivaltimes = allinterarrivaltimes + interarrivaltimes
            if layertype == dpkt.ip.IP_PROTO_TCP:
                tcpinterarrivaltimes = tcpinterarrivaltimes + interarrivaltimes
            elif layertype == dpkt.ip.IP_PROTO_UDP:
                udpinterarrivaltimes = udpinterarrivaltimes + interarrivaltimes
        f.close()

    allinterarrivaltimes.sort()
    tcpinterarrivaltimes.sort()
    udpinterarrivaltimes.sort()

    numpy.savetxt("allinterarrivaltimes.csv", allinterarrivaltimes, delimiter=",", fmt="%f")
    numpy.savetxt("tcpinterarrivaltimes.csv", tcpinterarrivaltimes, delimiter=",", fmt="%f")
    numpy.savetxt("udpinterarrivaltimes.csv", udpinterarrivaltimes, delimiter=",", fmt="%f")

def gettcpstates():
    tcpstates=[]

    for filename in os.listdir(path):
        f = open(path+"/"+filename, 'rb')
        pcap = dpkt.pcap.Reader(f)
        tcpflags = []

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            reset_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0
            fin_flag = (tcp.flags & dpkt.tcp.TH_FIN) != 0
            request_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0

            if reset_flag:
                tcpflags.append("RESET")
            if fin_flag:
                tcpflags.append("FIN")
            if request_flag:
                tcpflags.append("REQUEST")

        if tcpflags.count("FIN") == 2:
            tcpstates.append("FIN")
        elif tcpflags.count("RESET") > 0:
            tcpstates.append("RESET")
        elif len(tcpflags) == 1 and tcpflags[0] == "REQUEST":
            tcpstates.append("REQUEST")
        else:
            tcpstates.append("ONGOING")
        f.close()

        numpy.savetxt("tcpstates.csv", tcpstates, delimiter=",", fmt="%s")


if __name__ == '__main__':
    gettcpstates()