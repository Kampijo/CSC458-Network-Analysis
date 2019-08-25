import matplotlib.pyplot as plt
path = '/Users/nygellopez/Documents/CSC458/CourseProject/tcpflows'

def getrtts(filename):
    f = open(path+"/"+filename)
    lines = f.readlines()
    rttdict = dict()
    tsdict = dict()

    for line in lines:
        info = line.split()
        if len(info) < 3:
            continue
        rtt = info[0]
        src = info[1]
        timestamp = info[2]
        if src in rttdict:
            rttdict[src].append(float(rtt))
        if src not in rttdict:
            rttdict[src] = [float(rtt), ]
        if src in tsdict:
            tsdict[src].append(float(timestamp))
        if src not in tsdict:
            tsdict[src] = [float(timestamp), ]
    f.close()

    alpha = 1 / 8
    rttlist1 = [i * 1000 for i in list(rttdict.values())[0]]
    tslist1 = [i - list(tsdict.values())[0][0] for i in list(tsdict.values())[0]]
    srttlist1 = [rttlist1[0], ]
    for i in range(1, len(rttlist1)):
        srttlist1.append((1 - alpha) * srttlist1[i-1] + alpha * rttlist1[i])

    plt.subplot(2, 2, 1)
    plt.title("Sample RTT for %s ->" % filename)
    plt.ylabel("RTT (ms)")
    plt.xlabel("Time (s)")
    plt.plot(tslist1, rttlist1)

    plt.subplot(2, 2, 2)
    plt.title("Estimated RTT for %s ->" % filename)
    plt.ylabel("RTT (ms)")
    plt.xlabel("Time (s)")
    plt.plot(tslist1, srttlist1)

    if len(rttdict.keys()) == 2:
        rttlist2 = [i * 1000 for i in list(rttdict.values())[1]]
        tslist2 = [i - list(tsdict.values())[1][0] for i in list(tsdict.values())[1]]
        srttlist2 = [rttlist1[0], ]
        for i in range(1, len(rttlist2)):
            srttlist2.append((1 - alpha) * srttlist2[i - 1] + alpha * rttlist2[i])

        plt.subplot(2, 2, 3)
        plt.title("Sample RTT for %s <-" % filename)
        plt.ylabel("RTT (ms)")
        plt.xlabel("Time (s)")
        plt.plot(tslist2, rttlist2)

        plt.subplot(2, 2, 4)
        plt.title("Estimated RTT for %s <-" % filename)
        plt.ylabel("RTT (ms)")
        plt.xlabel("Time (s)")
        plt.plot(tslist2, srttlist2)

    plt.tight_layout()
    plt.show()


if __name__ == '__main__':
    getrtts("tcpflow1")