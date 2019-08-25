import matplotlib.pyplot as plt
import numpy as np
import csv

# this file was used to generate the cdf plots needed

def cdfplot(filename, xlabel, ylabel):
    reader = csv.reader(open(filename, 'r'))
    counts = dict()
    totalcounts = 0
    for i in reader:
        key = float(i[0])
        counts[key] = counts.get(key, 0) + 1

    for value in counts.values():
        totalcounts+=value

    print(counts)
    x = sorted(counts.keys())
    y = [0] * len(counts)
    for i in range(0, len(counts)):
        index = x[i]
        y[i] = counts.get(index, 0) / totalcounts
    print(y)
    print(x)
    cy = np.cumsum(y)
    print(cy)
    plt.xscale('log', basex=2)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.plot(x, cy)
    plt.show()

if __name__ == '__main__':
    cdfplot("flowstats/udpinterarrivaltimes.csv", "UDP Interarrival Times (seconds)", "CDF")