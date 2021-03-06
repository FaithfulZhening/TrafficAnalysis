import numpy as np
import matplotlib.pyplot as plt


def plot_cdf(data,xlabel,ylabel,title,log):
    x = np.sort(data)
    #delete outlier
    x = x[:round(len(x)*0.9)]
    if log:
        plt.xscale('log')
    y = np.arange(0,len(x))/len(x)
    plt.plot(x,y)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.margins(0.02)
    plt.show()

def plot_cdf_together(data_list,labels,xlabel,ylabel,title,log):
    if log:
        plt.xscale('log')
    for i in range(len(data_list)):
        data = data_list[i]
        label = labels[i]
        x = np.sort(data)
        #delete outlier
        # x = x[:round(len(x)*0.9)]
        y = np.arange(0, len(x)) / len(x)
        plt.plot(x, y, label = label)
        plt.legend(loc='best')
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.margins(0.02)
    plt.show()

def plot_rtt_function(data_list,labels, xlabel,ylabel,title,log):
    if log:
        plt.xscale('log')
    for i in range(len(data_list)):
        data = data_list[i]
        label = labels[i]
        if not data:
            continue
        y,x = zip(*data)
        start_time = x[0]
        x = [timestamp - start_time for timestamp in x]
        plt.plot(x, y, label=label, alpha=0.8)
        plt.legend(loc='best')
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.show()

def plot_host_rtt_function(data,xlabel,ylabel,title):
    # y is representative rtt and x is start time
    y,x = zip(*data)
    plt.plot(x, y)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.margins(0.02)
    plt.show()