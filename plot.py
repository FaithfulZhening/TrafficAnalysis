import numpy as np
import matplotlib.pyplot as plt


def plot_cdf(data,xlabel,ylabel,title,log):
    if log:
        x = np.log(np.sort(data))
    else:
        x =np.sort(data)
    y = np.arange(0,len(x))/len(x)
    plt.plot(x,y)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.margins(0.02)
    plt.show()

def plot_cdf_together(data_list,labels,xlabel,ylabel,title,log):
    for i in range(len(data_list)):
        data = data_list[i]
        label = labels[i]
        if log:
            x = np.log(np.sort(data))
        else:
            x = np.sort(data)
        y = np.arange(0, len(x)) / len(x)
        plt.plot(x, y, label = label)
        plt.legend(loc='best')
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.margins(0.02)
    plt.show()
