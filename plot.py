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