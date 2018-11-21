import numpy as np
import matplotlib.pyplot as plt


def plot_cdf(data):
    x = np.log(np.sort(data))
    y = np.arange(0,len(x))/len(x)
    _ = plt.plot(x,y)
    _ = plt.xlabel('time')
    _ = plt.ylabel('percentage')
    plt.margins(0.02)
    plt.show()