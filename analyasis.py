import dpkt
import math
from datetime import datetime
from plot import plot_cdf

# code partly from http://amirrazmjou.net/data-mining-pcap-files-using-weka-and-python-dpkt-library/
def parse_pcap_file(input_file_name):
    #variables
    flow = dict()
    tcp_number = 0;
    udp_number = 0;


    f = open(input_file_name,'rb')
    data = dpkt.pcap.Reader(f)

    for timestamp, packet in data:
        #print(datetime.fromtimestamp(timestamp))
        eth = dpkt.ethernet.Ethernet(packet)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        #only look at tcp and udp packets
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcp_number += 1
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            udp_number += 1
        else:
            continue


        conn = ip.data
        tupl = ((ip.src, conn.sport), (ip.dst, conn.dport))
        rtupl = ((ip.dst, conn.dport), (ip.src, conn.sport))

        if tupl in flow:
            flow[tupl].append((eth,timestamp))
        elif rtupl in flow:
            flow[rtupl].append((eth,timestamp))
        else:
            flow[tupl] = [(eth,timestamp)]
    #write statistics to file

    return flow
    #save_obj(flow)


def main():
    flow = parse_pcap_file('test.pcap')
    #flow = parse_pcap_file('univ1_pt20.pcap')
    statistics_per_flow_duration = []
    statistics_per_tcp_flow_duration = []
    statistics_per_udp_flow_duration = []
    tcp_flow = 0
    udp_flow = 0
    for key, eths in flow.items():
        maxTime = 0
        minTime = math.inf
        for (eth,timestamp) in eths:
            #print(datetime.fromtimestamp(timestamp))
            if timestamp > maxTime:
                maxTime = timestamp
            if timestamp < minTime:
                minTime = timestamp
        #print((maxTime-minTime)*1000)
        duration = (maxTime-minTime)*1000
        statistics_per_flow_duration.append(duration)
        if (eths[0][0].data.p == dpkt.ip.IP_PROTO_TCP):
            tcp_flow += 1
            statistics_per_tcp_flow_duration.append(duration)
        elif (eths[0][0].data.p == dpkt.ip.IP_PROTO_UDP):
            udp_flow += 1
            statistics_per_udp_flow_duration.append(duration)
    plot_cdf(statistics_per_flow_duration)

    #result_file = open('results.txt', "w+")
    #result_file.close()

main()