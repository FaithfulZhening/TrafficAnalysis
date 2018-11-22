import dpkt
import socket
import math
from datetime import datetime
from plot import plot_cdf

# code partly from http://amirrazmjou.net/data-mining-pcap-files-using-weka-and-python-dpkt-library/
def parse_pcap_file(input_file_name, oneway):
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

        if not oneway:
            if tupl in flow:
                flow[tupl].append((eth, timestamp))
            elif rtupl in flow:
                flow[rtupl].append((eth, timestamp))
            else:
                flow[tupl] = [(eth, timestamp)]
        else:
            if tupl in flow:
                flow[tupl].append((eth, timestamp))
            else:
                flow[tupl] = [(eth, timestamp)]


    #write statistics to file

    return flow
    #save_obj(flow)


def flow_analysis(flow,oneway):
    #statistics about flow
    statistics_per_flow_duration = []
    statistics_per_tcp_flow_duration = []
    statistics_per_udp_flow_duration = []
    statistics_per_flow_arrival_interval = []
    statistics_per_tcp_flow_arrival_interval = []
    statistics_per_udp_flow_arrival_interval = []
    tcp_flow = 0
    udp_flow = 0
    for key, eths in flow.items():
        is_tcp = False
        is_udp = False
        maxTime = 0
        minTime = math.inf
        last_packet_time = -1
        if eths[0][0].data.p == dpkt.ip.IP_PROTO_TCP:
            is_tcp = True
        elif eths[0][0].data.p == dpkt.ip.IP_PROTO_UDP:
            is_udp = True
        for (eth,timestamp) in eths:
            #print(datetime.fromtimestamp(timestamp))
            if timestamp > maxTime:
                maxTime = timestamp
            if timestamp < minTime:
                minTime = timestamp
            if last_packet_time == -1:
                interval = 0
                last_packet_time = timestamp
            else:
                interval = (timestamp - last_packet_time) * 1000
                last_packet_time = timestamp
            statistics_per_flow_arrival_interval.append(interval)
            if is_tcp:
                statistics_per_tcp_flow_arrival_interval.append(interval)
                print(interval)
            elif is_udp:
                statistics_per_udp_flow_arrival_interval.append(interval)

        #print((maxTime-minTime)*1000)
        #convert to miliseconds
        duration = (maxTime-minTime)*1000
        # if duration != 0:
        #     statistics_per_flow_duration.append(duration)
        statistics_per_flow_duration.append(duration)
        if is_tcp:
            tcp_flow += 1
            statistics_per_tcp_flow_duration.append(duration)
        elif is_udp:
            udp_flow += 1
            statistics_per_udp_flow_duration.append(duration)
    # plot_cdf(statistics_per_flow_duration,"","","total flow duration",False)
    # plot_cdf(statistics_per_tcp_flow_duration, "", "", "tcp flow duration", False)
    # plot_cdf(statistics_per_udp_flow_duration, "", "", "udp flow duration", False)
    plot_cdf(statistics_per_flow_arrival_interval, "", "", "total flow interval", False)
    plot_cdf(statistics_per_tcp_flow_arrival_interval, "", "", "tcp flow interval", False)
    plot_cdf(statistics_per_udp_flow_arrival_interval, "", "", "udp flow interval", False)
    #result_file = open('results.txt', "w+")
    #result_file.close()

def tcp_flow_state_analysis(flow):
    #look at each flow
    request_cnt = 0
    reset_cnt = 0
    finished_cnt = 0
    ongoing_cnt = 0
    failed_cnt = 0
    total_cnt = 0
    flgs = []



    for key, eths in flow.items():
        #only look at tcp flow
        if eths[0][0].data.p != dpkt.ip.IP_PROTO_TCP:
            continue
        total_cnt += 1
        # look at each packet in flow
        (src,sport),(dst,dport) = key
        # if src/dst has sent finbit
        src_fin = False
        dst_fin = False
        # if src/dst has been acknowledged
        src_ack = False
        dst_ack = False
        # the src/dst acknowledged number
        src_seq_number = -1
        dst_seq_number = -1
        for (eth,timestamp) in eths:
            ip = eth.data
            tcp = ip.data
            # flags
            fin_flag = (tcp.flags & dpkt.tcp.TH_FIN)
            syn_flag = (tcp.flags & dpkt.tcp.TH_SYN)
            rst_flag = (tcp.flags & dpkt.tcp.TH_RST)
            ack_flag = (tcp.flags & dpkt.tcp.TH_ACK)

            # check for request state
            if syn_flag and (not ack_flag) and len(eths) == 1:
                request_cnt += 1
            # to find out if a connection finished
            # need to check if both fin msgs are acknowledged
            if fin_flag:
                if ip.src == src:
                    src_fin = True
                    src_seq_number = tcp.seq
                elif ip.src == dst:
                    dst_fin = True
                    dst_seq_number = tcp.seq
            # if src has sent finbit but not acknowledged
            if src_fin and ack_flag and (not src_ack) and (ip.src == dst) and (tcp.ack == src_seq_number + 1):
                src_ack = True
            if dst_fin and ack_flag and (not dst_ack) and (ip.src == src) and (tcp.ack == dst_seq_number + 1):
                dst_ack = True
        if src_ack and dst_ack:
                finished_cnt += 1

        last_packet = eths[-1]
        last_packet_tcp = last_packet[0].data.data
        # check for reset state
        if (last_packet_tcp.flags & dpkt.tcp.TH_RST):
            reset_cnt += 1
    print(finished_cnt)
    print(request_cnt)
    print(reset_cnt)
    print(total_cnt)


def flow_size_analysis(flow):
    flow_packet_cnt = []
    tcp_flow_packet_cnt = []
    udp_flow_packet_cnt = []
    flow_byte_cnt = []
    tcp_flow_byte_cnt = []
    udp_flow_byte_cnt = []
    for key, eths in flow.items():
        is_tcp = False
        is_udp = False
        packet_cnt = 0
        tcp_packet_cnt = 0
        udp_packet_cnt = 0
        byte_sum = 0
        tcp_byte_sum = 0
        udp_byte_sum = 0

        if eths[0][0].data.p == dpkt.ip.IP_PROTO_TCP:
            is_tcp = True
        elif eths[0][0].data.p == dpkt.ip.IP_PROTO_UDP:
            is_udp = True
        for (eth,timestamp) in eths:
            if is_tcp:
                tcp_packet_cnt += 1
            if is_udp:
                udp_packet_cnt += 1
            packet_cnt += 1
            print(eth.__len__())
        #delete outlier
        if is_tcp:
            tcp_flow_packet_cnt.append(tcp_packet_cnt)
        if is_udp:
            udp_flow_packet_cnt.append(udp_packet_cnt)
        flow_packet_cnt.append(packet_cnt)
    #plot_cdf(tcp_flow_packet_cnt, "", "", "TCP Flows Packet Number", False)
    #plot_cdf(udp_flow_packet_cnt, "", "", "UDP Flows Packet Number", True)
    #plot_cdf(flow_packet_cnt, "", "", "All Flows Packet Number", False)



def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

if __name__ == "__main__":
    oneway = False
    flow = parse_pcap_file('test.pcap', oneway)
    #flow = parse_pcap_file('univ1_pt20.pcap',oneway)
    # flow_analysis(flow,oneway)
    #tcp_flow_state_analysis(flow)
    flow_size_analysis(flow)