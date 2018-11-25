import dpkt
import socket
import math
from plot import plot_cdf, plot_cdf_together
from rtt_analysis import analyze_rtt

# tcp hdr length : tcp.__hdr_len__ + len(tcp.opts)
# tcp payload size : ip.len- 20 - tcp.__hdr_len__ - len(tcp.opts)
# code for this function partly from http://amirrazmjou.net/data-mining-pcap-files-using-weka-and-python-dpkt-library/
def parse_pcap_file(input_file_name, oneway):
    #variables
    flow = dict()
    tcp_number = 0
    udp_number = 0
    f = open(input_file_name,'rb')
    data = dpkt.pcap.Reader(f)

    for timestamp, packet,size in data:
        eth = dpkt.ethernet.Ethernet(packet)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        #only look at tcp and udp packets
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcp_number += 1
            tcp = ip.data

        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            udp_number += 1
        else:
            continue

        conn = ip.data
        tupl = ((ip.src, conn.sport), (ip.dst, conn.dport))
        rtupl = ((ip.dst, conn.dport), (ip.src, conn.sport))

        if not oneway:
            if tupl in flow:
                flow[tupl].append((eth, timestamp, size))
            elif rtupl in flow:
                flow[rtupl].append((eth, timestamp, size))
            else:
                flow[tupl] = [(eth, timestamp, size)]
        else:
            if tupl in flow:
                flow[tupl].append((eth, timestamp,size))
            else:
                flow[tupl] = [(eth, timestamp,size)]


    #write statistics to file
    return flow
    #save_obj(flow)



# flow duration and arrival interval analysis
def flow_analysis(flow,oneway):
    #statistics about flow
    statistics_per_flow_duration = []
    statistics_per_tcp_flow_duration = []
    #used to help find top 3 flow duration
    statistics_per_tcp_flow_duration_pair = []
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
        for (eth,timestamp,size) in eths:
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
            statistics_per_tcp_flow_duration_pair.append((key, duration))
        elif is_udp:
            udp_flow += 1
            statistics_per_udp_flow_duration.append(duration)
    # plot_cdf(statistics_per_flow_duration,"","","total flow duration",False)
    # plot_cdf(statistics_per_tcp_flow_duration, "", "", "tcp flow duration", False)
    # plot_cdf(statistics_per_udp_flow_duration, "", "", "udp flow duration", False)
    # plot_cdf(statistics_per_flow_arrival_interval, "", "", "total flow interval", False)
    # plot_cdf(statistics_per_tcp_flow_arrival_interval, "", "", "tcp flow interval", False)
    # plot_cdf(statistics_per_udp_flow_arrival_interval, "", "", "udp flow interval", False)
    #result_file = open('results.txt', "w+")
    #result_file.close()
    return statistics_per_tcp_flow_duration_pair

def tcp_flow_state_analysis(flow):
    #look at each flow
    request_cnt = 0
    reset_cnt = 0
    finished_cnt = 0
    ongoing_cnt = 0
    total_cnt = 0
    for key, eths in flow.items():
        is_request = False
        is_ongoing = False
        is_finished = False
        is_reset = False
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
        for (eth,timestamp,size) in eths:
            ip = eth.data
            tcp = ip.data
            # flags
            fin_flag = (tcp.flags & dpkt.tcp.TH_FIN)
            syn_flag = (tcp.flags & dpkt.tcp.TH_SYN)
            rst_flag = (tcp.flags & dpkt.tcp.TH_RST)
            ack_flag = (tcp.flags & dpkt.tcp.TH_ACK)

            # check for request state
            if syn_flag and (not ack_flag) and len(eths) == 1:
                is_request = True
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
                is_finished = True

        last_packet = eths[-1]
        last_packet_tcp = last_packet[0].data.data
        # check for reset state
        if (last_packet_tcp.flags & dpkt.tcp.TH_RST):
            is_reset = True
        if (not is_request) and (not is_finished) and (not is_reset):
            is_ongoing += 1
        if is_finished:
            finished_cnt += 1
        if is_reset:
            reset_cnt += 1
        if is_request:
            request_cnt += 1
        if is_ongoing:
            ongoing_cnt += 1

    print("finished: "+ str(finished_cnt))
    print("request: "+ str(request_cnt))
    print("reset: " + str(reset_cnt))
    print("ongoing: " + str(ongoing_cnt))
    print("total: " + str(total_cnt))


def flow_size_analysis(flow):
    # flow size analysis
    # Args:
    #   flow: the flow collection
    # Return:
    #   a tuple with tcp flow byte/packet size key pair
    flow_packet_cnt = []
    tcp_flow_packet_cnt = []
    tcp_flow_packet_cnt_pair = []
    udp_flow_packet_cnt = []
    flow_byte_cnt = []
    tcp_flow_byte_cnt = []
    tcp_flow_byte_cnt_pair = []
    udp_flow_byte_cnt = []
    tcp_flow_overhead_ratio= []
    total_length = 0
    for key, eths in flow.items():
        is_tcp = False
        is_udp = False
        packet_cnt = 0
        tcp_packet_cnt = 0
        udp_packet_cnt = 0
        byte_sum = 0
        tcp_byte_sum = 0
        udp_byte_sum = 0
        tcp_packet_header_byte_sum = 0

        if eths[0][0].data.p == dpkt.ip.IP_PROTO_TCP:
            is_tcp = True
        elif eths[0][0].data.p == dpkt.ip.IP_PROTO_UDP:
            is_udp = True
        for (eth,timestamp,size) in eths:
            if is_tcp:
                tcp_packet_cnt += 1
            if is_udp:
                udp_packet_cnt += 1
            packet_cnt += 1
            ip = eth.data
            tcp = ip.data
            total_length += size
            byte_sum += size
            if is_tcp:
                tcp_byte_sum += size
                tcp_packet_header_byte_sum += tcp.__hdr_len__ + len(tcp.opts)
            else:
                udp_byte_sum += size
        # TODO:delete outlier
        if is_tcp:
            tcp_flow_packet_cnt.append(tcp_packet_cnt)
            tcp_flow_byte_cnt.append(tcp_byte_sum)
            tcp_flow_packet_cnt_pair.append((key,tcp_packet_cnt))
            tcp_flow_byte_cnt_pair.append((key,tcp_byte_sum))
            tcp_flow_overhead_ratio.append(tcp_packet_header_byte_sum/tcp_byte_sum)
        if is_udp:
            udp_flow_packet_cnt.append(udp_packet_cnt)
            udp_flow_byte_cnt.append(udp_byte_sum)
        flow_packet_cnt.append(packet_cnt)
        flow_byte_cnt.append(byte_sum)
    #plot_cdf(tcp_flow_packet_cnt, "", "", "TCP Flows Packet Number", False)
    #plot_cdf(udp_flow_packet_cnt, "", "", "UDP Flows Packet Number", True)
    #plot_cdf(flow_packet_cnt, "", "", "All Flows Packet Number", False)
    #plot_cdf(tcp_flow_byte_cnt, "", "", "TCP Flows Bytes", True)
    # plot_cdf(udp_flow_byte_cnt, "", "", "UDP Flows Bytes", False)
    # plot_cdf(flow_byte_cnt, "", "", "All Flows Bytes", False)
    #plot_cdf_together([tcp_flow_byte_cnt,udp_flow_byte_cnt],["tcp flow","udp flow"], "size(byte)","fraction","",True)
    # plot_cdf(tcp_flow_overhead_ratio,"","","TCP Flow Overhead Ratio",False)
    return (tcp_flow_packet_cnt_pair,tcp_flow_byte_cnt_pair)


def find_top_three_largest_flow(tcp_flow_size_pair):
    largest = sorted(tcp_flow_size_pair, key=lambda x:x[1],reverse=True)[:3]
    return largest


def find_top_three_hosts(flow):
    tcp_connection_cnt_pair = dict()
    for key, eths in flow.items():
        ip = eths[0][0].data
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tupl = (ip.src, ip.dst)
            rtupl = (ip.dst,ip.src)
            if tupl in tcp_connection_cnt_pair:
                tcp_connection_cnt_pair[tupl].append(eths)
            elif rtupl in tcp_connection_cnt_pair:
                tcp_connection_cnt_pair[rtupl].append(eths)
            else:
                tcp_connection_cnt_pair[tupl] = [eths]
    # for key, eths_list in tcp_connection_cnt_pair.items():
    #     print(len(eths_list))
    largest = [(k,tcp_connection_cnt_pair[k]) for k in sorted(tcp_connection_cnt_pair, key=lambda x:len(tcp_connection_cnt_pair[x]),reverse=True)][:3]
    return largest


def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

if __name__ == "__main__":
    oneway = False
    parsedFlow = parse_pcap_file('test.pcap', oneway)
    # parsedFlow = parse_pcap_file('univ1_pt20.pcap',oneway)
    #tcp_flow_duration_key_pair = flow_analysis(parsedFlow,oneway)
    #tcp_flow_state_analysis(parsedFlow)
    (tcp_flow_packet_cnt_pair, tcp_flow_byte_cnt_pair) = flow_size_analysis(parsedFlow)