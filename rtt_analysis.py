import dpkt
from plot import *
from statistics import median
import socket


alpha = 1/8

def analyze_rtt(keypair,flow, name):
    flow_number = 1
    #look at each one of the three flows
    for key,cnt in keypair:
        eths = flow[key]
        ((src, sport), (dst, dport)) = key
        #print(inet_to_str(src))
        a_to_b_expected_ack_dict= dict()
        a_to_b_sample_rtt = []
        a_to_b_estimate_rtt = []
        b_to_a_expected_ack_dict = dict()
        b_to_a_sample_rtt = []
        b_to_a_estimate_rtt = []
        for (eth, timestamp, size) in eths:
            ip = eth.data
            tcp = ip.data
            tcp_payload_len = ip.len - 20 - tcp.__hdr_len__ - len(tcp.opts)
            # first look at flow from A to B
            if ip.src == src:
                # if this package is already sent, ignore it
                if (tcp.seq + tcp_payload_len ) in a_to_b_expected_ack_dict:
                    a_to_b_expected_ack_dict[tcp.seq + tcp_payload_len] = -1
                # else add it to the expected ack dict, with timestamp being the value
                else:
                    a_to_b_expected_ack_dict[tcp.seq + tcp_payload_len] = timestamp

                # if this packge ack some package and that package is not resent, add it to sample rtt
                if (tcp.ack in b_to_a_expected_ack_dict) and b_to_a_expected_ack_dict[tcp.ack] != -1:
                    b_to_a_sample_rtt.append(((timestamp - b_to_a_expected_ack_dict[tcp.ack]) * 1000,timestamp))
                    b_to_a_expected_ack_dict[tcp.ack] = -1
                    #print(tcp.ack)

            # then look at flow from B to A
            elif ip.src == dst:
                if (tcp.seq + tcp_payload_len) in b_to_a_expected_ack_dict:
                    b_to_a_expected_ack_dict[tcp.seq + tcp_payload_len] = -1
                else:
                    b_to_a_expected_ack_dict[tcp.seq + tcp_payload_len] = timestamp

                if (tcp.ack in a_to_b_expected_ack_dict) and a_to_b_expected_ack_dict[tcp.ack] != -1:
                    a_to_b_sample_rtt.append(((timestamp - a_to_b_expected_ack_dict[tcp.ack]) * 1000,timestamp))
                    a_to_b_expected_ack_dict[tcp.ack] = -1
                    #print(tcp.ack)
        estimate_rtt = 0
        for sample_rtt, timestamp in a_to_b_sample_rtt:
            if not a_to_b_estimate_rtt:
                estimate_rtt = sample_rtt
            else:
                estimate_rtt = estimate_rtt * ( 1 - alpha) + alpha * sample_rtt
            a_to_b_estimate_rtt.append((estimate_rtt, timestamp))

        estimate_rtt = 0
        for sample_rtt, timestamp in b_to_a_sample_rtt:
            if not b_to_a_estimate_rtt:
                estimate_rtt = sample_rtt
            else:
                estimate_rtt = estimate_rtt * ( 1 - alpha) + alpha * sample_rtt
            b_to_a_estimate_rtt.append((estimate_rtt, timestamp))

        plot_rtt_function([a_to_b_estimate_rtt, a_to_b_sample_rtt], ["estimation", "sample"], "time (seconds)",
                          "rtt (milliseconds)", name + "Flow number " + str(flow_number) + " From src to dst", False)
        plot_rtt_function([b_to_a_estimate_rtt, b_to_a_sample_rtt], ["estimation", "sample"], "time (seconds)",
                          "rtt (milliseconds)", name + "Flow number " + str(flow_number)+ " From dst to scr", False)
        flow_number += 1


def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def analysis_host_rtt(top_three_host_pair):
    # look at each pair of host
    for (number, eths_list) in top_three_host_pair:
        median_rtt_start_time_pair = []
        median_rtt_start_time_pair_from = []
        median_rtt_start_time_pair_to = []
        # look at each flow
        for eths in eths_list:
            ip = eths[0][0].data
            src = ip.src
            dst = ip.dst
            a_to_b_start_time = -1;
            b_to_a_start_time = -1;
            a_to_b_expected_ack_dict = dict()
            a_to_b_sample_rtt = []
            a_to_b_estimate_rtt = []
            b_to_a_expected_ack_dict = dict()
            b_to_a_sample_rtt = []
            b_to_a_estimate_rtt = []
            for (eth, timestamp, size) in eths:
                ip = eth.data
                tcp = ip.data
                tcp_payload_len = ip.len - 20 - tcp.__hdr_len__ - len(tcp.opts)
                fin_flag = (tcp.flags & dpkt.tcp.TH_FIN)
                syn_flag = (tcp.flags & dpkt.tcp.TH_SYN)
                rst_flag = (tcp.flags & dpkt.tcp.TH_RST)
                ack_flag = (tcp.flags & dpkt.tcp.TH_ACK)
                # first look at flow from A to B
                if ip.src == src:
                    if a_to_b_start_time == -1:
                        a_to_b_start_time = timestamp
                    # if this package is already sent, ignore it
                    if fin_flag:
                        expected_value = tcp.seq + tcp_payload_len + 1
                    else:
                        expected_value = tcp.seq + tcp_payload_len

                    if (expected_value) in a_to_b_expected_ack_dict:
                        a_to_b_expected_ack_dict[expected_value] = -1
                    # else add it to the expected ack dict, with timestamp being the value
                    else:
                        a_to_b_expected_ack_dict[expected_value] = timestamp

                    # if this packge ack some package and that package is not resent, add it to sample rtt
                    if (tcp.ack in b_to_a_expected_ack_dict) and b_to_a_expected_ack_dict[tcp.ack] != -1:
                        b_to_a_sample_rtt.append(((timestamp - b_to_a_expected_ack_dict[tcp.ack]) * 1000, timestamp))
                        b_to_a_expected_ack_dict[tcp.ack] = -1
                        # print(tcp.ack)

                # then look at flow from B to A
                elif ip.src == dst:
                    if b_to_a_start_time == -1:
                        b_to_a_start_time = timestamp

                    if fin_flag:
                        expected_value = tcp.seq + tcp_payload_len + 1
                    else:
                        expected_value = tcp.seq + tcp_payload_len

                    if (expected_value) in b_to_a_expected_ack_dict:
                        b_to_a_expected_ack_dict[expected_value] = -1
                    else:
                        b_to_a_expected_ack_dict[expected_value] = timestamp

                    if (tcp.ack in a_to_b_expected_ack_dict) and a_to_b_expected_ack_dict[tcp.ack] != -1:
                        a_to_b_sample_rtt.append(((timestamp - a_to_b_expected_ack_dict[tcp.ack]) * 1000, timestamp))
                        a_to_b_expected_ack_dict[tcp.ack] = -1
                        # print(tcp.ack)

            estimate_rtt = 0
            for sample_rtt, timestamp in a_to_b_sample_rtt:
                if not a_to_b_estimate_rtt:
                    estimate_rtt = sample_rtt
                else:
                    estimate_rtt = estimate_rtt * (1 - alpha) + alpha * sample_rtt
                a_to_b_estimate_rtt.append(estimate_rtt)

            estimate_rtt = 0
            for sample_rtt, timestamp in b_to_a_sample_rtt:
                if not b_to_a_estimate_rtt:
                    estimate_rtt = sample_rtt
                else:
                    estimate_rtt = estimate_rtt * (1 - alpha) + alpha * sample_rtt
                b_to_a_estimate_rtt.append(estimate_rtt)

            if a_to_b_estimate_rtt:
                median_rtt_start_time_pair.append((median(sorted(a_to_b_estimate_rtt)), a_to_b_start_time))
                median_rtt_start_time_pair_from.append((median(sorted(a_to_b_estimate_rtt)), a_to_b_start_time))
            if b_to_a_estimate_rtt:
                median_rtt_start_time_pair.append((median(sorted(b_to_a_estimate_rtt)), b_to_a_start_time))
                median_rtt_start_time_pair_to.append((median(sorted(b_to_a_estimate_rtt)), b_to_a_start_time))
        if median_rtt_start_time_pair:
            median_rtt_start_time_pair.sort(key=lambda x: x[1])
            median_rtt_start_time_pair_from.sort(key=lambda x: x[1])
            median_rtt_start_time_pair_to.sort(key=lambda x: x[1])
            plot_host_rtt_function(median_rtt_start_time_pair_from,"start time","representative rtt (ms)","Host RTT Analysis (A to B)")
            plot_host_rtt_function(median_rtt_start_time_pair_to, "start time", "representative rtt (ms)",
                                   "Host RTT Analysis (B to A)")