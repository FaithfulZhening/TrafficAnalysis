import dpkt
from plot import plot_cdf, plot_cdf_together
from dataset_analyasis import inet_to_str


def analyze_rtt(keypair,flow):
    #look at each one of the three flows
    for key,cnt in keypair:
        eths = flow[key]
        ((src, sport), (dst, dport)) = key
        #print(inet_to_str(src))
        a_to_b_expected_ack_dict= dict()
        a_to_b_sample_rtt = []
        a_to_b_estimate_rtt = 0
        b_to_a_expected_ack_dict = dict()
        b_to_a_sample_rtt = []
        b_to_a_estimate_rtt = 0
        for (eth, timestamp, size) in eths:
            ip = eth.data
            tcp = ip.data
            tcp_payload_len = ip.len - 20 - tcp.__hdr_len__ - len(tcp.opts)
            # first look at flow from A to B
            if ip.src == src:
                # if this package is already sent, ignore it
                if (tcp.seq + tcp.seq + tcp_payload_len ) in a_to_b_expected_ack_dict:
                    a_to_b_expected_ack_dict[tcp.seq + tcp_payload_len] = -1
                # else add it to the expected ack dict, with timestamp being the value
                else:
                    a_to_b_expected_ack_dict[tcp.seq + tcp_payload_len] = timestamp

                # if this packge ack some package and that package is not resent, add it to sample rtt
                if (tcp.ack in b_to_a_expected_ack_dict) and b_to_a_expected_ack_dict[tcp.ack] != -1:
                    b_to_a_sample_rtt.append(timestamp - b_to_a_expected_ack_dict[tcp.ack])
                    b_to_a_expected_ack_dict[tcp.ack] = -1
                    print(tcp.ack)

            # then look at flow from B to A
            elif ip.src == dst:
                if (tcp.seq + tcp_payload_len) in b_to_a_expected_ack_dict:
                    b_to_a_expected_ack_dict[tcp.seq + tcp_payload_len] = -1
                else:
                    b_to_a_expected_ack_dict[tcp.seq + tcp_payload_len] = timestamp

                if (tcp.ack in a_to_b_expected_ack_dict) and a_to_b_expected_ack_dict[tcp.ack] != -1:
                    a_to_b_sample_rtt.append(timestamp - a_to_b_expected_ack_dict[tcp.ack])
                    a_to_b_expected_ack_dict[tcp.ack] = -1
                    print(tcp.ack)



        print(inet_to_str(ip.src))
        print(a_to_b_sample_rtt)
        print(b_to_a_sample_rtt)

