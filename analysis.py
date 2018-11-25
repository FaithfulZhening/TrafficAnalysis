from dataset_analyasis import *
from rtt_analysis import *


if __name__ == "__main__":
    oneway = False
    #parsedFlow = parse_pcap_file('test.pcap', oneway)
    parsedFlow = parse_pcap_file('univ1_pt20.pcap',oneway)
    #tcp_flow_duration_key_pair = flow_analysis(parsedFlow,oneway)
    #tcp_flow_state_analysis(parsedFlow)
    #(tcp_flow_packet_cnt_pair, tcp_flow_byte_cnt_pair) = flow_size_analysis(parsedFlow)
    # analyze_rtt(find_top_three_largest_flow(tcp_flow_packet_cnt_pair),parsedFlow, "Top three packet number")
    # analyze_rtt(find_top_three_largest_flow(tcp_flow_byte_cnt_pair), parsedFlow, "Top three total byte size")
    # analyze_rtt(find_top_three_largest_flow(tcp_flow_duration_key_pair), parsedFlow, "Top three duration")
    top_three_hosts = find_top_three_hosts(parsedFlow)
    analysis_host_rtt(top_three_hosts)