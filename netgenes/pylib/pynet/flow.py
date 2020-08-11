# 3rdParty
try:
    import numpy as np
except ImportError:
    raise ImportError("You need to do 'pip3 install -r requirements.txt' to be able to use this program.")

# Ours
from pylib.pynet.netobject_utils import *
from pylib.pyaux.utils import datetime_to_unixtime, unixtime_to_datetime
from pylib.pyaux.utils import Colors

def build_l3_uniflows(packets):
    """Associate layer-3 uniflow ids to packets"""
    l3_uniflows = dict()
    l3_uniflow_ids = list()
    for packet in packets:
        flow_id = tuple(packet[0])
        try:
            l3_uniflows[flow_id].append(packet)
        except KeyError:
            l3_uniflow_ids.append(flow_id)
            l3_uniflows[flow_id] = [packet]

    return l3_uniflows, l3_uniflow_ids

def build_l3_biflows(l3_uniflows, l3_uniflow_ids):
    """Join unidirectional flow information into its bidirectional flow equivalent"""
    def get_unique_matching_l3_uniflow_ids(l3_uniflows, l3_uniflow_ids):
        """Local helper function to return matching unidirectional flow ids, with l3_fwd_flow_id
        as key and l3_bwd_flow_id as value, and not vice-versa"""
        matching_l3_uniflow_ids_dict = dict()
        l3_fwd_flow_ids = list()
        for l3_uniflow_id in l3_uniflow_ids:
            reversed_l3_uniflow_id = (l3_uniflow_id[2], l3_uniflow_id[3], l3_uniflow_id[0],
                l3_uniflow_id[1], l3_uniflow_id[4], l3_uniflow_id[5])

            # Note: O(n**2) --> O(n) optimization done using dictionary search
            if reversed_l3_uniflow_id in l3_uniflows:
                if reversed_l3_uniflow_id not in matching_l3_uniflow_ids_dict:
                    l3_fwd_flow_ids.append(l3_uniflow_id)
                    matching_l3_uniflow_ids_dict[l3_uniflow_id] = reversed_l3_uniflow_id
            else:
                if reversed_l3_uniflow_id not in matching_l3_uniflow_ids_dict:
                    l3_fwd_flow_ids.append(l3_uniflow_id)
                    matching_l3_uniflow_ids_dict[l3_uniflow_id] = False
        return matching_l3_uniflow_ids_dict, l3_fwd_flow_ids

    matching_l3_uniflow_ids_dict, l3_fwd_flow_ids = get_unique_matching_l3_uniflow_ids(l3_uniflows, l3_uniflow_ids)
    l3_biflows = dict()
    l3_biflow_ids = list()

    for l3_fwd_flow_id in l3_fwd_flow_ids:
        # have in mind every l3_uniflow_id in this list will have been constituted by the first packet ever recorded in that flow,
        # which is assumed to be the first request, i.e., a 'forward' packet, hence the researcher defines l3_biflow_id = l3_fwd_flow_id
        l3_bwd_flow_id = matching_l3_uniflow_ids_dict[l3_fwd_flow_id]
        l3_biflow_ids.append(l3_fwd_flow_id)
        if l3_bwd_flow_id:
            l3_biflows[l3_fwd_flow_id] = l3_uniflows[l3_fwd_flow_id] + l3_uniflows[l3_bwd_flow_id]
        else:
            l3_biflows[l3_fwd_flow_id] = l3_uniflows[l3_fwd_flow_id]
    return l3_biflows, l3_biflow_ids

def build_l4_biflows(l3_biflows, l3_biflow_ids, debug=False):
    """Separate layer-3 bidirectional flows by layer-4 protocol and
    build layer-4 bidirectional flows according to TCP and UDP RFCs"""
    def build_rfc793_tcp_biflows(tmp_tcp_biflows, tmp_tcp_biflow_ids, debug=False):
        """Local helper function to build TCP BiFlows according to RFC793"""
        # ====================
        # START: Aux Functions
        # ====================
        def set_flow_inner_sep_counter(packet_list, flow_inner_sep_counter):
            """Local helper function to update flows' packets to the right flow_inner_sep_counter,
            thus correcting their flow_id values"""
            packet_list_len = len(packet_list)
            for i in range(packet_list_len):
                # set each packet's flow_inner_sep_counter
                packet_list[i][0][5] = flow_inner_sep_counter
            return packet_list

        def same_seq_packet_test(packet1, packet2):
            """Checks if packet1 and packet2 have the same SEQ."""
            tcp_seq1, tcp_seq2 = packet1[8], packet2[8]
            return (tcp_seq1 == tcp_seq2)

        def duplicate_packet_test(packet1, packet2):
            """Checks if packet1 and packet2 are duplicates (retransmission/duplicate), which
            means the packets share the same SEQ, same ACK and same flags."""
            tcp_seq1, tcp_ack1 = packet1[8], packet1[9]
            tcp_flags1 = packet1[-8:]
            tcp_seq2, tcp_ack2 = packet2[8], packet2[9]
            tcp_flags2 = packet2[-8:]
            return (tcp_seq1 == tcp_seq2) and (tcp_ack1 == tcp_ack2) and (tcp_flags1 == tcp_flags2)

        def sequential_packet_test(packet1, packet2):
            """Checks if packet2 is the SEQ/ACK sequential packet after packet1"""
            # account for SYN flag bit
            tcp_data_len1 = 1 if packet1[7] == 0 else packet1[7]
            tcp_seq1, tcp_ack1 = packet1[8], packet1[9]
            tcp_data_len2 = 1 if packet2[7] == 0 else packet2[7]
            tcp_seq2, tcp_ack2 = packet2[8], packet2[9]
            return (tcp_ack2 == tcp_seq1 + tcp_data_len1)

        # ==================
        # END: Aux Functions
        # ==================

        rfc793_tcp_biflow_conceptual_features = dict()
        rfc793_tcp_biflows = dict()
        rfc793_tcp_biflow_ids = []
        n_disconected_rfc793_packets = 0

        # create RFC793-compliant TCP flows
        for tmp_tcp_biflow_id in tmp_tcp_biflow_ids:
            curr_5tuple_flow = tmp_tcp_biflows[tmp_tcp_biflow_id]
            curr_5tuple_flow_n_packets = len(curr_5tuple_flow)
            if curr_5tuple_flow_n_packets == 0:
                print("[!] A flow can't have 0 packets.", flush=True)
                exit()

            if debug == "2":
                print("[D2] Wireshark Flow: %s" %(biflow_id_to_pcap_filter(tmp_tcp_biflow_id)), flush=True)

            # ===============================
            # RFC793 Parsing and Flow Control
            # ===============================
            rfc793_tcp_biflow_id = None
            # sorting the packets in each flow by timestamp
            curr_5tuple_flow.sort(key=lambda x: x[1])

            # tcp_data_len - packet[7], tcp_seq - packet[8], tcp_ack - packet[9], tcp_flags - packet[-8:]
            # Flow controller could be a list of: (1) ranges between which flows exist;
            # (2) flow initialization method; (3) flow connection state; (4) flow termination method
            # 5tuple-flow and tcp-separated flow beginnings coincide
            initiation_packet_index = 0
            termination_packet_index = None
            # counter to separate several tcp-separated flows (6tuple-flow) inside the same 5tuple-flow
            flow_inner_sep_counter = 0

            first_init_packet, second_init_packet, third_init_packet = None, None, None
            first_term_packet, second_term_packet, third_term_packet = None, None, None
            flow_initiation_type = "Initiation not seen"
            flow_connection_type  = "Connection type undetermined"
            flow_termination_type = "Termination not seen"
            for i in range(curr_5tuple_flow_n_packets):
                # in case there's more 6tuple flows, need to skip already processed packets
                # (e.g., needed in case of graceful termination)
                if i < initiation_packet_index:
                    continue
                is_curr_penultimate_packet = (i == curr_5tuple_flow_n_packets-2)
                is_curr_last_packet = (i == curr_5tuple_flow_n_packets-1)
                # ====================================================================
                # Get first, second and third relative (from current position) packets
                # ====================================================================              
                first_rel_packet = curr_5tuple_flow[i]
                tcp_data_len1 = first_rel_packet[7]
                tcp_seq1 = first_rel_packet[8]
                tcp_ack1 = first_rel_packet[9]
                flag_fin1, flag_syn1, flag_rst1, flag_psh1, flag_ack1, flag_urg1, flag_ece1, flag_cwr1 = first_rel_packet[-8:]

                if debug == "2":
                    print("[D2] Packet %s/%s" %(i+1, curr_5tuple_flow_n_packets), flush=True)
                    print("[D2] Data Length: %s (Data Length)" %(tcp_data_len1), flush=True)
                    print("[D2] SEQ/ACK: %s (SEQ), %s (ACK)" %(tcp_seq1, tcp_ack1), flush=True)
                    print("[D2] Flags: %s (FIN), %s (SYN), %s (RST), %s (PSH)" %(flag_fin1, flag_syn1, flag_rst1, flag_psh1), flush=True)
                    print("[D2] Flags: %s (ACK), %s (URG), %s (ECE), %s (CWR)" %(flag_ack1, flag_urg1, flag_ece1, flag_cwr1), flush=True)
                
                # =======================
                # TCP Initiation P1-P2-P3
                # =======================
                # if the initiation is not complete...
                if flow_initiation_type != "3-way Handshake":
                    # if first_init_packet wasn't seen, tcp_ack1 value is 0 and it's a SYN packet, then
                    # first_rel_packet is first_init_packet
                    # DEV-NOTE: condition "(tcp_ack1 == 0)" removed due to cases where first packet is a SYN packet with
                    # a non-zero ACK value, which is not normal TCP behavior, but we must account for these cases because
                    # machines still respond to such packets smartly devised by adversaries
                    # DEV-NOTE: to include connections with an unseen initiation, also remove the condition "flag_syn1"
                    if (not first_init_packet) and flag_syn1:
                        first_init_packet = first_rel_packet
                        flow_initiation_type = "Requested Connection"
                        initiation_packet_index = i
                        # Init1 - Requested Connection (syn)
                        # Valid connection states:
                        # Init1.1 - Dropped Connection (current packet is last non-duplicate packet)
                        # DEV-NOTE: need to test with multiple duplicate syn packets
                        # (thus, belonging to the same flow)
                        for j in range(i+1, curr_5tuple_flow_n_packets):
                            packet_n = curr_5tuple_flow[j]
                            tcp_dup_p1_pn = duplicate_packet_test(first_init_packet, packet_n)
                            # if a non-duplicate packet was found, then it is not a dropped connection
                            if not tcp_dup_p1_pn:
                                break
                            # else, if n is a duplicate syn packet and it is also the last one,
                            # then it's a dropped connection
                            elif (j == curr_5tuple_flow_n_packets-1):
                                flow_connection_type = "Dropped Connection"
                    # else first_init_packet remains unknown and we'll have to keep parsing

                    if is_curr_last_packet:
                        second_rel_packet = None
                    elif first_init_packet and not second_init_packet:
                        init_flag_fin1, init_flag_syn1, init_flag_rst1, init_flag_psh1, init_flag_ack1,\
                        init_flag_urg1, init_flag_ece1, init_flag_cwr1 = first_init_packet[-8:]
                        second_rel_packet = curr_5tuple_flow[i+1]
                        flag_fin2, flag_syn2, flag_rst2, flag_psh2, flag_ack2, flag_urg2, flag_ece2, flag_cwr2 = second_rel_packet[-8:]
                        tcp_seq_p1_p2 = sequential_packet_test(first_init_packet, second_rel_packet)
                        if debug == "2":
                            print("[D2] InitP1: %s" %(first_init_packet))
                            print("[D2] P2: %s" %(second_rel_packet))
                            print("[D2] InitP1-P2 sequential: %s" %(tcp_seq_p1_p2))

                        # if first_init_packet and second_rel_packet are sequential, test flag combinations
                        if tcp_seq_p1_p2:
                            if init_flag_syn1 and flag_ack2:
                                # Init2 - 2-way Handshake (syn, ack)
                                # Valid connection states:
                                # Init2.1 - Rejected Connection (syn, rst-ack)
                                # Init2.2 - Established Half-duplex Connection (syn, syn-ack)
                                second_init_packet = second_rel_packet
                                flow_initiation_type = "2-way Handshake"

                                if flag_rst2:
                                    flow_connection_type = "Rejected Connection"
                                elif flag_syn2:
                                    flow_connection_type = "Established Half-duplex Connection"
                        # else the real second_init_packet remains unknown and we'll have to keep parsing
                    
                    if is_curr_penultimate_packet:
                        second_rel_packet = None
                    elif is_curr_last_packet:
                        third_rel_packet = None
                    elif first_init_packet and second_init_packet and not third_init_packet:
                        init_flag_fin1, init_flag_syn1, init_flag_rst1, init_flag_psh1, init_flag_ack1,\
                        init_flag_urg1, init_flag_ece1, init_flag_cwr1 = first_init_packet[-8:]
                        init_flag_fin2, init_flag_syn2, init_flag_rst2, init_flag_psh2, init_flag_ack2,\
                        init_flag_urg2, init_flag_ece2, init_flag_cwr2 = second_init_packet[-8:]
                        third_rel_packet = curr_5tuple_flow[i+2]
                        flag_fin3, flag_syn3, flag_rst3, flag_psh3, flag_ack3, flag_urg3, flag_ece3, flag_cwr3 = third_rel_packet[-8:]
                        tcp_seq_p2_p3 = sequential_packet_test(second_init_packet, third_rel_packet)
                        if debug == "2":
                            print("[D2] InitP2: %s" %(second_init_packet))
                            print("[D2] P3: %s" %(third_rel_packet))
                            print("[D2] InitP2-P3 sequential: %s" %(tcp_seq_p2_p3))
                        # if second_init_packet and third_rel_packet are sequential
                        # third_rel_packet is the third_init_packet
                        if tcp_seq_p2_p3:
                            if init_flag_syn1 and (init_flag_syn2 and init_flag_ack2) and flag_ack3:
                                # Init3 - 3-way Handshake (syn,syn-ack,ack)
                                # Valid connection states:
                                # Init3.1 - Established Full-duplex Connection
                                third_init_packet = third_rel_packet
                                flow_initiation_type = "3-way Handshake"
                                flow_connection_type = "Established Full-duplex Connection"
                        # else the real third_init_packet remains unknown and we'll have to keep parsing

                # ========================
                # TCP Termination P1-P2-P3
                # ========================
                # if, at least, a connection was requested...
                if flow_initiation_type != "Initiation not seen":
                    # if first_term_packet wasn't seen and current packet is a FIN packet
                    # then, first_rel_packet is first_term_packet
                    if (not first_term_packet) and flag_fin1:
                        first_term_packet = first_rel_packet
                    # else, if termination wasn't seen yet, constantly check for RST flag and
                    # for last packet termination
                    elif flow_termination_type == "Termination not seen":
                        if flag_rst1:
                            # Term1 - Abort Termination (rst)
                            first_term_packet = first_rel_packet
                            flow_termination_type = "Abort Termination"
                            # MAYBE-TODO: packets outside flows after termination are being discarded
                            # (to make it consistent with Wireshark, this could be solved by saving
                            # same-seq/duplicate packets inside the same 6tuple flow, but doing it this
                            # way is more consistent)
                            termination_packet_index = i
                        elif is_curr_last_packet:
                            # Term2 - Null Termination (current packet is the last packet)
                            first_term_packet = first_rel_packet
                            flow_termination_type = "Null Termination"
                            termination_packet_index = i
                    # else first_term_packet remains unknown and we'll have to keep parsing

                    if is_curr_last_packet:
                        second_rel_packet = None
                    elif first_term_packet and not second_term_packet:
                        term_flag_fin1, term_flag_syn1, term_flag_rst1, term_flag_psh1, term_flag_ack1,\
                        term_flag_urg1, term_flag_ece1, term_flag_cwr1 = first_term_packet[-8:]
                        second_rel_packet = curr_5tuple_flow[i+1]
                        flag_fin2, flag_syn2, flag_rst2, flag_psh2, flag_ack2, flag_urg2, flag_ece2, flag_cwr2 = second_rel_packet[-8:]
                        tcp_seq_p1_p2 = sequential_packet_test(first_term_packet, second_rel_packet)
                        if debug == "2":
                            print("[D2] TermP1: %s" %(first_term_packet))
                            print("[D2] P2: %s" %(second_rel_packet))
                            print("[D2] TermP1-P2 sequential: %s" %(tcp_seq_p1_p2))
                        # if first_term_packet and second_rel_packet are sequential, test flag combinations
                        if tcp_seq_p1_p2:
                            # Unfinished Term3 - Graceful Termination (fin, fin-ack)
                            if term_flag_fin1 and (flag_fin2 and flag_ack2): second_term_packet = second_rel_packet
                        # else the real second_term_packet remains unknown and we'll have to keep parsing
                    if is_curr_penultimate_packet:
                        second_rel_packet = None
                    elif is_curr_last_packet:
                        third_rel_packet = None
                    elif first_term_packet and second_term_packet and not third_term_packet:
                        term_flag_fin1, term_flag_syn1, term_flag_rst1, term_flag_psh1, term_flag_ack1,\
                        term_flag_urg1, term_flag_ece1, term_flag_cwr1 = first_term_packet[-8:]
                        term_flag_fin2, term_flag_syn2, term_flag_rst2, term_flag_psh2, term_flag_ack2,\
                        term_flag_urg2, term_flag_ece2, term_flag_cwr2 = second_term_packet[-8:]
                        third_rel_packet = curr_5tuple_flow[i+2]
                        flag_fin3, flag_syn3, flag_rst3, flag_psh3, flag_ack3, flag_urg3, flag_ece3, flag_cwr3 = third_rel_packet[-8:]
                        tcp_seq_p2_p3 = sequential_packet_test(second_term_packet, third_rel_packet)
                        if debug == "2":
                            print("[D2] TermP2: %s" %(second_term_packet))
                            print("[D2] P3: %s" %(third_rel_packet))
                            print("[D2] TermP2-P3 sequential: %s" %(tcp_seq_p2_p3))
                        # if second_term_packet and third_rel_packet are sequential, test flag combinations
                        if tcp_seq_p2_p3:
                            # Term3 - Graceful Termination (fin, fin-ack, ack)
                            if term_flag_fin1 and (term_flag_fin2 and term_flag_fin2) and flag_ack3:
                                third_term_packet = third_rel_packet
                                flow_termination_type = "Graceful Termination"
                                # MAYBE-TODO: packets outside flows after termination are being discarded
                                # (to make it consistent with Wireshark, this could be solved by saving
                                # same-seq/duplicate packets inside the same 6tuple flow, but doing it this
                                # way is more consistent)
                                termination_packet_index = i + 2
                        # else the real third_term_packet remains unknown and we'll have to keep parsing

                if debug == "2":
                    print("[D2] %s (Flow Initiation Type)" %(flow_initiation_type))
                    print("[D2] %s (Flow Connection Type)" %(flow_connection_type))
                    print("[D2] %s (Flow Termination Type)" %(flow_termination_type))

                # =======================================
                # TREAT EACH CONNECTION STATE DIFFERENTLY
                # =======================================
                # if initiation was not seen, packet is discarded
                if flow_initiation_type == "Initiation not seen":
                    n_disconected_rfc793_packets += 1

                # if termination was seen, then,
                # it's time that packets are saved for
                # the terminated 6tuple BiFlow
                if flow_termination_type != "Termination not seen":
                    # 6tuple BiFlow Id
                    rfc793_tcp_biflow_id = (tmp_tcp_biflow_id[0], tmp_tcp_biflow_id[1], tmp_tcp_biflow_id[2],\
                        tmp_tcp_biflow_id[3], tmp_tcp_biflow_id[4], tmp_tcp_biflow_id[5] + flow_inner_sep_counter)
                    # ---------------------------------------------------------
                    # Keep 6tuple BiFlow, its packets and its inherent features
                    # ---------------------------------------------------------
                    # DEV-NOTE: "int" function usefully directly converts True and False to 1 and 0
                    rfc793_tcp_biflow_conceptual_features[rfc793_tcp_biflow_id] = [
                        int(flow_initiation_type == "Requested Connection"),
                        int(flow_initiation_type == "2-way Handshake"),
                        int(flow_initiation_type == "3-way Handshake"),
                        int(flow_connection_type == "Dropped Connection"),
                        int(flow_connection_type == "Rejected Connection"),
                        int(flow_connection_type == "Established Half-duplex Connection"),
                        int(flow_connection_type == "Established Full-duplex Connection"),
                        int(flow_termination_type == "Abort Termination"),
                        int(flow_termination_type == "Null Termination"),
                        int(flow_termination_type == "Graceful Termination")
                    ]
                    packet_list = curr_5tuple_flow[initiation_packet_index:termination_packet_index+1]
                    packet_list = set_flow_inner_sep_counter(packet_list, flow_inner_sep_counter)
                    rfc793_tcp_biflows[rfc793_tcp_biflow_id] = packet_list
                    rfc793_tcp_biflow_ids.append(rfc793_tcp_biflow_id)
                    # ------------------------------
                    # RESET all 6tuple BiFlow values
                    # ------------------------------
                    # increment 6tuple counter
                    flow_inner_sep_counter += 1
                    # (if there is one) next initiation packet index
                    initiation_packet_index = termination_packet_index+1
                    # reset all other values to their defaults
                    termination_packet_index = None
                    first_init_packet, second_init_packet, third_init_packet = None, None, None
                    first_term_packet, second_term_packet, third_term_packet = None, None, None
                    flow_initiation_type = "Initiation not seen"
                    flow_connection_type  = "Connection type undetermined"
                    flow_termination_type = "Termination not seen"

        return rfc793_tcp_biflows, rfc793_tcp_biflow_ids, rfc793_tcp_biflow_conceptual_features, n_disconected_rfc793_packets

    # ==================================
    # Separate L3 BiFlows by L4 protocol
    # ==================================
    udp_biflows, udp_biflow_ids = dict(), list()
    tmp_tcp_biflows, tmp_tcp_biflow_ids = dict(), list()
    for l3_biflow_id in l3_biflow_ids:
        biflow = l3_biflows[l3_biflow_id]
        l4_protocol_name = l3_biflow_id[4]
        if l4_protocol_name == "UDP":
            udp_biflows[l3_biflow_id] = biflow
            udp_biflow_ids.append(l3_biflow_id)
        elif l4_protocol_name == "TCP":
            tmp_tcp_biflows[l3_biflow_id] = biflow
            tmp_tcp_biflow_ids.append(l3_biflow_id)
        else:
            print("ERROR: Run-time should never reach this branch, but in case it does, it means that another protocol was let through in an earlier stage.",\
                flush=True)
            exit()

    # Apply RFC793 to the unseparated TCP BiFlows
    tcp_biflows, tcp_biflow_ids, rfc793_tcp_biflow_conceptual_features, n_disconected_rfc793_packets = build_rfc793_tcp_biflows(tmp_tcp_biflows, tmp_tcp_biflow_ids, debug)
    return udp_biflows, udp_biflow_ids, tcp_biflows, tcp_biflow_ids, rfc793_tcp_biflow_conceptual_features, n_disconected_rfc793_packets


def get_l3_l4_biflow_gene_generators(genes_dir, biflows, biflow_ids, l4_protocol=None, l4_conceptual_features=None, verbose=True):
    """Return L3-L4 biflow gene generators"""
    def calculate_l3_l4_biflow_genes(genes_dir, biflows, biflow_ids, l4_protocol=None, l4_conceptual_features=None, verbose=True):
        """Calculate and yield L3-L4 biflow genes"""
        time_scale_factor = 1000.0
        # =================
        # IPv4 GENES HEADER
        # =================
        ipv4_biflow_genes_header_list = get_network_object_header(genes_dir, "biflow", "ipv4")
        # ===============
        # L4 GENES HEADER
        # ===============
        ipv4_l4_biflow_genes_header_list = get_network_object_header(genes_dir, "biflow", "ipv4-l4")
        # ================
        # TCP GENES HEADER
        # ================
        ipv4_tcp_biflow_genes_header_list = get_network_object_header(genes_dir, "biflow", "ipv4-tcp")

        # IPv4 Header
        ipv4_all_biflow_genes_header_list = ipv4_biflow_genes_header_list
        if l4_protocol:
            # IPv4-L4 Header
            ipv4_all_biflow_genes_header_list += ipv4_l4_biflow_genes_header_list
            if l4_protocol == "UDP":
                pass
            elif l4_protocol == "TCP":
                ipv4_all_biflow_genes_header_list += ipv4_tcp_biflow_genes_header_list

        for biflow_id in biflow_ids:
            # DEV-NOTE: curr_biflow[packet_index][packet_gene_index]
            # NOTE: backward packets may not exist
            curr_biflow = biflows[biflow_id]
            if l4_conceptual_features:
                curr_biflow_l4_conceptual_features = l4_conceptual_features[biflow_id]
                # ====================================
                # Set Local L4 Conceptual Feature Vars
                # ====================================
                # TCP
                if l4_protocol == "TCP":
                    biflow_eth_ipv4_tcp_initiation_requested_connection = curr_biflow_l4_conceptual_features[0]
                    biflow_eth_ipv4_tcp_initiation_two_way_handshake = curr_biflow_l4_conceptual_features[1]
                    biflow_eth_ipv4_tcp_initiation_three_way_handshake = curr_biflow_l4_conceptual_features[2]
                    biflow_eth_ipv4_tcp_connection_dropped = curr_biflow_l4_conceptual_features[3]
                    biflow_eth_ipv4_tcp_connection_rejected = curr_biflow_l4_conceptual_features[4]
                    biflow_eth_ipv4_tcp_connection_established_half_duplex = curr_biflow_l4_conceptual_features[5]
                    biflow_eth_ipv4_tcp_connection_established_full_duplex = curr_biflow_l4_conceptual_features[6]
                    biflow_eth_ipv4_tcp_termination_abort = curr_biflow_l4_conceptual_features[7]
                    biflow_eth_ipv4_tcp_termination_null = curr_biflow_l4_conceptual_features[8]
                    biflow_eth_ipv4_tcp_termination_graceful = curr_biflow_l4_conceptual_features[9]

            # =========================
            # PREPARE DATA STRUCTURES |
            # =========================
            # ======
            # Packet
            # ======
            # ----------------
            # Packet Frequency
            # ----------------
            biflow_any_n_packets = len(curr_biflow)
            biflow_fwd_n_packets = 0
            biflow_bwd_n_packets = 0

            # ================================
            # Packet & Byte Frequency Features
            # ================================
            # done below

            # -------------------
            # Inter-arrival Times
            # -------------------
            biflow_any_packet_iats = list()
            biflow_fwd_packet_iats = list()
            biflow_bwd_packet_iats = list()

            # ====
            # IPv4
            # ====
            # -------------------
            # IPv4 Header Lengths
            # -------------------
            biflow_any_eth_ipv4_header_lens = list()
            biflow_fwd_eth_ipv4_header_lens = list()
            biflow_bwd_eth_ipv4_header_lens = list()

            # -----------------
            # IPv4 Data Lengths
            # -----------------
            biflow_any_eth_ipv4_data_lens = list()
            biflow_fwd_eth_ipv4_data_lens = list()
            biflow_bwd_eth_ipv4_data_lens = list()

            # ------------------------
            # IPv4 Fragmentation Flags
            # ------------------------
            biflow_any_eth_ip_df_flags = list()
            biflow_fwd_eth_ip_df_flags = list()
            biflow_bwd_eth_ip_df_flags = list()

            biflow_any_eth_ip_mf_flags = list()
            biflow_fwd_eth_ip_mf_flags = list()
            biflow_bwd_eth_ip_mf_flags = list()

            # ==
            # L4
            # ==
            # ------------------------
            # L4 Data Packet Frequency
            # ------------------------
            biflow_any_eth_ipv4_l4_n_data_packets = 0
            biflow_fwd_eth_ipv4_l4_n_data_packets = 0
            biflow_bwd_eth_ipv4_l4_n_data_packets = 0

            # -----------------
            # L4 Header Lengths
            # -----------------
            biflow_any_eth_ipv4_l4_header_lens = list()
            biflow_fwd_eth_ipv4_l4_header_lens = list()
            biflow_bwd_eth_ipv4_l4_header_lens = list()

            # ---------------
            # L4 Data Lengths
            # ---------------
            biflow_any_eth_ipv4_l4_data_lens = list()
            biflow_fwd_eth_ipv4_l4_data_lens = list()
            biflow_bwd_eth_ipv4_l4_data_lens = list()

            # ===
            # TCP
            # ===
            # --------------
            # TCP Flow Flags
            # --------------
            biflow_any_eth_ipv4_tcp_fin_flags = list()
            biflow_any_eth_ipv4_tcp_syn_flags = list()
            biflow_any_eth_ipv4_tcp_rst_flags = list()
            biflow_any_eth_ipv4_tcp_psh_flags = list()
            biflow_any_eth_ipv4_tcp_ack_flags = list()
            biflow_any_eth_ipv4_tcp_urg_flags = list()
            biflow_any_eth_ipv4_tcp_ece_flags = list()
            biflow_any_eth_ipv4_tcp_cwr_flags = list()

            biflow_fwd_eth_ipv4_tcp_fin_flags = list()
            biflow_fwd_eth_ipv4_tcp_syn_flags = list()
            biflow_fwd_eth_ipv4_tcp_rst_flags = list()
            biflow_fwd_eth_ipv4_tcp_psh_flags = list()
            biflow_fwd_eth_ipv4_tcp_ack_flags = list()
            biflow_fwd_eth_ipv4_tcp_urg_flags = list()
            biflow_fwd_eth_ipv4_tcp_ece_flags = list()
            biflow_fwd_eth_ipv4_tcp_cwr_flags = list()

            biflow_bwd_eth_ipv4_tcp_fin_flags = list()
            biflow_bwd_eth_ipv4_tcp_syn_flags = list()
            biflow_bwd_eth_ipv4_tcp_rst_flags = list()
            biflow_bwd_eth_ipv4_tcp_psh_flags = list()
            biflow_bwd_eth_ipv4_tcp_ack_flags = list()
            biflow_bwd_eth_ipv4_tcp_urg_flags = list()
            biflow_bwd_eth_ipv4_tcp_ece_flags = list()
            biflow_bwd_eth_ipv4_tcp_cwr_flags = list()

            # ==========================
            # POPULATE DATA STRUCTURES |
            # ==========================
            curr_packet_index = 0
            while curr_packet_index < biflow_any_n_packets:
                # ===============
                # Packet Concepts
                # ===============
                if curr_packet_index >= 1:
                    previous_packet = curr_biflow[curr_packet_index-1]
                    previous_packet_biflow_id = tuple(previous_packet[0])
                    previous_packet_timestamp = previous_packet[1]

                curr_packet = curr_biflow[curr_packet_index]
                curr_packet_biflow_id = tuple(curr_packet[0])
                curr_packet_timestamp = curr_packet[1]
                curr_packet_eth_ipv4_header_len = curr_packet[2]
                curr_packet_eth_ipv4_data_len = curr_packet[3]
                curr_packet_eth_ip_df_flag = curr_packet[4]
                curr_packet_eth_ip_mf_flag = curr_packet[5]

                # Packet IAT requires that there's at least two packets
                if curr_packet_index >= 1:
                    previous_packet_time = datetime_to_unixtime(previous_packet_timestamp)
                    curr_packet_time = datetime_to_unixtime(curr_packet_timestamp)
                    curr_packet_iat = (curr_packet_time - previous_packet_time)/time_scale_factor
                    biflow_any_packet_iats.append(curr_packet_iat)
                    if previous_packet_biflow_id == biflow_id:
                        biflow_fwd_packet_iats.append(curr_packet_iat)
                    else:
                        biflow_bwd_packet_iats.append(curr_packet_iat)

                # =============
                # IPv4 Concepts
                # =============
                # STATISTICAL
                biflow_any_eth_ipv4_data_lens.append(curr_packet_eth_ipv4_data_len)
                biflow_any_eth_ipv4_header_lens.append(curr_packet_eth_ipv4_header_len)
                biflow_any_eth_ip_df_flags.append(curr_packet_eth_ip_df_flag)
                biflow_any_eth_ip_mf_flags.append(curr_packet_eth_ip_mf_flag)

                if curr_packet_biflow_id == biflow_id:
                    # CONCEPTUAL
                    biflow_fwd_n_packets += 1

                    # STATISTICAL
                    biflow_fwd_eth_ipv4_data_lens.append(curr_packet_eth_ipv4_data_len)
                    biflow_fwd_eth_ipv4_header_lens.append(curr_packet_eth_ipv4_header_len)
                    biflow_fwd_eth_ip_df_flags.append(curr_packet_eth_ip_df_flag)
                    biflow_fwd_eth_ip_mf_flags.append(curr_packet_eth_ip_mf_flag)
                else:
                    # CONCEPTUAL
                    biflow_bwd_n_packets += 1

                    # STATISTICAL
                    biflow_bwd_eth_ipv4_data_lens.append(curr_packet_eth_ipv4_data_len)
                    biflow_bwd_eth_ipv4_header_lens.append(curr_packet_eth_ipv4_header_len)
                    biflow_bwd_eth_ip_df_flags.append(curr_packet_eth_ip_df_flag)
                    biflow_bwd_eth_ip_mf_flags.append(curr_packet_eth_ip_mf_flag)

                # ===========
                # L4 Concepts
                # ===========
                if l4_protocol:
                    curr_packet_eth_ipv4_l4_header_len = curr_packet[6]
                    curr_packet_eth_ipv4_l4_data_len = curr_packet[7]

                    # any
                    biflow_any_eth_ipv4_l4_header_lens.append(curr_packet_eth_ipv4_l4_header_len)
                    biflow_any_eth_ipv4_l4_data_lens.append(curr_packet_eth_ipv4_l4_data_len)

                    #fwd
                    if curr_packet_biflow_id == biflow_id:
                        # CONCEPTUAL
                        if curr_packet_eth_ipv4_l4_data_len > 0:
                            biflow_any_eth_ipv4_l4_n_data_packets += 1
                            biflow_fwd_eth_ipv4_l4_n_data_packets += 1

                        # STATISTICAL
                        biflow_fwd_eth_ipv4_l4_header_lens.append(curr_packet_eth_ipv4_l4_header_len)
                        biflow_fwd_eth_ipv4_l4_data_lens.append(curr_packet_eth_ipv4_l4_data_len)
                    #bwd
                    else:
                        # CONCEPTUAL
                        if curr_packet_eth_ipv4_l4_data_len > 0:
                            biflow_any_eth_ipv4_l4_n_data_packets += 1
                            biflow_bwd_eth_ipv4_l4_n_data_packets += 1

                        # STATISTICAL
                        biflow_bwd_eth_ipv4_l4_header_lens.append(curr_packet_eth_ipv4_l4_header_len)
                        biflow_bwd_eth_ipv4_l4_data_lens.append(curr_packet_eth_ipv4_l4_data_len)

                    # ============
                    # TCP Concepts
                    # ============
                    if l4_protocol == "TCP":
                        curr_packet_eth_ipv4_tcp_fin_flag = curr_packet[-8]
                        curr_packet_eth_ipv4_tcp_syn_flag = curr_packet[-7]
                        curr_packet_eth_ipv4_tcp_rst_flag = curr_packet[-6]
                        curr_packet_eth_ipv4_tcp_psh_flag = curr_packet[-5]
                        curr_packet_eth_ipv4_tcp_ack_flag = curr_packet[-4]
                        curr_packet_eth_ipv4_tcp_urg_flag = curr_packet[-3]
                        curr_packet_eth_ipv4_tcp_ece_flag = curr_packet[-2]
                        curr_packet_eth_ipv4_tcp_cwr_flag = curr_packet[-1]

                        # any
                        biflow_any_eth_ipv4_tcp_fin_flags.append(curr_packet_eth_ipv4_tcp_fin_flag)
                        biflow_any_eth_ipv4_tcp_syn_flags.append(curr_packet_eth_ipv4_tcp_syn_flag)
                        biflow_any_eth_ipv4_tcp_rst_flags.append(curr_packet_eth_ipv4_tcp_rst_flag)
                        biflow_any_eth_ipv4_tcp_psh_flags.append(curr_packet_eth_ipv4_tcp_psh_flag)
                        biflow_any_eth_ipv4_tcp_ack_flags.append(curr_packet_eth_ipv4_tcp_ack_flag)
                        biflow_any_eth_ipv4_tcp_urg_flags.append(curr_packet_eth_ipv4_tcp_urg_flag)
                        biflow_any_eth_ipv4_tcp_ece_flags.append(curr_packet_eth_ipv4_tcp_ece_flag)
                        biflow_any_eth_ipv4_tcp_cwr_flags.append(curr_packet_eth_ipv4_tcp_cwr_flag)

                        #fwd
                        if curr_packet_biflow_id == biflow_id:
                            biflow_fwd_eth_ipv4_tcp_fin_flags.append(curr_packet_eth_ipv4_tcp_fin_flag)
                            biflow_fwd_eth_ipv4_tcp_syn_flags.append(curr_packet_eth_ipv4_tcp_syn_flag)
                            biflow_fwd_eth_ipv4_tcp_rst_flags.append(curr_packet_eth_ipv4_tcp_rst_flag)
                            biflow_fwd_eth_ipv4_tcp_psh_flags.append(curr_packet_eth_ipv4_tcp_psh_flag)
                            biflow_fwd_eth_ipv4_tcp_ack_flags.append(curr_packet_eth_ipv4_tcp_ack_flag)
                            biflow_fwd_eth_ipv4_tcp_urg_flags.append(curr_packet_eth_ipv4_tcp_urg_flag)
                            biflow_fwd_eth_ipv4_tcp_ece_flags.append(curr_packet_eth_ipv4_tcp_ece_flag)
                            biflow_fwd_eth_ipv4_tcp_cwr_flags.append(curr_packet_eth_ipv4_tcp_cwr_flag)
                        #bwd
                        else:
                            biflow_bwd_eth_ipv4_tcp_fin_flags.append(curr_packet_eth_ipv4_tcp_fin_flag)
                            biflow_bwd_eth_ipv4_tcp_syn_flags.append(curr_packet_eth_ipv4_tcp_syn_flag)
                            biflow_bwd_eth_ipv4_tcp_rst_flags.append(curr_packet_eth_ipv4_tcp_rst_flag)
                            biflow_bwd_eth_ipv4_tcp_psh_flags.append(curr_packet_eth_ipv4_tcp_psh_flag)
                            biflow_bwd_eth_ipv4_tcp_ack_flags.append(curr_packet_eth_ipv4_tcp_ack_flag)
                            biflow_bwd_eth_ipv4_tcp_urg_flags.append(curr_packet_eth_ipv4_tcp_urg_flag)
                            biflow_bwd_eth_ipv4_tcp_ece_flags.append(curr_packet_eth_ipv4_tcp_ece_flag)
                            biflow_bwd_eth_ipv4_tcp_cwr_flags.append(curr_packet_eth_ipv4_tcp_cwr_flag)
                # keep iterating through the packets
                curr_packet_index+=1

            # TCP BiFlow direction
            if biflow_fwd_n_packets == 0:
                # -------------------------------------------------------------------
                # Note 1: In case this is reached, TCP BiFlow direction got messed up
                # This sometimes happens for an unknown reason in datasets.
                # The researcher speculates it might have something to do with
                # the dataset creators having merged small pcap files from different
                # endpoints or the fact that the network interface itself registered
                # the two packets in a different order relatively to their respective
                # sending and receival times.
                # An example of this is the Thursday-WorkingHours file of the CICIDS-2017
                # dataset, in the afternoon, when a Windows Vista endpoint (192.168.10.8)
                # performs a portscan on all other network clients. The eBPF filter for the
                # bitalker is '((ip.addr==192.168.10.8)&&(ip.addr==192.168.10.9))', and
                # for the specific biflow where this happens is
                # '((ip.addr==192.168.10.8)&&(ip.addr==192.168.10.9))&&((tcp.srcport==45500&&tcp.dstport==407)||(tcp.srcport==407&&tcp.dstport==45500))'
                # --------------------------------------------------------------------------------------------------------------------------------------
                # Note 2: in case this happens, we will ignore this biflow by continuing to process other biflows.
                # SHOULD-TODO: Despite this, we are ignoring the 6-tuple biflow when we should be ignoring the whole
                # 5-tuple biflow instead. I don't currently know how to implement this effectively in the current code
                # and, thus, will ignore it for now because there aren't many biflows that encounter this "mistiming"
                # (only found it in the Thursday capture, for portscans)
                if verbose:
                    print(Colors.RED + "[!] " + iterator_to_str(biflow_id), "is an out-of-order BiFlow. Ignoring..." + Colors.ENDC)
                continue

            # ================================
            # ENRICH AND EXTRACT INFORMATION |
            # ================================

            # ======================
            # ADDITIONAL INFORMATION
            # ======================
            # Get bitalker_id and convert bitalker_id and biflow_id to strings
            bitalker_id = iterator_to_str(biflow_id_to_bitalker_id(biflow_id))
            bihost_fwd_id = iterator_to_str(bitalker_id_to_bihost_id(str_to_iterator(bitalker_id)))
            bihost_bwd_id = iterator_to_str(bitalker_id_to_bihost_id(str_to_iterator(bitalker_id), _fwd=False))
            biflow_src_port = biflow_id[1]
            biflow_dst_port = biflow_id[3]
            biflow_id = iterator_to_str(biflow_id)

            first_packet = curr_biflow[0]
            last_packet = curr_biflow[-1]
            first_packet_timestamp = first_packet[1]
            last_packet_timestamp = last_packet[1]
            biflow_any_first_packet_time = datetime_to_unixtime(first_packet_timestamp)
            biflow_any_last_packet_time = datetime_to_unixtime(last_packet_timestamp)

            # =================
            # IPv4 Data Lengths
            # =================
            biflow_any_eth_ipv4_data_len_total = round(sum(biflow_any_eth_ipv4_data_lens), 3)
            biflow_any_eth_ipv4_data_len_mean = round(np.mean(biflow_any_eth_ipv4_data_lens), 3)
            biflow_any_eth_ipv4_data_len_std = round(np.std(biflow_any_eth_ipv4_data_lens), 3)
            biflow_any_eth_ipv4_data_len_var = round(np.var(biflow_any_eth_ipv4_data_lens), 3)
            biflow_any_eth_ipv4_data_len_max = round(max(biflow_any_eth_ipv4_data_lens), 3)
            biflow_any_eth_ipv4_data_len_min = round(min(biflow_any_eth_ipv4_data_lens), 3)

            biflow_fwd_eth_ipv4_data_len_total = round(sum(biflow_fwd_eth_ipv4_data_lens), 3)
            biflow_fwd_eth_ipv4_data_len_mean = round(np.mean(biflow_fwd_eth_ipv4_data_lens), 3)
            biflow_fwd_eth_ipv4_data_len_std = round(np.std(biflow_fwd_eth_ipv4_data_lens), 3)
            biflow_fwd_eth_ipv4_data_len_var = round(np.var(biflow_fwd_eth_ipv4_data_lens), 3)
            biflow_fwd_eth_ipv4_data_len_max = round(max(biflow_fwd_eth_ipv4_data_lens), 3)
            biflow_fwd_eth_ipv4_data_len_min = round(min(biflow_fwd_eth_ipv4_data_lens), 3)

            if len(biflow_bwd_eth_ipv4_data_lens) == 0:
                biflow_bwd_eth_ipv4_data_len_total = biflow_bwd_eth_ipv4_data_len_max = biflow_bwd_eth_ipv4_data_len_min = 0
                biflow_bwd_eth_ipv4_data_len_mean = biflow_bwd_eth_ipv4_data_len_std = biflow_bwd_eth_ipv4_data_len_var = 0.0
            else:
                biflow_bwd_eth_ipv4_data_len_total = round(sum(biflow_bwd_eth_ipv4_data_lens), 3)
                biflow_bwd_eth_ipv4_data_len_mean = round(np.mean(biflow_bwd_eth_ipv4_data_lens), 3)
                biflow_bwd_eth_ipv4_data_len_std = round(np.std(biflow_bwd_eth_ipv4_data_lens), 3)
                biflow_bwd_eth_ipv4_data_len_var = round(np.var(biflow_bwd_eth_ipv4_data_lens), 3)
                biflow_bwd_eth_ipv4_data_len_max = round(max(biflow_bwd_eth_ipv4_data_lens), 3)
                biflow_bwd_eth_ipv4_data_len_min = round(min(biflow_bwd_eth_ipv4_data_lens), 3)

            # =============
            # Time Features
            # =============
            biflow_any_duration = round((biflow_any_last_packet_time - biflow_any_first_packet_time)/time_scale_factor, 3)

            # =================================
            # Additional Information - Reformat
            # =================================
            biflow_any_first_packet_time = unixtime_to_datetime(biflow_any_first_packet_time)
            biflow_any_last_packet_time = unixtime_to_datetime(biflow_any_last_packet_time)

            # ================================
            # Packet & Byte Frequency Features
            # ================================
            if biflow_any_duration == 0:
                biflow_any_packets_per_sec = biflow_fwd_packets_per_sec = biflow_bwd_packets_per_sec = 0.0
                biflow_any_bytes_per_sec = biflow_fwd_bytes_per_sec = biflow_bwd_bytes_per_sec = 0.0
            else:
                biflow_any_packets_per_sec = round(biflow_any_n_packets/biflow_any_duration, 3)
                biflow_fwd_packets_per_sec = round(biflow_fwd_n_packets/biflow_any_duration, 3)
                biflow_bwd_packets_per_sec = round(biflow_bwd_n_packets/biflow_any_duration, 3)
                biflow_any_bytes_per_sec = round(biflow_any_eth_ipv4_data_len_total/biflow_any_duration, 3)
                biflow_fwd_bytes_per_sec = round(biflow_fwd_eth_ipv4_data_len_total/biflow_any_duration, 3)
                biflow_bwd_bytes_per_sec = round(biflow_bwd_eth_ipv4_data_len_total/biflow_any_duration, 3)

            # ===================
            # IPv4 Header Lengths
            # ===================
            biflow_any_eth_ipv4_header_len_total = round(sum(biflow_any_eth_ipv4_header_lens), 3)
            biflow_any_eth_ipv4_header_len_mean = round(np.mean(biflow_any_eth_ipv4_header_lens), 3)
            biflow_any_eth_ipv4_header_len_std = round(np.std(biflow_any_eth_ipv4_header_lens), 3)
            biflow_any_eth_ipv4_header_len_var = round(np.var(biflow_any_eth_ipv4_header_lens), 3)
            biflow_any_eth_ipv4_header_len_max = round(max(biflow_any_eth_ipv4_header_lens), 3)
            biflow_any_eth_ipv4_header_len_min = round(min(biflow_any_eth_ipv4_header_lens), 3)

            biflow_fwd_eth_ipv4_header_len_total = round(sum(biflow_fwd_eth_ipv4_header_lens), 3)
            biflow_fwd_eth_ipv4_header_len_mean = round(np.mean(biflow_fwd_eth_ipv4_header_lens), 3)
            biflow_fwd_eth_ipv4_header_len_std = round(np.std(biflow_fwd_eth_ipv4_header_lens), 3)
            biflow_fwd_eth_ipv4_header_len_var = round(np.var(biflow_fwd_eth_ipv4_header_lens), 3)
            biflow_fwd_eth_ipv4_header_len_max = round(max(biflow_fwd_eth_ipv4_header_lens), 3)
            biflow_fwd_eth_ipv4_header_len_min = round(min(biflow_fwd_eth_ipv4_header_lens), 3)

            if len(biflow_bwd_eth_ipv4_header_lens) == 0:
                biflow_bwd_eth_ipv4_header_len_total = biflow_bwd_eth_ipv4_header_len_max = biflow_bwd_eth_ipv4_header_len_min = 0
                biflow_bwd_eth_ipv4_header_len_mean = biflow_bwd_eth_ipv4_header_len_std = biflow_bwd_eth_ipv4_header_len_var = 0.0
            else:
                biflow_bwd_eth_ipv4_header_len_total = round(sum(biflow_bwd_eth_ipv4_header_lens), 3)
                biflow_bwd_eth_ipv4_header_len_mean = round(np.mean(biflow_bwd_eth_ipv4_header_lens), 3)
                biflow_bwd_eth_ipv4_header_len_std = round(np.std(biflow_bwd_eth_ipv4_header_lens), 3)
                biflow_bwd_eth_ipv4_header_len_var = round(np.var(biflow_bwd_eth_ipv4_header_lens), 3)
                biflow_bwd_eth_ipv4_header_len_max = round(max(biflow_bwd_eth_ipv4_header_lens), 3)
                biflow_bwd_eth_ipv4_header_len_min = round(min(biflow_bwd_eth_ipv4_header_lens), 3)
                

            # ==========================
            # Packet Inter-arrival Times
            # ==========================
            # Packet IATs need at least 2 packets to be properly populated
            if len(biflow_any_packet_iats) == 0:
                biflow_any_packet_iat_total = biflow_any_packet_iat_max = biflow_any_packet_iat_min = 0.0
                biflow_any_packet_iat_mean = biflow_any_packet_iat_std = biflow_any_packet_iat_var = 0.0
            else:
                biflow_any_packet_iat_total = round(sum(biflow_any_packet_iats), 3)
                biflow_any_packet_iat_mean = round(np.mean(biflow_any_packet_iats), 3)
                biflow_any_packet_iat_std = round(np.std(biflow_any_packet_iats), 3)
                biflow_any_packet_iat_var = round(np.var(biflow_any_packet_iats), 3)
                biflow_any_packet_iat_max = round(max(biflow_any_packet_iats), 3)
                biflow_any_packet_iat_min = round(min(biflow_any_packet_iats), 3)

            # Packet IATs need at least 2 packets to be properly populated
            if len(biflow_fwd_packet_iats) == 0:
                biflow_fwd_packet_iat_total = biflow_fwd_packet_iat_max = biflow_fwd_packet_iat_min = 0.0
                biflow_fwd_packet_iat_mean = biflow_fwd_packet_iat_std = biflow_fwd_packet_iat_var = 0.0
            else:
                biflow_fwd_packet_iat_total = round(sum(biflow_fwd_packet_iats), 3)
                biflow_fwd_packet_iat_mean = round(np.mean(biflow_fwd_packet_iats), 3)
                biflow_fwd_packet_iat_std = round(np.std(biflow_fwd_packet_iats), 3)
                biflow_fwd_packet_iat_var = round(np.var(biflow_fwd_packet_iats), 3)
                biflow_fwd_packet_iat_max = round(max(biflow_fwd_packet_iats), 3)
                biflow_fwd_packet_iat_min = round(min(biflow_fwd_packet_iats), 3)

            # Packet IATs need at least 2 packets to be properly populated
            if len(biflow_bwd_packet_iats) == 0:
                biflow_bwd_packet_iat_total = biflow_bwd_packet_iat_max = biflow_bwd_packet_iat_min = 0.0
                biflow_bwd_packet_iat_mean = biflow_bwd_packet_iat_std = biflow_bwd_packet_iat_var = 0.0
            else:
                biflow_bwd_packet_iat_total = round(sum(biflow_bwd_packet_iats), 3)
                biflow_bwd_packet_iat_mean = round(np.mean(biflow_bwd_packet_iats), 3)
                biflow_bwd_packet_iat_std = round(np.std(biflow_bwd_packet_iats), 3)
                biflow_bwd_packet_iat_var = round(np.var(biflow_bwd_packet_iats), 3)
                biflow_bwd_packet_iat_max = round(max(biflow_bwd_packet_iats), 3)
                biflow_bwd_packet_iat_min = round(min(biflow_bwd_packet_iats), 3)

            # ======================
            # IP Fragmentation Flags
            # ======================
            biflow_any_eth_ip_n_active_df_flags = round(sum(biflow_any_eth_ip_df_flags), 3)
            biflow_any_eth_ip_active_df_flags_rate = round(np.mean(biflow_any_eth_ip_df_flags), 3)

            biflow_fwd_eth_ip_n_active_df_flags = round(sum(biflow_fwd_eth_ip_df_flags), 3)
            biflow_fwd_eth_ip_active_df_flags_rate = round(np.mean(biflow_fwd_eth_ip_df_flags), 3)

            if len(biflow_bwd_eth_ip_df_flags) == 0:
                biflow_bwd_eth_ip_n_active_df_flags = 0
                biflow_bwd_eth_ip_active_df_flags_rate = 0.0
            else:
                biflow_bwd_eth_ip_n_active_df_flags = round(sum(biflow_bwd_eth_ip_df_flags), 3)
                biflow_bwd_eth_ip_active_df_flags_rate = round(np.mean(biflow_bwd_eth_ip_df_flags), 3)


            biflow_any_eth_ip_n_active_mf_flags = round(sum(biflow_any_eth_ip_mf_flags), 3)
            biflow_any_eth_ip_active_mf_flags_rate = round(np.mean(biflow_any_eth_ip_mf_flags), 3)

            biflow_fwd_eth_ip_n_active_mf_flags = round(sum(biflow_fwd_eth_ip_mf_flags), 3)
            biflow_fwd_eth_ip_active_mf_flags_rate = round(np.mean(biflow_fwd_eth_ip_mf_flags), 3)

            if len(biflow_bwd_eth_ip_mf_flags) == 0:
                biflow_bwd_eth_ip_n_active_mf_flags = 0
                biflow_bwd_eth_ip_active_mf_flags_rate = 0.0
            else:
                biflow_bwd_eth_ip_n_active_mf_flags = round(sum(biflow_bwd_eth_ip_mf_flags), 3)
                biflow_bwd_eth_ip_active_mf_flags_rate = round(np.mean(biflow_bwd_eth_ip_mf_flags), 3)

            # ==========================
            # L4 Protocol Specific Genes
            # ==========================
            if l4_protocol:
                # ========================
                # L4 Data Packet Frequency
                # ========================
                if biflow_any_duration == 0:
                    biflow_any_eth_ipv4_l4_data_packets_per_sec = biflow_fwd_eth_ipv4_l4_data_packets_per_sec = \
                        biflow_bwd_eth_ipv4_l4_data_packets_per_sec = 0.0
                else:
                    biflow_any_eth_ipv4_l4_data_packets_per_sec = round(biflow_any_eth_ipv4_l4_n_data_packets/biflow_any_duration, 3)
                    biflow_fwd_eth_ipv4_l4_data_packets_per_sec = round(biflow_fwd_eth_ipv4_l4_n_data_packets/biflow_any_duration, 3)
                    biflow_bwd_eth_ipv4_l4_data_packets_per_sec = round(biflow_bwd_eth_ipv4_l4_n_data_packets/biflow_any_duration, 3)
                
                # =================
                # L4 HEADER LENGTHS
                # =================
                biflow_any_eth_ipv4_l4_header_len_total = round(sum(biflow_any_eth_ipv4_l4_header_lens), 3)
                biflow_any_eth_ipv4_l4_header_len_mean = round(np.mean(biflow_any_eth_ipv4_l4_header_lens), 3)
                biflow_any_eth_ipv4_l4_header_len_std = round(np.std(biflow_any_eth_ipv4_l4_header_lens), 3)
                biflow_any_eth_ipv4_l4_header_len_var = round(np.var(biflow_any_eth_ipv4_l4_header_lens), 3)
                biflow_any_eth_ipv4_l4_header_len_max = round(max(biflow_any_eth_ipv4_l4_header_lens), 3)
                biflow_any_eth_ipv4_l4_header_len_min = round(min(biflow_any_eth_ipv4_l4_header_lens), 3)

                biflow_fwd_eth_ipv4_l4_header_len_total = round(sum(biflow_fwd_eth_ipv4_l4_header_lens), 3)
                biflow_fwd_eth_ipv4_l4_header_len_mean = round(np.mean(biflow_fwd_eth_ipv4_l4_header_lens), 3)
                biflow_fwd_eth_ipv4_l4_header_len_std = round(np.std(biflow_fwd_eth_ipv4_l4_header_lens), 3)
                biflow_fwd_eth_ipv4_l4_header_len_var = round(np.var(biflow_fwd_eth_ipv4_l4_header_lens), 3)
                biflow_fwd_eth_ipv4_l4_header_len_max = round(max(biflow_fwd_eth_ipv4_l4_header_lens), 3)
                biflow_fwd_eth_ipv4_l4_header_len_min = round(min(biflow_fwd_eth_ipv4_l4_header_lens), 3)

                if len(biflow_bwd_eth_ipv4_l4_header_lens) == 0:
                    biflow_bwd_eth_ipv4_l4_header_len_total = biflow_bwd_eth_ipv4_l4_header_len_max = biflow_bwd_eth_ipv4_l4_header_len_min = 0
                    biflow_bwd_eth_ipv4_l4_header_len_mean = biflow_bwd_eth_ipv4_l4_header_len_std = biflow_bwd_eth_ipv4_l4_header_len_var = 0.0
                else:
                    biflow_bwd_eth_ipv4_l4_header_len_total = round(sum(biflow_bwd_eth_ipv4_l4_header_lens), 3)
                    biflow_bwd_eth_ipv4_l4_header_len_mean = round(np.mean(biflow_bwd_eth_ipv4_l4_header_lens), 3)
                    biflow_bwd_eth_ipv4_l4_header_len_std = round(np.std(biflow_bwd_eth_ipv4_l4_header_lens), 3)
                    biflow_bwd_eth_ipv4_l4_header_len_var = round(np.var(biflow_bwd_eth_ipv4_l4_header_lens), 3)
                    biflow_bwd_eth_ipv4_l4_header_len_max = round(max(biflow_bwd_eth_ipv4_l4_header_lens), 3)
                    biflow_bwd_eth_ipv4_l4_header_len_min = round(min(biflow_bwd_eth_ipv4_l4_header_lens), 3)

                # ===============
                # L4 DATA LENGTHS
                # ===============
                biflow_any_eth_ipv4_l4_data_len_total = round(sum(biflow_any_eth_ipv4_l4_data_lens), 3)
                biflow_any_eth_ipv4_l4_data_len_mean = round(np.mean(biflow_any_eth_ipv4_l4_data_lens), 3)
                biflow_any_eth_ipv4_l4_data_len_std = round(np.std(biflow_any_eth_ipv4_l4_data_lens), 3)
                biflow_any_eth_ipv4_l4_data_len_var = round(np.var(biflow_any_eth_ipv4_l4_data_lens), 3)
                biflow_any_eth_ipv4_l4_data_len_max = round(max(biflow_any_eth_ipv4_l4_data_lens), 3)
                biflow_any_eth_ipv4_l4_data_len_min = round(min(biflow_any_eth_ipv4_l4_data_lens), 3)

                biflow_fwd_eth_ipv4_l4_data_len_total = round(sum(biflow_fwd_eth_ipv4_l4_data_lens), 3)
                biflow_fwd_eth_ipv4_l4_data_len_mean = round(np.mean(biflow_fwd_eth_ipv4_l4_data_lens), 3)
                biflow_fwd_eth_ipv4_l4_data_len_std = round(np.std(biflow_fwd_eth_ipv4_l4_data_lens), 3)
                biflow_fwd_eth_ipv4_l4_data_len_var = round(np.var(biflow_fwd_eth_ipv4_l4_data_lens), 3)
                biflow_fwd_eth_ipv4_l4_data_len_max = round(max(biflow_fwd_eth_ipv4_l4_data_lens), 3)
                biflow_fwd_eth_ipv4_l4_data_len_min = round(min(biflow_fwd_eth_ipv4_l4_data_lens), 3)

                if len(biflow_bwd_eth_ipv4_l4_data_lens) == 0:
                    biflow_bwd_eth_ipv4_l4_data_len_total = biflow_bwd_eth_ipv4_l4_data_len_max = biflow_bwd_eth_ipv4_l4_data_len_min = 0
                    biflow_bwd_eth_ipv4_l4_data_len_mean = biflow_bwd_eth_ipv4_l4_data_len_std = biflow_bwd_eth_ipv4_l4_data_len_var = 0.0
                else:
                    biflow_bwd_eth_ipv4_l4_data_len_total = round(sum(biflow_bwd_eth_ipv4_l4_data_lens), 3)
                    biflow_bwd_eth_ipv4_l4_data_len_mean = round(np.mean(biflow_bwd_eth_ipv4_l4_data_lens), 3)
                    biflow_bwd_eth_ipv4_l4_data_len_std = round(np.std(biflow_bwd_eth_ipv4_l4_data_lens), 3)
                    biflow_bwd_eth_ipv4_l4_data_len_var = round(np.var(biflow_bwd_eth_ipv4_l4_data_lens), 3)
                    biflow_bwd_eth_ipv4_l4_data_len_max = round(max(biflow_bwd_eth_ipv4_l4_data_lens), 3)
                    biflow_bwd_eth_ipv4_l4_data_len_min = round(min(biflow_bwd_eth_ipv4_l4_data_lens), 3)

                # =======================================
                # UDP Protocol Specific Genes: COULD-TODO
                # =======================================
                if l4_protocol=="UDP":
                    pass
                # ===========================
                # TCP Protocol Specific Genes
                # ===========================
                elif l4_protocol == "TCP":
                    # =========
                    # FIN FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_n_active_fin_flags = round(sum(biflow_any_eth_ipv4_tcp_fin_flags), 3)
                    biflow_any_eth_ipv4_tcp_active_fin_flags_rate = round(np.mean(biflow_any_eth_ipv4_tcp_fin_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_n_active_fin_flags = round(sum(biflow_fwd_eth_ipv4_tcp_fin_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_active_fin_flags_rate = round(np.mean(biflow_fwd_eth_ipv4_tcp_fin_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_fin_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_n_active_fin_flags = 0
                        biflow_bwd_eth_ipv4_tcp_active_fin_flags_rate = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_n_active_fin_flags = round(sum(biflow_bwd_eth_ipv4_tcp_fin_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_active_fin_flags_rate = round(np.mean(biflow_bwd_eth_ipv4_tcp_fin_flags), 3)

                    # =========
                    # SYN FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_n_active_syn_flags = round(sum(biflow_any_eth_ipv4_tcp_syn_flags), 3)
                    biflow_any_eth_ipv4_tcp_active_syn_flags_rate = round(np.mean(biflow_any_eth_ipv4_tcp_syn_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_n_active_syn_flags = round(sum(biflow_fwd_eth_ipv4_tcp_syn_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_active_syn_flags_rate = round(np.mean(biflow_fwd_eth_ipv4_tcp_syn_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_syn_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_n_active_syn_flags = 0
                        biflow_bwd_eth_ipv4_tcp_active_syn_flags_rate = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_n_active_syn_flags = round(sum(biflow_bwd_eth_ipv4_tcp_syn_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_active_syn_flags_rate = round(np.mean(biflow_bwd_eth_ipv4_tcp_syn_flags), 3)

                    # =========
                    # RST FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_n_active_rst_flags = round(sum(biflow_any_eth_ipv4_tcp_rst_flags), 3)
                    biflow_any_eth_ipv4_tcp_active_rst_flags_rate = round(np.mean(biflow_any_eth_ipv4_tcp_rst_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_n_active_rst_flags = round(sum(biflow_fwd_eth_ipv4_tcp_rst_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_active_rst_flags_rate = round(np.mean(biflow_fwd_eth_ipv4_tcp_rst_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_rst_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_n_active_rst_flags = 0
                        biflow_bwd_eth_ipv4_tcp_active_rst_flags_rate = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_n_active_rst_flags = round(sum(biflow_bwd_eth_ipv4_tcp_rst_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_active_rst_flags_rate = round(np.mean(biflow_bwd_eth_ipv4_tcp_rst_flags), 3)

                    # =========
                    # PSH FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_n_active_psh_flags = round(sum(biflow_any_eth_ipv4_tcp_psh_flags), 3)
                    biflow_any_eth_ipv4_tcp_active_psh_flags_rate = round(np.mean(biflow_any_eth_ipv4_tcp_psh_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_n_active_psh_flags = round(sum(biflow_fwd_eth_ipv4_tcp_psh_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_active_psh_flags_rate = round(np.mean(biflow_fwd_eth_ipv4_tcp_psh_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_psh_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_n_active_psh_flags = 0
                        biflow_bwd_eth_ipv4_tcp_active_psh_flags_rate = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_n_active_psh_flags = round(sum(biflow_bwd_eth_ipv4_tcp_psh_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_active_psh_flags_rate = round(np.mean(biflow_bwd_eth_ipv4_tcp_psh_flags), 3)

                    # =========
                    # ACK FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_n_active_ack_flags = round(sum(biflow_any_eth_ipv4_tcp_ack_flags), 3)
                    biflow_any_eth_ipv4_tcp_active_ack_flags_rate = round(np.mean(biflow_any_eth_ipv4_tcp_ack_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_n_active_ack_flags = round(sum(biflow_fwd_eth_ipv4_tcp_ack_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_active_ack_flags_rate = round(np.mean(biflow_fwd_eth_ipv4_tcp_ack_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_ack_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_n_active_ack_flags = 0
                        biflow_bwd_eth_ipv4_tcp_active_ack_flags_rate = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_n_active_ack_flags = round(sum(biflow_bwd_eth_ipv4_tcp_ack_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_active_ack_flags_rate = round(np.mean(biflow_bwd_eth_ipv4_tcp_ack_flags), 3)

                    # =========
                    # URG FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_n_active_urg_flags = round(sum(biflow_any_eth_ipv4_tcp_urg_flags), 3)
                    biflow_any_eth_ipv4_tcp_active_urg_flags_rate = round(np.mean(biflow_any_eth_ipv4_tcp_urg_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_n_active_urg_flags = round(sum(biflow_fwd_eth_ipv4_tcp_urg_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_active_urg_flags_rate = round(np.mean(biflow_fwd_eth_ipv4_tcp_urg_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_urg_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_n_active_urg_flags = 0
                        biflow_bwd_eth_ipv4_tcp_active_urg_flags_rate = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_n_active_urg_flags = round(sum(biflow_bwd_eth_ipv4_tcp_urg_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_active_urg_flags_rate = round(np.mean(biflow_bwd_eth_ipv4_tcp_urg_flags), 3)

                    # =========
                    # ECE FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_n_active_ece_flags = round(sum(biflow_any_eth_ipv4_tcp_ece_flags), 3)
                    biflow_any_eth_ipv4_tcp_active_ece_flags_rate = round(np.mean(biflow_any_eth_ipv4_tcp_ece_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_n_active_ece_flags = round(sum(biflow_fwd_eth_ipv4_tcp_ece_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_active_ece_flags_rate = round(np.mean(biflow_fwd_eth_ipv4_tcp_ece_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_ece_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_n_active_ece_flags = 0
                        biflow_bwd_eth_ipv4_tcp_active_ece_flags_rate = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_n_active_ece_flags = round(sum(biflow_bwd_eth_ipv4_tcp_ece_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_active_ece_flags_rate = round(np.mean(biflow_bwd_eth_ipv4_tcp_ece_flags), 3)

                    # =========
                    # CWR FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_n_active_cwr_flags = round(sum(biflow_any_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_any_eth_ipv4_tcp_active_cwr_flags_rate = round(np.mean(biflow_any_eth_ipv4_tcp_cwr_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_n_active_cwr_flags = round(sum(biflow_fwd_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_active_cwr_flags_rate = round(np.mean(biflow_fwd_eth_ipv4_tcp_cwr_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_cwr_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_n_active_cwr_flags = 0
                        biflow_bwd_eth_ipv4_tcp_active_cwr_flags_rate = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_n_active_cwr_flags = round(sum(biflow_bwd_eth_ipv4_tcp_cwr_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_active_cwr_flags_rate = round(np.mean(biflow_bwd_eth_ipv4_tcp_cwr_flags), 3)
                else:
                    print("No L4 protocol specified.", flush=True)
                    exit()
            # ===============
            # WRAP-UP RESULTS
            # ===============
            biflow_local_vars = locals()
            biflow_genes = [str(biflow_local_vars[var_name]) for var_name in ipv4_all_biflow_genes_header_list]

            yield biflow_genes

    # IPv4-[UDP|TCP] Genes Generator
    biflow_genes_generator = calculate_l3_l4_biflow_genes(genes_dir, biflows, biflow_ids,\
        l4_protocol=l4_protocol, l4_conceptual_features=l4_conceptual_features, verbose=verbose)

    # can return a listed yelder since passive analysis (threat hunting) is the objective
    # https://stackoverflow.com/questions/3487802/which-is-generally-faster-a-yield-or-an-append
    return list(biflow_genes_generator)