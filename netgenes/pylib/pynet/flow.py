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
        # Aux class
        class RFC793:
            def __init__(self):
                # INITIATION STATES
                self.flow_initiated = False
                self.flow_initiation_r1 = False
                self.flow_initiation_r2 = False
                self.flow_initiation_r3 = False

                # TERMINATION STATES
                self.flow_terminated = False
                self.flow_termination_r1 = False
                self.flow_termination_r2 = False
                self.flow_termination_r3 = False

                # CONCEPTUAL FEATURES
                self.biflow_eth_ipv4_tcp_initiation_two_way_handshake = False
                self.biflow_eth_ipv4_tcp_full_duplex_connection_established = False
                self.biflow_eth_ipv4_tcp_half_duplex_connection_established = False
                self.biflow_eth_ipv4_tcp_connection_rejected = False
                self.biflow_eth_ipv4_tcp_connection_dropped = False
                self.biflow_eth_ipv4_tcp_termination_graceful = False
                self.biflow_eth_ipv4_tcp_termination_abort = False
                self.biflow_eth_ipv4_tcp_termination_null = False

            def reset_states_and_genes(self):
                # if the flow hasn't terminated, won't reset states and genes
                if not self.flow_terminated:
                    return

                # INITIATION STATES
                self.flow_initiated = False
                self.flow_initiation_r1 = False
                self.flow_initiation_r2 = False
                self.flow_initiation_r3 = False

                # TERMINATION STATES
                self.flow_terminated = False
                self.flow_termination_r1 = False
                self.flow_termination_r2 = False
                self.flow_termination_r3 = False

                # CONCEPTUAL FEATURES
                self.biflow_eth_ipv4_tcp_initiation_two_way_handshake = False
                self.biflow_eth_ipv4_tcp_full_duplex_connection_established = False
                self.biflow_eth_ipv4_tcp_half_duplex_connection_established = False
                self.biflow_eth_ipv4_tcp_connection_rejected = False
                self.biflow_eth_ipv4_tcp_connection_dropped = False
                self.biflow_eth_ipv4_tcp_termination_graceful = False
                self.biflow_eth_ipv4_tcp_termination_abort = False
                self.biflow_eth_ipv4_tcp_termination_null = False

            def get_rfc793_tcp_biflow_conceptual_features(self):
                rfc793_tcp_biflow_conceptual_features = [
                    self.biflow_eth_ipv4_tcp_initiation_two_way_handshake,
                    self.biflow_eth_ipv4_tcp_full_duplex_connection_established,
                    self.biflow_eth_ipv4_tcp_half_duplex_connection_established,
                    self.biflow_eth_ipv4_tcp_connection_rejected,
                    self.biflow_eth_ipv4_tcp_connection_dropped,
                    self.biflow_eth_ipv4_tcp_termination_graceful,
                    self.biflow_eth_ipv4_tcp_termination_abort,
                    self.biflow_eth_ipv4_tcp_termination_null
                ]

                return rfc793_tcp_biflow_conceptual_features
        # Aux function
        def set_inner_sep_counter(packet_list, inner_sep_counter):
            """Local helper function to update flows' packets to the right inner_sep_counter,
            thus correcting its flow_id"""
            for i, packet in enumerate(packet_list):
                # set each packet's inner_sep_counter
                packet_list[i][0][5] = inner_sep_counter
            return packet_list

        # COULD-TODO: validate using tcp_seq
        rfc793_tcp_biflow_conceptual_features = dict()
        rfc793_tcp_biflows = dict()
        rfc793_tcp_biflow_ids = []
        n_disconected_rfc793_packets = 0

        # create RFC793-compliant TCP flows
        for tmp_tcp_biflow_id in tmp_tcp_biflow_ids:
            curr_flow = tmp_tcp_biflows[tmp_tcp_biflow_id]
            # sorting the packets in each flow by timestamp
            curr_flow.sort(key=lambda x: x[1])
            flow_any_n_packets = len(curr_flow)

            if flow_any_n_packets == 0:
                print("[!] A flow can't have 0 packets.", flush=True)
                exit()
            else:
                # =================================
                # RFC793-compliant TCP BiFlow Genes
                # =================================
                rfc793 = RFC793()
                rfc793_tcp_biflow_id = None

                # ==============
                # RFC793 parsing
                # ==============
                curr_packet_index = 0
                previous_packet_index = 0
                inner_sep_counter = 0

                while curr_packet_index < flow_any_n_packets:
                    # ===================
                    # Gathering TCP flags
                    # ===================
                    fin1,syn1,rst1,psh1,ack1,urg1,ece1,cwr1 = curr_flow[curr_packet_index][-8:]
                    try:
                        fin2,syn2,rst2,psh2,ack2,urg2,ece2,cwr2 = curr_flow[curr_packet_index+1][-8:]
                    except IndexError:
                        fin2,syn2,rst2,psh2,ack2,urg2,ece2,cwr2 = [False]*8
                    try:
                        fin3,syn3,rst3,psh3,ack3,urg3,ece3,cwr3 = curr_flow[curr_packet_index+2][-8:]
                    except IndexError:
                        fin3,syn3,rst3,psh3,ack3,urg2,ece3,cwr3 = [False]*8
                    
                    # =========================
                    # TCP FLOW INITIATION RULES
                    # =========================
                    # Begin Flow: tcp_three_way_handshake (r1), tcp_two_way_handshake (r2) and connection request (r3)
                    # 3-way handshake (full-duplex): (syn,syn-ack,ack) or (syn,syn-ack,syn-ack)
                    rfc793.flow_initiation_r1 = (syn1 and not ack1) and (syn2 and ack2) and ack3
                    # 2-way handshake (half-duplex): (syn,ack) or (syn,syn-ack)
                    rfc793.flow_initiation_r2 = (syn1 and not ack1) and ack2
                    # Connection request: (syn)
                    rfc793.flow_initiation_r3 = (syn1 and not ack1)

                    # ==========================
                    # TCP FLOW TERMINATION RULES
                    # ==========================
                    # End Flow: tcp_graceful_termination (r1), tcp_abort_termination (r2) and last packet (r3)
                    # graceful termination
                    rfc793.flow_termination_r1 = fin1 and (fin2 and ack2) and ack3
                    # abort termination
                    rfc793.flow_termination_r2 = rst1 and not rst2
                    # null termination
                    rfc793.flow_termination_r3 = (curr_packet_index == flow_any_n_packets-1)

                    if not rfc793.flow_initiated:
                        # ===================
                        # TCP FLOW INITIATION
                        # ===================
                        # Note 1: Consider flow begin or ignore it (considering it is safer, but not considering it will
                        # leave out flows that have started before the capture)
                        # Note 2: We consider flows only the ones that start with a 2 or 3-way handshake (r1,r2). In case
                        # there's no second acknowledgement, the connection was dropped and, nonetheless, the researcher
                        # considers it a flow
                        # -------------------
                        # Three-way Handshake
                        # -------------------
                        if rfc793.flow_initiation_r1:
                            # Note: Any three-way handshake initiates a full-duplex connection, no need to duplicate variables
                            rfc793.flow_initiated = True
                            # ----------------------------------
                            # Established Full-Duplex Connection
                            # ----------------------------------
                            rfc793.biflow_eth_ipv4_tcp_full_duplex_connection_established = True
                        # -----------------
                        # Two-way Handshake
                        # -----------------
                        elif rfc793.flow_initiation_r2:
                            # Note: Rare occurrence, except in the case of rejected and dropped connections:
                            # 1. After receiving syn, the receiving endpoint acknowledges the connection request and aborts it.
                            # The connection is acknowledged (ack) and immediately terminated (rst) in the same packet: REJECT.
                            # The most common 2nd packet flags are (rst-ack), ack used for the connection acknowledgement (two-way handshake)
                            # and reset used for immediately rejecting the connection
                            # 2. After receiving syn, the receiving endpoint acknowledges the connection request and accepts it.
                            # The connection is acknowledged (syn-ack) but never initiated: (syn, syn-ack). It might or not be
                            # terminated afterwards, since it is very common that it's a portscan and a reset is received right
                            # afterwards or, in more uncommon cases where an attacker can close a TCP connection and not send a
                            # RST packet, no message is received at all by the endpoint, but these termination cases are handled
                            # by our flow termination rules later.
                            rfc793.flow_initiated = True
                            rfc793.biflow_eth_ipv4_tcp_initiation_two_way_handshake = True

                            # -------------------
                            # Rejected Connection
                            # -------------------
                            if rst2:
                                rfc793.biflow_eth_ipv4_tcp_connection_rejected = True
                            # ----------------------------------
                            # Established Half-Duplex Connection
                            # ----------------------------------
                            else:
                                rfc793.biflow_eth_ipv4_tcp_half_duplex_connection_established = True
                        # ---------------------------------
                        # Unacknowledged Connection Request
                        # ---------------------------------
                        elif rfc793.flow_initiation_r3:
                            # 1. After receiving syn, the receiving endpoint ignores the connection request and drops it: DROP.
                            rfc793.flow_initiated = True
                            # ------------------
                            # Dropped connection
                            # ------------------
                            rfc793.biflow_eth_ipv4_tcp_connection_dropped = True

                    # the flow end conditions are r1 and r2, (fin,fin-ack,ack)/(rst,!rst,---),
                    # or if the packet is the last one of the existing communication
                    # SHOULD-TODO: Improve this spaghetti hardcoded code
                    if rfc793.flow_initiated:
                        rfc793_tcp_biflow_id = (tmp_tcp_biflow_id[0], tmp_tcp_biflow_id[1], tmp_tcp_biflow_id[2],\
                            tmp_tcp_biflow_id[3], tmp_tcp_biflow_id[4], tmp_tcp_biflow_id[5] + inner_sep_counter)
                        next_packet_index = 0
                        # ====================
                        # TCP FLOW TERMINATION
                        # ====================
                        # graceful termination
                        if rfc793.flow_termination_r1:
                            rfc793.flow_initiated = False
                            rfc793.flow_terminated = True
                            rfc793.biflow_eth_ipv4_tcp_termination_graceful = True
                            # keep tcp biflow and packets
                            rfc793_tcp_biflow_conceptual_features[rfc793_tcp_biflow_id] = rfc793.get_rfc793_tcp_biflow_conceptual_features()
                            packet_list = curr_flow[previous_packet_index:curr_packet_index+3]
                            packet_list = set_inner_sep_counter(packet_list, inner_sep_counter)
                            rfc793_tcp_biflows[rfc793_tcp_biflow_id] = packet_list
                            rfc793_tcp_biflow_ids.append(rfc793_tcp_biflow_id)
                            previous_packet_index = curr_packet_index + 3
                            inner_sep_counter += 1
                        # abort termination
                        elif rfc793.flow_termination_r2:
                            rfc793.flow_initiated = False
                            rfc793.flow_terminated = True
                            rfc793.biflow_eth_ipv4_tcp_termination_abort = True
                            # keep tcp biflow and packets
                            rfc793_tcp_biflow_conceptual_features[rfc793_tcp_biflow_id] = rfc793.get_rfc793_tcp_biflow_conceptual_features()
                            packet_list = curr_flow[previous_packet_index:curr_packet_index+1]
                            packet_list = set_inner_sep_counter(packet_list, inner_sep_counter)
                            rfc793_tcp_biflows[rfc793_tcp_biflow_id] = packet_list
                            rfc793_tcp_biflow_ids.append(rfc793_tcp_biflow_id)
                            previous_packet_index = curr_packet_index + 1
                            inner_sep_counter += 1
                        # null termination
                        elif rfc793.flow_termination_r3:
                            rfc793.flow_initiated = False
                            rfc793.flow_terminated = True
                            rfc793.biflow_eth_ipv4_tcp_termination_null = True
                            # keep tcp biflow and packets
                            rfc793_tcp_biflow_conceptual_features[rfc793_tcp_biflow_id] = rfc793.get_rfc793_tcp_biflow_conceptual_features()
                            packet_list = curr_flow[previous_packet_index:curr_packet_index+1]
                            packet_list = set_inner_sep_counter(packet_list, inner_sep_counter)
                            rfc793_tcp_biflows[rfc793_tcp_biflow_id] = packet_list
                            rfc793_tcp_biflow_ids.append(rfc793_tcp_biflow_id)
                            previous_packet_index = curr_packet_index + 1
                            inner_sep_counter += 1
                    elif not rfc793_tcp_biflow_id:
                        # disconected packet
                        n_disconected_rfc793_packets += 1
                    else:
                        # just packets
                        pass

                    # =====================
                    # TCP BiFlow Debug Info
                    # =====================
                    if debug == "2":
                        # Initiation/Connection Types
                        if rfc793.biflow_eth_ipv4_tcp_full_duplex_connection_established:
                            print("[D] IPv4-TCP Full-Duplex Connection Established (3-way Handshake): " +\
                                biflow_id_to_pcap_filter(tmp_tcp_biflow_id), flush=True)
                        elif rfc793.biflow_eth_ipv4_tcp_half_duplex_connection_established:
                            print("[D] IPv4-TCP Half-Duplex Connection Established (2-way Handshake): " +\
                                biflow_id_to_pcap_filter(tmp_tcp_biflow_id), flush=True)
                        elif rfc793.biflow_eth_ipv4_tcp_connection_rejected:
                            print("[D] IPv4-TCP Rejected Connection (2-way Handshake): " + biflow_id_to_pcap_filter(tmp_tcp_biflow_id), flush=True)
                        elif rfc793.biflow_eth_ipv4_tcp_connection_dropped:
                            print("[D] IPv4-TCP Dropped Connection (No Handshake): " + biflow_id_to_pcap_filter(tmp_tcp_biflow_id), flush=True)

                        # Termination Types
                        if rfc793.biflow_eth_ipv4_tcp_termination_graceful:
                            print("[D] IPv4-TCP Graceful Termination: " + biflow_id_to_pcap_filter(tmp_tcp_biflow_id), flush=True)
                        elif rfc793.biflow_eth_ipv4_tcp_termination_abort:
                            print("[D] IPv4-TCP Abort Termination: " + biflow_id_to_pcap_filter(tmp_tcp_biflow_id), flush=True)
                        elif rfc793.biflow_eth_ipv4_tcp_termination_null:
                            print("[D] IPv4-TCP Null Termination: " + biflow_id_to_pcap_filter(tmp_tcp_biflow_id), flush=True)

                    # =====================================================================================================
                    # Flow Termination: reset all inside loop, in case there's a 6-tuple biflow inside this 5-tuple parsing
                    # =====================================================================================================
                    rfc793.reset_states_and_genes()

                    # keep iterating through the packets
                    curr_packet_index += 1

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
    tcp_biflows, tcp_biflow_ids, rfc793_tcp_biflow_conceptual_features, n_disconected_rfc793_packets = build_rfc793_tcp_biflows(tmp_tcp_biflows, tmp_tcp_biflow_ids, debug=True)
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
                    biflow_eth_ipv4_tcp_initiation_two_way_handshake = curr_biflow_l4_conceptual_features[0]
                    biflow_eth_ipv4_tcp_full_duplex_connection_established = curr_biflow_l4_conceptual_features[1]
                    biflow_eth_ipv4_tcp_half_duplex_connection_established = curr_biflow_l4_conceptual_features[2]
                    biflow_eth_ipv4_tcp_connection_rejected = curr_biflow_l4_conceptual_features[3]
                    biflow_eth_ipv4_tcp_connection_dropped = curr_biflow_l4_conceptual_features[4]
                    biflow_eth_ipv4_tcp_termination_graceful = curr_biflow_l4_conceptual_features[5]
                    biflow_eth_ipv4_tcp_termination_abort = curr_biflow_l4_conceptual_features[6]
                    biflow_eth_ipv4_tcp_termination_null = curr_biflow_l4_conceptual_features[7]

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
            biflow_any_iats = list()
            biflow_fwd_iats = list()
            biflow_bwd_iats = list()

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
                    biflow_any_iats.append(curr_packet_iat)
                    if previous_packet_biflow_id == biflow_id:
                        biflow_fwd_iats.append(curr_packet_iat)
                    else:
                        biflow_bwd_iats.append(curr_packet_iat)

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
                    print(Colors.RED + iterator_to_str(biflow_id), "is an out-of-order BiFlow. Ignoring..." + Colors.ENDC)
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
            if len(biflow_any_iats) == 0:
                biflow_any_iat_total = biflow_any_iat_max = biflow_any_iat_min = 0.0
                biflow_any_iat_mean = biflow_any_iat_std = biflow_any_iat_var = 0.0
            else:
                biflow_any_iat_total = round(sum(biflow_any_iats), 3)
                biflow_any_iat_mean = round(np.mean(biflow_any_iats), 3)
                biflow_any_iat_std = round(np.std(biflow_any_iats), 3)
                biflow_any_iat_var = round(np.var(biflow_any_iats), 3)
                biflow_any_iat_max = round(max(biflow_any_iats), 3)
                biflow_any_iat_min = round(min(biflow_any_iats), 3)

            # Packet IATs need at least 2 packets to be properly populated
            if len(biflow_fwd_iats) == 0:
                biflow_fwd_iat_total = biflow_fwd_iat_max = biflow_fwd_iat_min = 0.0
                biflow_fwd_iat_mean = biflow_fwd_iat_std = biflow_fwd_iat_var = 0.0
            else:
                biflow_fwd_iat_total = round(sum(biflow_fwd_iats), 3)
                biflow_fwd_iat_mean = round(np.mean(biflow_fwd_iats), 3)
                biflow_fwd_iat_std = round(np.std(biflow_fwd_iats), 3)
                biflow_fwd_iat_var = round(np.var(biflow_fwd_iats), 3)
                biflow_fwd_iat_max = round(max(biflow_fwd_iats), 3)
                biflow_fwd_iat_min = round(min(biflow_fwd_iats), 3)

            # Packet IATs need at least 2 packets to be properly populated
            if len(biflow_bwd_iats) == 0:
                biflow_bwd_iat_total = biflow_bwd_iat_max = biflow_bwd_iat_min = 0.0
                biflow_bwd_iat_mean = biflow_bwd_iat_std = biflow_bwd_iat_var = 0.0
            else:
                biflow_bwd_iat_total = round(sum(biflow_bwd_iats), 3)
                biflow_bwd_iat_mean = round(np.mean(biflow_bwd_iats), 3)
                biflow_bwd_iat_std = round(np.std(biflow_bwd_iats), 3)
                biflow_bwd_iat_var = round(np.var(biflow_bwd_iats), 3)
                biflow_bwd_iat_max = round(max(biflow_bwd_iats), 3)
                biflow_bwd_iat_min = round(min(biflow_bwd_iats), 3)

            # ======================
            # IP Fragmentation Flags
            # ======================
            biflow_any_eth_ip_df_flags_total = round(sum(biflow_any_eth_ip_df_flags), 3)
            biflow_any_eth_ip_df_flags_mean = round(np.mean(biflow_any_eth_ip_df_flags), 3)
            biflow_any_eth_ip_df_flags_std = round(np.std(biflow_any_eth_ip_df_flags), 3)
            biflow_any_eth_ip_df_flags_var = round(np.var(biflow_any_eth_ip_df_flags), 3)
            biflow_any_eth_ip_df_flags_max = round(max(biflow_any_eth_ip_df_flags), 3)
            biflow_any_eth_ip_df_flags_min = round(min(biflow_any_eth_ip_df_flags), 3)

            biflow_fwd_eth_ip_df_flags_total = round(sum(biflow_fwd_eth_ip_df_flags), 3)
            biflow_fwd_eth_ip_df_flags_mean = round(np.mean(biflow_fwd_eth_ip_df_flags), 3)
            biflow_fwd_eth_ip_df_flags_std = round(np.std(biflow_fwd_eth_ip_df_flags), 3)
            biflow_fwd_eth_ip_df_flags_var = round(np.var(biflow_fwd_eth_ip_df_flags), 3)
            biflow_fwd_eth_ip_df_flags_max = round(max(biflow_fwd_eth_ip_df_flags), 3)
            biflow_fwd_eth_ip_df_flags_min = round(min(biflow_fwd_eth_ip_df_flags), 3)

            if len(biflow_bwd_eth_ip_df_flags) == 0:
                biflow_bwd_eth_ip_df_flags_total = biflow_bwd_eth_ip_df_flags_max = biflow_bwd_eth_ip_df_flags_min = 0
                biflow_bwd_eth_ip_df_flags_mean = biflow_bwd_eth_ip_df_flags_std = biflow_bwd_eth_ip_df_flags_var = 0.0
            else:
                biflow_bwd_eth_ip_df_flags_total = round(sum(biflow_bwd_eth_ip_df_flags), 3)
                biflow_bwd_eth_ip_df_flags_mean = round(np.mean(biflow_bwd_eth_ip_df_flags), 3)
                biflow_bwd_eth_ip_df_flags_std = round(np.std(biflow_bwd_eth_ip_df_flags), 3)
                biflow_bwd_eth_ip_df_flags_var = round(np.var(biflow_bwd_eth_ip_df_flags), 3)
                biflow_bwd_eth_ip_df_flags_max = round(max(biflow_bwd_eth_ip_df_flags), 3)
                biflow_bwd_eth_ip_df_flags_min = round(min(biflow_bwd_eth_ip_df_flags), 3)

            biflow_any_eth_ip_mf_flags_total = round(sum(biflow_any_eth_ip_mf_flags), 3)
            biflow_any_eth_ip_mf_flags_mean = round(np.mean(biflow_any_eth_ip_mf_flags), 3)
            biflow_any_eth_ip_mf_flags_std = round(np.std(biflow_any_eth_ip_mf_flags), 3)
            biflow_any_eth_ip_mf_flags_var = round(np.var(biflow_any_eth_ip_mf_flags), 3)
            biflow_any_eth_ip_mf_flags_max = round(max(biflow_any_eth_ip_mf_flags), 3)
            biflow_any_eth_ip_mf_flags_min = round(min(biflow_any_eth_ip_mf_flags), 3)

            biflow_fwd_eth_ip_mf_flags_total = round(sum(biflow_fwd_eth_ip_mf_flags), 3)
            biflow_fwd_eth_ip_mf_flags_mean = round(np.mean(biflow_fwd_eth_ip_mf_flags), 3)
            biflow_fwd_eth_ip_mf_flags_std = round(np.std(biflow_fwd_eth_ip_mf_flags), 3)
            biflow_fwd_eth_ip_mf_flags_var = round(np.var(biflow_fwd_eth_ip_mf_flags), 3)
            biflow_fwd_eth_ip_mf_flags_max = round(max(biflow_fwd_eth_ip_mf_flags), 3)
            biflow_fwd_eth_ip_mf_flags_min = round(min(biflow_fwd_eth_ip_mf_flags), 3)

            if len(biflow_bwd_eth_ip_mf_flags) == 0:
                biflow_bwd_eth_ip_mf_flags_total = biflow_bwd_eth_ip_mf_flags_max = biflow_bwd_eth_ip_mf_flags_min = 0
                biflow_bwd_eth_ip_mf_flags_mean = biflow_bwd_eth_ip_mf_flags_std = biflow_bwd_eth_ip_mf_flags_var = 0.0
            else:
                biflow_bwd_eth_ip_mf_flags_total = round(sum(biflow_bwd_eth_ip_mf_flags), 3)
                biflow_bwd_eth_ip_mf_flags_mean = round(np.mean(biflow_bwd_eth_ip_mf_flags), 3)
                biflow_bwd_eth_ip_mf_flags_std = round(np.std(biflow_bwd_eth_ip_mf_flags), 3)
                biflow_bwd_eth_ip_mf_flags_var = round(np.var(biflow_bwd_eth_ip_mf_flags), 3)
                biflow_bwd_eth_ip_mf_flags_max = round(max(biflow_bwd_eth_ip_mf_flags), 3)
                biflow_bwd_eth_ip_mf_flags_min = round(min(biflow_bwd_eth_ip_mf_flags), 3)

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
                    biflow_any_eth_ipv4_tcp_fin_flags_total = round(sum(biflow_any_eth_ipv4_tcp_fin_flags), 3)
                    biflow_any_eth_ipv4_tcp_fin_flags_mean = round(np.mean(biflow_any_eth_ipv4_tcp_fin_flags), 3)
                    biflow_any_eth_ipv4_tcp_fin_flags_std = round(np.std(biflow_any_eth_ipv4_tcp_fin_flags), 3)
                    biflow_any_eth_ipv4_tcp_fin_flags_var = round(np.var(biflow_any_eth_ipv4_tcp_fin_flags), 3)
                    biflow_any_eth_ipv4_tcp_fin_flags_max = round(max(biflow_any_eth_ipv4_tcp_fin_flags), 3)
                    biflow_any_eth_ipv4_tcp_fin_flags_min = round(min(biflow_any_eth_ipv4_tcp_fin_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_fin_flags_total = round(sum(biflow_fwd_eth_ipv4_tcp_fin_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_fin_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_tcp_fin_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_fin_flags_std = round(np.std(biflow_fwd_eth_ipv4_tcp_fin_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_fin_flags_var = round(np.var(biflow_fwd_eth_ipv4_tcp_fin_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_fin_flags_max = round(max(biflow_fwd_eth_ipv4_tcp_fin_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_fin_flags_min = round(min(biflow_fwd_eth_ipv4_tcp_fin_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_fin_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_fin_flags_total = biflow_bwd_eth_ipv4_tcp_fin_flags_max = biflow_bwd_eth_ipv4_tcp_fin_flags_min = 0
                        biflow_bwd_eth_ipv4_tcp_fin_flags_mean = biflow_bwd_eth_ipv4_tcp_fin_flags_std = biflow_bwd_eth_ipv4_tcp_fin_flags_var = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_fin_flags_total = round(sum(biflow_bwd_eth_ipv4_tcp_fin_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_fin_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_tcp_fin_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_fin_flags_std = round(np.std(biflow_bwd_eth_ipv4_tcp_fin_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_fin_flags_var = round(np.var(biflow_bwd_eth_ipv4_tcp_fin_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_fin_flags_max = round(max(biflow_bwd_eth_ipv4_tcp_fin_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_fin_flags_min = round(min(biflow_bwd_eth_ipv4_tcp_fin_flags), 3)

                    # =========
                    # SYN FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_syn_flags_total = round(sum(biflow_any_eth_ipv4_tcp_syn_flags), 3)
                    biflow_any_eth_ipv4_tcp_syn_flags_mean = round(np.mean(biflow_any_eth_ipv4_tcp_syn_flags), 3)
                    biflow_any_eth_ipv4_tcp_syn_flags_std = round(np.std(biflow_any_eth_ipv4_tcp_syn_flags), 3)
                    biflow_any_eth_ipv4_tcp_syn_flags_var = round(np.var(biflow_any_eth_ipv4_tcp_syn_flags), 3)
                    biflow_any_eth_ipv4_tcp_syn_flags_max = round(max(biflow_any_eth_ipv4_tcp_syn_flags), 3)
                    biflow_any_eth_ipv4_tcp_syn_flags_min = round(min(biflow_any_eth_ipv4_tcp_syn_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_syn_flags_total = round(sum(biflow_fwd_eth_ipv4_tcp_syn_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_syn_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_tcp_syn_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_syn_flags_std = round(np.std(biflow_fwd_eth_ipv4_tcp_syn_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_syn_flags_var = round(np.var(biflow_fwd_eth_ipv4_tcp_syn_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_syn_flags_max = round(max(biflow_fwd_eth_ipv4_tcp_syn_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_syn_flags_min = round(min(biflow_fwd_eth_ipv4_tcp_syn_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_syn_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_syn_flags_total = biflow_bwd_eth_ipv4_tcp_syn_flags_max = biflow_bwd_eth_ipv4_tcp_syn_flags_min = 0
                        biflow_bwd_eth_ipv4_tcp_syn_flags_mean = biflow_bwd_eth_ipv4_tcp_syn_flags_std = biflow_bwd_eth_ipv4_tcp_syn_flags_var = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_syn_flags_total = round(sum(biflow_bwd_eth_ipv4_tcp_syn_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_syn_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_tcp_syn_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_syn_flags_std = round(np.std(biflow_bwd_eth_ipv4_tcp_syn_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_syn_flags_var = round(np.var(biflow_bwd_eth_ipv4_tcp_syn_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_syn_flags_max = round(max(biflow_bwd_eth_ipv4_tcp_syn_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_syn_flags_min = round(min(biflow_bwd_eth_ipv4_tcp_syn_flags), 3)

                    # =========
                    # RST FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_rst_flags_total = round(sum(biflow_any_eth_ipv4_tcp_rst_flags), 3)
                    biflow_any_eth_ipv4_tcp_rst_flags_mean = round(np.mean(biflow_any_eth_ipv4_tcp_rst_flags), 3)
                    biflow_any_eth_ipv4_tcp_rst_flags_std = round(np.std(biflow_any_eth_ipv4_tcp_rst_flags), 3)
                    biflow_any_eth_ipv4_tcp_rst_flags_var = round(np.var(biflow_any_eth_ipv4_tcp_rst_flags), 3)
                    biflow_any_eth_ipv4_tcp_rst_flags_max = round(max(biflow_any_eth_ipv4_tcp_rst_flags), 3)
                    biflow_any_eth_ipv4_tcp_rst_flags_min = round(min(biflow_any_eth_ipv4_tcp_rst_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_rst_flags_total = round(sum(biflow_fwd_eth_ipv4_tcp_rst_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_rst_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_tcp_rst_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_rst_flags_std = round(np.std(biflow_fwd_eth_ipv4_tcp_rst_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_rst_flags_var = round(np.var(biflow_fwd_eth_ipv4_tcp_rst_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_rst_flags_max = round(max(biflow_fwd_eth_ipv4_tcp_rst_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_rst_flags_min = round(min(biflow_fwd_eth_ipv4_tcp_rst_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_rst_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_rst_flags_total = biflow_bwd_eth_ipv4_tcp_rst_flags_max = biflow_bwd_eth_ipv4_tcp_rst_flags_min = 0
                        biflow_bwd_eth_ipv4_tcp_rst_flags_mean = biflow_bwd_eth_ipv4_tcp_rst_flags_std = biflow_bwd_eth_ipv4_tcp_rst_flags_var = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_rst_flags_total = round(sum(biflow_bwd_eth_ipv4_tcp_rst_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_rst_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_tcp_rst_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_rst_flags_std = round(np.std(biflow_bwd_eth_ipv4_tcp_rst_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_rst_flags_var = round(np.var(biflow_bwd_eth_ipv4_tcp_rst_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_rst_flags_max = round(max(biflow_bwd_eth_ipv4_tcp_rst_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_rst_flags_min = round(min(biflow_bwd_eth_ipv4_tcp_rst_flags), 3)

                    # =========
                    # PSH FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_psh_flags_total = round(sum(biflow_any_eth_ipv4_tcp_psh_flags), 3)
                    biflow_any_eth_ipv4_tcp_psh_flags_mean = round(np.mean(biflow_any_eth_ipv4_tcp_psh_flags), 3)
                    biflow_any_eth_ipv4_tcp_psh_flags_std = round(np.std(biflow_any_eth_ipv4_tcp_psh_flags), 3)
                    biflow_any_eth_ipv4_tcp_psh_flags_var = round(np.var(biflow_any_eth_ipv4_tcp_psh_flags), 3)
                    biflow_any_eth_ipv4_tcp_psh_flags_max = round(max(biflow_any_eth_ipv4_tcp_psh_flags), 3)
                    biflow_any_eth_ipv4_tcp_psh_flags_min = round(min(biflow_any_eth_ipv4_tcp_psh_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_psh_flags_total = round(sum(biflow_fwd_eth_ipv4_tcp_psh_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_psh_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_tcp_psh_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_psh_flags_std = round(np.std(biflow_fwd_eth_ipv4_tcp_psh_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_psh_flags_var = round(np.var(biflow_fwd_eth_ipv4_tcp_psh_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_psh_flags_max = round(max(biflow_fwd_eth_ipv4_tcp_psh_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_psh_flags_min = round(min(biflow_fwd_eth_ipv4_tcp_psh_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_psh_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_psh_flags_total = biflow_bwd_eth_ipv4_tcp_psh_flags_max = biflow_bwd_eth_ipv4_tcp_psh_flags_min = 0
                        biflow_bwd_eth_ipv4_tcp_psh_flags_mean = biflow_bwd_eth_ipv4_tcp_psh_flags_std = biflow_bwd_eth_ipv4_tcp_psh_flags_var = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_psh_flags_total = round(sum(biflow_bwd_eth_ipv4_tcp_psh_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_psh_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_tcp_psh_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_psh_flags_std = round(np.std(biflow_bwd_eth_ipv4_tcp_psh_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_psh_flags_var = round(np.var(biflow_bwd_eth_ipv4_tcp_psh_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_psh_flags_max = round(max(biflow_bwd_eth_ipv4_tcp_psh_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_psh_flags_min = round(min(biflow_bwd_eth_ipv4_tcp_psh_flags), 3)

                    # =========
                    # ACK FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_ack_flags_total = round(sum(biflow_any_eth_ipv4_tcp_ack_flags), 3)
                    biflow_any_eth_ipv4_tcp_ack_flags_mean = round(np.mean(biflow_any_eth_ipv4_tcp_ack_flags), 3)
                    biflow_any_eth_ipv4_tcp_ack_flags_std = round(np.std(biflow_any_eth_ipv4_tcp_ack_flags), 3)
                    biflow_any_eth_ipv4_tcp_ack_flags_var = round(np.var(biflow_any_eth_ipv4_tcp_ack_flags), 3)
                    biflow_any_eth_ipv4_tcp_ack_flags_max = round(max(biflow_any_eth_ipv4_tcp_ack_flags), 3)
                    biflow_any_eth_ipv4_tcp_ack_flags_min = round(min(biflow_any_eth_ipv4_tcp_ack_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_ack_flags_total = round(sum(biflow_fwd_eth_ipv4_tcp_ack_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ack_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_tcp_ack_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ack_flags_std = round(np.std(biflow_fwd_eth_ipv4_tcp_ack_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ack_flags_var = round(np.var(biflow_fwd_eth_ipv4_tcp_ack_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ack_flags_max = round(max(biflow_fwd_eth_ipv4_tcp_ack_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ack_flags_min = round(min(biflow_fwd_eth_ipv4_tcp_ack_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_ack_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_ack_flags_total = biflow_bwd_eth_ipv4_tcp_ack_flags_max = biflow_bwd_eth_ipv4_tcp_ack_flags_min = 0
                        biflow_bwd_eth_ipv4_tcp_ack_flags_mean = biflow_bwd_eth_ipv4_tcp_ack_flags_std = biflow_bwd_eth_ipv4_tcp_ack_flags_var = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_ack_flags_total = round(sum(biflow_bwd_eth_ipv4_tcp_ack_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ack_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_tcp_ack_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ack_flags_std = round(np.std(biflow_bwd_eth_ipv4_tcp_ack_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ack_flags_var = round(np.var(biflow_bwd_eth_ipv4_tcp_ack_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ack_flags_max = round(max(biflow_bwd_eth_ipv4_tcp_ack_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ack_flags_min = round(min(biflow_bwd_eth_ipv4_tcp_ack_flags), 3)

                    # =========
                    # URG FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_urg_flags_total = round(sum(biflow_any_eth_ipv4_tcp_urg_flags), 3)
                    biflow_any_eth_ipv4_tcp_urg_flags_mean = round(np.mean(biflow_any_eth_ipv4_tcp_urg_flags), 3)
                    biflow_any_eth_ipv4_tcp_urg_flags_std = round(np.std(biflow_any_eth_ipv4_tcp_urg_flags), 3)
                    biflow_any_eth_ipv4_tcp_urg_flags_var = round(np.var(biflow_any_eth_ipv4_tcp_urg_flags), 3)
                    biflow_any_eth_ipv4_tcp_urg_flags_max = round(max(biflow_any_eth_ipv4_tcp_urg_flags), 3)
                    biflow_any_eth_ipv4_tcp_urg_flags_min = round(min(biflow_any_eth_ipv4_tcp_urg_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_urg_flags_total = round(sum(biflow_fwd_eth_ipv4_tcp_urg_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_urg_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_tcp_urg_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_urg_flags_std = round(np.std(biflow_fwd_eth_ipv4_tcp_urg_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_urg_flags_var = round(np.var(biflow_fwd_eth_ipv4_tcp_urg_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_urg_flags_max = round(max(biflow_fwd_eth_ipv4_tcp_urg_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_urg_flags_min = round(min(biflow_fwd_eth_ipv4_tcp_urg_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_urg_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_urg_flags_total = biflow_bwd_eth_ipv4_tcp_urg_flags_max = biflow_bwd_eth_ipv4_tcp_urg_flags_min = 0
                        biflow_bwd_eth_ipv4_tcp_urg_flags_mean = biflow_bwd_eth_ipv4_tcp_urg_flags_std = biflow_bwd_eth_ipv4_tcp_urg_flags_var = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_urg_flags_total = round(sum(biflow_bwd_eth_ipv4_tcp_urg_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_urg_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_tcp_urg_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_urg_flags_std = round(np.std(biflow_bwd_eth_ipv4_tcp_urg_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_urg_flags_var = round(np.var(biflow_bwd_eth_ipv4_tcp_urg_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_urg_flags_max = round(max(biflow_bwd_eth_ipv4_tcp_urg_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_urg_flags_min = round(min(biflow_bwd_eth_ipv4_tcp_urg_flags), 3)

                    # =========
                    # ECE FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_ece_flags_total = round(sum(biflow_any_eth_ipv4_tcp_ece_flags), 3)
                    biflow_any_eth_ipv4_tcp_ece_flags_mean = round(np.mean(biflow_any_eth_ipv4_tcp_ece_flags), 3)
                    biflow_any_eth_ipv4_tcp_ece_flags_std = round(np.std(biflow_any_eth_ipv4_tcp_ece_flags), 3)
                    biflow_any_eth_ipv4_tcp_ece_flags_var = round(np.var(biflow_any_eth_ipv4_tcp_ece_flags), 3)
                    biflow_any_eth_ipv4_tcp_ece_flags_max = round(max(biflow_any_eth_ipv4_tcp_ece_flags), 3)
                    biflow_any_eth_ipv4_tcp_ece_flags_min = round(min(biflow_any_eth_ipv4_tcp_ece_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_ece_flags_total = round(sum(biflow_fwd_eth_ipv4_tcp_ece_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ece_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_tcp_ece_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ece_flags_std = round(np.std(biflow_fwd_eth_ipv4_tcp_ece_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ece_flags_var = round(np.var(biflow_fwd_eth_ipv4_tcp_ece_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ece_flags_max = round(max(biflow_fwd_eth_ipv4_tcp_ece_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_ece_flags_min = round(min(biflow_fwd_eth_ipv4_tcp_ece_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_ece_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_ece_flags_total = biflow_bwd_eth_ipv4_tcp_ece_flags_max = biflow_bwd_eth_ipv4_tcp_ece_flags_min = 0
                        biflow_bwd_eth_ipv4_tcp_ece_flags_mean = biflow_bwd_eth_ipv4_tcp_ece_flags_std = biflow_bwd_eth_ipv4_tcp_ece_flags_var = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_ece_flags_total = round(sum(biflow_bwd_eth_ipv4_tcp_ece_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ece_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_tcp_ece_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ece_flags_std = round(np.std(biflow_bwd_eth_ipv4_tcp_ece_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ece_flags_var = round(np.var(biflow_bwd_eth_ipv4_tcp_ece_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ece_flags_max = round(max(biflow_bwd_eth_ipv4_tcp_ece_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_ece_flags_min = round(min(biflow_bwd_eth_ipv4_tcp_ece_flags), 3)

                    # =========
                    # CWR FLAGS
                    # =========
                    biflow_any_eth_ipv4_tcp_cwr_flags_total = round(sum(biflow_any_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_any_eth_ipv4_tcp_cwr_flags_mean = round(np.mean(biflow_any_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_any_eth_ipv4_tcp_cwr_flags_std = round(np.std(biflow_any_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_any_eth_ipv4_tcp_cwr_flags_var = round(np.var(biflow_any_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_any_eth_ipv4_tcp_cwr_flags_max = round(max(biflow_any_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_any_eth_ipv4_tcp_cwr_flags_min = round(min(biflow_any_eth_ipv4_tcp_cwr_flags), 3)

                    biflow_fwd_eth_ipv4_tcp_cwr_flags_total = round(sum(biflow_fwd_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_cwr_flags_mean = round(np.mean(biflow_fwd_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_cwr_flags_std = round(np.std(biflow_fwd_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_cwr_flags_var = round(np.var(biflow_fwd_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_cwr_flags_max = round(max(biflow_fwd_eth_ipv4_tcp_cwr_flags), 3)
                    biflow_fwd_eth_ipv4_tcp_cwr_flags_min = round(min(biflow_fwd_eth_ipv4_tcp_cwr_flags), 3)

                    if len(biflow_bwd_eth_ipv4_tcp_cwr_flags) == 0:
                        biflow_bwd_eth_ipv4_tcp_cwr_flags_total = biflow_bwd_eth_ipv4_tcp_cwr_flags_max = biflow_bwd_eth_ipv4_tcp_cwr_flags_min = 0
                        biflow_bwd_eth_ipv4_tcp_cwr_flags_mean = biflow_bwd_eth_ipv4_tcp_cwr_flags_std = biflow_bwd_eth_ipv4_tcp_cwr_flags_var = 0.0
                    else:
                        biflow_bwd_eth_ipv4_tcp_cwr_flags_total = round(sum(biflow_bwd_eth_ipv4_tcp_cwr_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_cwr_flags_mean = round(np.mean(biflow_bwd_eth_ipv4_tcp_cwr_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_cwr_flags_std = round(np.std(biflow_bwd_eth_ipv4_tcp_cwr_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_cwr_flags_var = round(np.var(biflow_bwd_eth_ipv4_tcp_cwr_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_cwr_flags_max = round(max(biflow_bwd_eth_ipv4_tcp_cwr_flags), 3)
                        biflow_bwd_eth_ipv4_tcp_cwr_flags_min = round(min(biflow_bwd_eth_ipv4_tcp_cwr_flags), 3)
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