from pynet.netobject_utils import *

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

def build_l4_biflows(l3_biflows, l3_biflow_ids, args):
    """Separate layer-3 bidirectional flows by layer-4 protocol and
    build layer-4 bidirectional flows according to TCP and UDP RFCs"""
    def build_rfc793_tcp_biflows(tmp_tcp_biflows, tmp_tcp_biflow_ids, args):
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
                print("[!] A flow can't have 0 packets.", file=sys.stderr, flush=True)
                sys.exit(1)
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
                    if args.debug == "2":
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
            print("ERROR: Run-time should never reach this branch, but in case it does, it means that another protocol was let through in an earlier stage.",
                file=sys.stderr, flush=True)
            sys.exit(1)

    # Apply RFC793 to the unseparated TCP BiFlows
    tcp_biflows, tcp_biflow_ids, rfc793_tcp_biflow_conceptual_features, n_disconected_rfc793_packets = build_rfc793_tcp_biflows(tmp_tcp_biflows, tmp_tcp_biflow_ids, args)
    return udp_biflows, udp_biflow_ids, tcp_biflows, tcp_biflow_ids, rfc793_tcp_biflow_conceptual_features, n_disconected_rfc793_packets
