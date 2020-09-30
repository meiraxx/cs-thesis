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
                self.biflow_eth_ipv4_tcp_connection_redropped = False
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
                self.biflow_eth_ipv4_tcp_connection_redropped = False
                self.biflow_eth_ipv4_tcp_termination_graceful = False
                self.biflow_eth_ipv4_tcp_termination_abort = False
                self.biflow_eth_ipv4_tcp_termination_null = False

            def get_rfc793_tcp_biflow_conceptual_features(self):
                rfc793_tcp_biflow_conceptual_features = [
                    self.biflow_eth_ipv4_tcp_initiation_two_way_handshake,
                    self.biflow_eth_ipv4_tcp_full_duplex_connection_established,
                    self.biflow_eth_ipv4_tcp_half_duplex_connection_established,
                    self.biflow_eth_ipv4_tcp_connection_rejected,
                    self.biflow_eth_ipv4_tcp_connection_redropped,
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

            if debug == "2":
                print("[D2] Wireshark Flow: %s" %(biflow_id_to_pcap_filter(tmp_tcp_biflow_id)))
            # =================================
            # RFC793-compliant TCP BiFlow Genes
            # =================================
            rfc793 = RFC793()
            rfc793_tcp_biflow_id = None

            # ==============
            # RFC793 parsing
            # ==============
            # SHOULD-TODO: Improve this spaghetti hardcoded code. Try to do static parsing of the whole flow
            # before guessing connection-states dynamically (like TCP does, it's not ideal here)
            # BUG[RFC793-1]: without SEQ/ACK parsing, connection flag bugs in some cases when there are
            # TCP out-of-order and duplicate/retransmission (includes decision changing) packets between
            # the TCP initialization and finalization streams. For example, it causes dropped=True instead
            # of full-duplex=True and fake absence of graceful termination, among others probably...
            # (this needs to be parsed correctly, as in: (1) need to check that packet is fwd and then bwd,
            # (2) seq and ack values should be validated and used to follow the stream as well - more complex due to
            # duplicate/retransmission packets...). These situations typically happen in cases of higher latency.
            curr_packet_index = 0
            previous_packet_index = 0
            inner_sep_counter = 0

            # Saved flow states
            last_duplicate_tcp_seq = None
            fixed_tcp_seq1 = None
            fixed_fin1,fixed_syn1,fixed_rst1,fixed_psh1,fixed_ack1,fixed_urg1,fixed_ece1,fixed_cwr1 = [None]*8
            fixed_tcp_seq2 = None
            fixed_fin2,fixed_syn2,fixed_rst2,fixed_psh2,fixed_ack2,fixed_urg2,fixed_ece2,fixed_cwr2 = [None]*8
            
            while curr_packet_index < flow_any_n_packets:
                if debug == "2":
                    print("[D2] Packet: %s/%s " %(curr_packet_index+1,flow_any_n_packets))
                # ===============
                # TCP PACKET INFO
                # ===============
                # Current packet
                curr_packet = curr_flow[curr_packet_index]
                tcp_seq1 = curr_packet[8]
                #tcp_ack1 = curr_packet[9]
                fin1,syn1,rst1,psh1,ack1,urg1,ece1,cwr1 = curr_packet[-8:]

                # Second packet from current
                try:
                    second_packet = curr_flow[curr_packet_index+1]
                    tcp_seq2 = second_packet[8]
                    #tcp_ack2 = second_packet[9]
                    fin2,syn2,rst2,psh2,ack2,urg2,ece2,cwr2 = second_packet[-8:]
                except IndexError:
                    fin2,syn2,rst2,psh2,ack2,urg2,ece2,cwr2 = [False]*8

                # Third packet from current
                try:
                    third_packet = curr_flow[curr_packet_index+2]
                    tcp_seq3 = third_packet[8]
                    #tcp_ack3 = third_packet[9]
                    fin3,syn3,rst3,psh3,ack3,urg3,ece3,cwr3 = third_packet[-8:]
                except IndexError:
                    fin3,syn3,rst3,psh3,ack3,urg2,ece3,cwr3 = [False]*8
                
                # ====================
                # TCP DUPLICATE IGNORE
                # ====================
                # BUG[RFC793-2] if parallel same-SEQ diff-flag flows are created and even responded to,
                # it's really hard to parse out these results. I have only seen this in flow termination
                # events, but it is possible that it may happen in flow initiation as well. However, for
                # this edge-case, worst case scenario the flow termination will be "null" rather
                # than "graceful" or an "abort" termination, which is not too bad compared to initations
                # and connection state mistakes. However, this should eventually be fixed.
                # [SEQ-1] check for duplicate packets and save current packet state if:
                # (1) packet is a real duplicate (same SEQ and flags)
                # (2) if the new duplicate is not saved yet (fixed_tcp_seq1|fixed_tcp_seq2)
                # (3) packet isn't another duplicate of the last duplicate packet (last_duplicate_tcp_seq)
                if (last_duplicate_tcp_seq != tcp_seq1):
                    # 1-2 sequential duplicate packet
                    duplicate_r1_1 = (tcp_seq1 == tcp_seq2) and \
                        [fin1,syn1,rst1,psh1,ack1,urg1,ece1,cwr1]==[fin2,syn2,rst2,psh2,ack2,urg2,ece2,cwr2]
                    if fixed_tcp_seq1 == None and duplicate_r1_1:
                        if debug == 2:
                            print("[D2] 1-2 sequential DUPLICATE: %s | %s" %(tcp_seq1, tcp_seq2))
                        fixed_tcp_seq1 = tcp_seq1
                        last_duplicate_tcp_seq = tcp_seq1
                        fixed_fin1,fixed_syn1,fixed_rst1,fixed_psh1,fixed_ack1,fixed_urg1,fixed_ece1,fixed_cwr1 = \
                            fin1,syn1,rst1,psh1,ack1,urg1,ece1,cwr1
                elif (last_duplicate_tcp_seq != tcp_seq2):
                    # 2-3 sequential duplicate packet
                    duplicate_r1_2 = (tcp_seq2 == tcp_seq3) and \
                        [fin2,syn2,rst2,psh1,ack2,urg2,ece2,cwr2]==[fin3,syn3,rst3,psh3,ack3,urg3,ece3,cwr3]
                    if fixed_tcp_seq2 == None and duplicate_r1_2:
                        if debug == "2":
                            print(curr_packet_index, tcp_seq1)
                            print("[D2] 2-3 sequential DUPLICATE: %s | %s" %(tcp_seq2, tcp_seq3))
                        fixed_tcp_seq2 = tcp_seq2
                        last_duplicate_tcp_seq = tcp_seq2
                        fixed_fin2,fixed_syn2,fixed_rst2,fixed_psh2,fixed_ack2,fixed_urg2,fixed_ece2,fixed_cwr2 = \
                            fin2,syn2,rst2,psh2,ack2,urg2,ece2,cwr2

                # =========================
                # TCP FLOW INITIATION RULES
                # =========================
                # Begin Flow: tcp_three_way_handshake (r1), tcp_two_way_handshake (r2) and connection request (r3)
                # Non-duplicate flag values will force first flag values
                non_duplicate_syn1 = (syn1 and not ack1) if fixed_tcp_seq1 == None else (fixed_syn1 and not fixed_ack1)
                non_duplicate_syn2_ack2 = (syn2 and ack2) if fixed_tcp_seq2 == None else (fixed_syn2 and fixed_ack2)
                non_duplicate_ack2 = ack2 if fixed_tcp_seq2 == None else fixed_ack2
                non_duplicate_syn2 = (syn2 and not ack2) if fixed_tcp_seq2 == None else (fixed_syn2 and not fixed_ack2)
                non_duplicate_fin1 = fin1 if fixed_tcp_seq1 == None else fixed_fin1
                non_duplicate_fin2_ack2 = (fin2 and ack2) if fixed_tcp_seq2 == None else (fixed_fin2 and fixed_ack2)
                # Other rules
                is_curr_last_packet = (curr_packet_index == flow_any_n_packets-1)

                if debug == "2":
                    print("[D2] Init1 - Syn, Syn-Ack, Ack:", non_duplicate_syn1, non_duplicate_syn2_ack2, ack3)
                    print("[D2] Init2 - Syn, Ack:", non_duplicate_syn1, non_duplicate_syn2_ack2)
                    print("[D2] Init3 - Syn, Syn or isLastPacket():", syn1, is_curr_last_packet)
                    print([fin2,syn2,rst2,psh1,ack2,urg2,ece2,cwr2])
                # 3-way handshake (full-duplex): (syn,syn-ack,ack) or (syn,syn-ack,syn-ack)
                rfc793.flow_initiation_r1 = non_duplicate_syn1 and non_duplicate_syn2_ack2 and ack3
                # 2-way handshake (half-duplex): (syn,ack) or (syn,syn-ack)
                rfc793.flow_initiation_r2 = non_duplicate_syn1 and non_duplicate_ack2
                # Connection request: (syn)
                rfc793.flow_initiation_r3 = False
                
                # ==========================
                # TCP FLOW TERMINATION RULES
                # ==========================
                # End Flow: tcp_graceful_termination (r1), tcp_abort_termination (r2) and last packet (r3)
                if debug == "2":
                    print("[D2] Term1 - Fin, Fin-Ack, Ack:", non_duplicate_fin1, non_duplicate_fin2_ack2, ack3)
                    print("[D2] Term2 - Rst, !Rst:", rst1, not rst2)
                    print("[D2] Term3 - isLastPacket():", is_curr_last_packet)

                # graceful termination
                rfc793.flow_termination_r1 = non_duplicate_fin1 and non_duplicate_fin2_ack2 and ack3
                # abort termination
                rfc793.flow_termination_r2 = rst1 and not rst2
                # null termination
                rfc793.flow_termination_r3 = is_curr_last_packet

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
                        # ----------------------------------
                        # Established Full-Duplex Connection
                        # ----------------------------------
                        rfc793.flow_initiated = True
                        # RESET saved Flow states
                        last_duplicate_tcp_seq = None
                        fixed_tcp_seq1 = None
                        fixed_fin1,fixed_syn1,fixed_rst1,fixed_psh1,fixed_ack1,fixed_urg1,fixed_ece1,fixed_cwr1 = [None]*8
                        fixed_tcp_seq2 = None
                        fixed_fin2,fixed_syn2,fixed_rst2,fixed_psh2,fixed_ack2,fixed_urg2,fixed_ece2,fixed_cwr2 = [None]*8
                        rfc793.biflow_eth_ipv4_tcp_full_duplex_connection_established = True
                    # -----------------
                    # Two-way Handshake
                    # -----------------
                    elif rfc793.flow_initiation_r2:
                        # Note: Rare occurrence, except in the case of rejected connections:
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
                        # RESET saved Flow states
                        last_duplicate_tcp_seq = None
                        fixed_tcp_seq1 = None
                        fixed_fin1,fixed_syn1,fixed_rst1,fixed_psh1,fixed_ack1,fixed_urg1,fixed_ece1,fixed_cwr1 = [None]*8
                        fixed_tcp_seq2 = None
                        fixed_fin2,fixed_syn2,fixed_rst2,fixed_psh2,fixed_ack2,fixed_urg2,fixed_ece2,fixed_cwr2 = [None]*8
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
                        # ------------------
                        # Dropped connection
                        # ------------------
                        rfc793.flow_initiated = True
                        # RESET saved Flow states
                        last_duplicate_tcp_seq = None
                        fixed_tcp_seq1 = None
                        fixed_fin1,fixed_syn1,fixed_rst1,fixed_psh1,fixed_ack1,fixed_urg1,fixed_ece1,fixed_cwr1 = [None]*8
                        fixed_tcp_seq2 = None
                        fixed_fin2,fixed_syn2,fixed_rst2,fixed_psh2,fixed_ack2,fixed_urg2,fixed_ece2,fixed_cwr2 = [None]*8
                        rfc793.biflow_eth_ipv4_tcp_connection_redropped = True

                # the flow end conditions are r1 and r2, (fin,fin-ack,ack)/(rst,!rst,---),
                # or if the packet is the last one of the existing communication
                # SHOULD-TODO: Improve this spaghetti hardcoded code
                if rfc793.flow_initiated:
                    rfc793_tcp_biflow_id = (tmp_tcp_biflow_id[0], tmp_tcp_biflow_id[1], tmp_tcp_biflow_id[2],\
                        tmp_tcp_biflow_id[3], tmp_tcp_biflow_id[4], tmp_tcp_biflow_id[5] + inner_sep_counter)
                    # ====================
                    # TCP FLOW TERMINATION
                    # ====================
                    
                    # graceful termination
                    if rfc793.flow_termination_r1:
                        rfc793.flow_initiated = False
                        rfc793.flow_terminated = True
                        # RESET saved Flow states
                        last_duplicate_tcp_seq = None
                        fixed_tcp_seq1 = None
                        fixed_fin1,fixed_syn1,fixed_rst1,fixed_psh1,fixed_ack1,fixed_urg1,fixed_ece1,fixed_cwr1 = [None]*8
                        fixed_tcp_seq2 = None
                        fixed_fin2,fixed_syn2,fixed_rst2,fixed_psh2,fixed_ack2,fixed_urg2,fixed_ece2,fixed_cwr2 = [None]*8
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
                        # RESET saved Flow states
                        last_duplicate_tcp_seq = None
                        fixed_tcp_seq1 = None
                        fixed_fin1,fixed_syn1,fixed_rst1,fixed_psh1,fixed_ack1,fixed_urg1,fixed_ece1,fixed_cwr1 = [None]*8
                        fixed_tcp_seq2 = None
                        fixed_fin2,fixed_syn2,fixed_rst2,fixed_psh2,fixed_ack2,fixed_urg2,fixed_ece2,fixed_cwr2 = [None]*8
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
                        # RESET saved Flow states
                        last_duplicate_tcp_seq = None
                        fixed_tcp_seq1 = None
                        fixed_fin1,fixed_syn1,fixed_rst1,fixed_psh1,fixed_ack1,fixed_urg1,fixed_ece1,fixed_cwr1 = [None]*8
                        fixed_tcp_seq2 = None
                        fixed_fin2,fixed_syn2,fixed_rst2,fixed_psh2,fixed_ack2,fixed_urg2,fixed_ece2,fixed_cwr2 = [None]*8
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
                        print("[D2] IPv4-TCP Full-Duplex Connection Established (3-way Handshake)", flush=True)
                    elif rfc793.biflow_eth_ipv4_tcp_half_duplex_connection_established:
                        print("[D2] IPv4-TCP Half-Duplex Connection Established (2-way Handshake)", flush=True)
                    elif rfc793.biflow_eth_ipv4_tcp_connection_rejected:
                        print("[D2] IPv4-TCP Rejected Connection (2-way Handshake)", flush=True)
                    elif rfc793.biflow_eth_ipv4_tcp_connection_redropped:
                        print("[D2] IPv4-TCP Dropped Connection (No Handshake)", flush=True)
                    else:
                        print("[D2] Initiation not reached yet.", flush=True)

                    # Termination Types
                    if rfc793.biflow_eth_ipv4_tcp_termination_graceful:
                        print("[D2] IPv4-TCP Graceful Termination", flush=True)
                    elif rfc793.biflow_eth_ipv4_tcp_termination_abort:
                        print("[D2] IPv4-TCP Abort Termination", flush=True)
                    elif rfc793.biflow_eth_ipv4_tcp_termination_null:
                        print("[D2] IPv4-TCP Null Termination", flush=True)
                    else:
                        print("[D2] Termination not reached yet.", flush=True)

                # =====================================================================================================
                # Flow Termination: reset all inside loop, in case there's a 6-tuple biflow inside this 5-tuple parsing
                # =====================================================================================================
                rfc793.reset_states_and_genes()

                # keep iterating through the packets
                curr_packet_index += 1

        return rfc793_tcp_biflows, rfc793_tcp_biflow_ids, rfc793_tcp_biflow_conceptual_features, n_disconected_rfc793_packets