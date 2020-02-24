# =========================
# TCP FLOW INITIATION RULES
# =========================
# Begin Flow: tcp_three_way_handshake, tcp_two_way_handshake
# 3-way handshake (full-duplex): (syn,syn-ack,ack) or (syn,syn-ack,syn-ack)
rfc793.tcp_three_way_handshake_phase1 = rfc793.tcp_three_way_handshake_phase1 or ((syn1 and not ack1) and (syn2 and ack2) and ack3)
rfc793.tcp_three_way_handshake_phase2 = rfc793.tcp_three_way_handshake_phase1 and (rfc793.tcp_three_way_handshake_phase2 or ((syn1 and ack1) and ack2))
rfc793.tcp_three_way_handshake_phase3 = rfc793.tcp_three_way_handshake_phase2 and (rfc793.tcp_three_way_handshake_phase3 or ack1)

# 2-way handshake (half-duplex): (syn,ack) or (syn,syn-ack)
rfc793.tcp_two_way_handshake_phase1 = rfc793.tcp_two_way_handshake_phase1 or ((syn1 and not ack1) and ack2)
rfc793.tcp_two_way_handshake_phase2 = rfc793.tcp_two_way_handshake_phase1 and (rfc793.tcp_two_way_handshake_phase2 or ack1)

# ==========================
# TCP FLOW TERMINATION RULES
# ==========================
# End Flow: tcp_graceful_termination, tcp_abort_termination
# graceful termination
rfc793.tcp_graceful_termination_phase1 = rfc793.tcp_graceful_termination_phase1 or (fin1 and (fin2 and ack2) and ack3)
rfc793.tcp_graceful_termination_phase2 = rfc793.tcp_graceful_termination_phase1 and (rfc793.tcp_graceful_termination_phase2 or ((fin1 and ack1) and ack2))
rfc793.tcp_graceful_termination_phase3 = rfc793.tcp_graceful_termination_phase2 and (rfc793.tcp_graceful_termination_phase3 or ack1)

# abort termination
rfc793.tcp_abort_termination_phase1 = rfc793.tcp_abort_termination_phase1 or (rst1 and not rst2)
rfc793.tcp_abort_termination_phase2 = rfc793.tcp_abort_termination_phase1 and (rfc793.tcp_abort_termination_phase2 or not rst1)

# ===================
# TCP FLOW INITIATION
# ===================
# Note: Consider flow begin or ignore it (considering it is safer, but not considering it will
# leave out flows that have started before the capture)

# Flow start conditions:
# S1: 2-way handshake
# S2: 3-way handshake
#if rfc793.tcp_three_way_handshake_phase3:
#    tcp_biflow_initiated = True
#elif rfc793.tcp_two_way_handshake_phase2:
#    tcp_biflow_initiated = True

# Flow end conditions are:
# E1: (fin,fin-ack,ack)
# E2: (rst,!rst,---)
# E3:the packet is the last one of the existing communication
if rfc793.tcp_three_way_handshake_phase3:
    tcp_flow_id = (tmp_tcp_biflow_id[0], tmp_tcp_biflow_id[1], tmp_tcp_biflow_id[2],\
        tmp_tcp_biflow_id[3], tmp_tcp_biflow_id[4], tmp_tcp_biflow_id[5] + rfc793.inner_sep_counter)
    next_packet_index = 0
    # ====================
    # TCP FLOW TERMINATION
    # ====================
    # graceful termination
    if rfc793.tcp_graceful_termination_phase3:
        rfc793_tcp_biflows[tcp_flow_id] = curr_flow[previous_packet_index:curr_packet_index+3]
        rfc793_tcp_biflow_ids.append(tcp_flow_id)
        previous_packet_index = curr_packet_index + 3
        rfc793.inner_sep_counter += 1

        rfc793.tcp_graceful_termination_phase1 = False
        rfc793.tcp_graceful_termination_phase2 = False
        rfc793.tcp_graceful_termination_phase3 = False
    else:
        # abort termination
        if rfc793.tcp_abort_termination_phase2:
            rfc793_tcp_biflows[tcp_flow_id] = curr_flow[previous_packet_index:curr_packet_index+1]
            rfc793_tcp_biflow_ids.append(tcp_flow_id)
            previous_packet_index = curr_packet_index + 1
            rfc793.inner_sep_counter += 1
        # null termination
        elif curr_packet_index == flow_any_n_packets-1:
            rfc793_tcp_biflows[tcp_flow_id] = curr_flow[previous_packet_index:curr_packet_index+1]
            rfc793_tcp_biflow_ids.append(tcp_flow_id)
            previous_packet_index = curr_packet_index + 1
            rfc793.inner_sep_counter += 1
# keep iterating through the packets
curr_packet_index+=1