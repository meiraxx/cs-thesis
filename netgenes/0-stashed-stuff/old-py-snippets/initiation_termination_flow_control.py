def flow_initiation_test(packet1, packet2=None, packet3=None):
    """If there is no initiation active, checks if packet1/packet2/packet3 form any initiation"""
    if (not packet2 and packet3):
        print("[!] flow_initiation_test(): Cannot skip packets.")
        exit()

    fin1, syn1, rst1, psh1, ack1, urg1, ece1, cwr1 = packet1[-8:]
    if packet2: fin2, syn2, rst2, psh2, ack2, urg2, ece2, cwr2 = packet2[-8:]
    if packet3: fin3, syn3, rst3, psh3, ack3, urg3, ece3, cwr3 = packet3[-8:]

    flow_initiation_r1, flow_initiation_r2, flow_initiation_r3 = False, False, False
    if packet1 and packet2 and packet3:
        # R1 -> 3-way handshake (conn-state: full-duplex connection): (syn,syn-ack,ack) or (syn,syn-ack,syn-ack) seen
        flow_initiation_r1 = syn1 and (syn2 and ack2) and ack3
    elif packet1 and packet2:
        # R2 -> 2-way handshake (conn-states: half-duplex connection / rejected connection): (syn,ack) or (syn,syn-ack) seen
        flow_initiation_r2 = syn1 and ack2
    else:
        # R3 -> Requested connection (conn-state: dropped connection): (syn) seen
        flow_initiation_r3 = syn1

    flow_initiation_type = "Initiation not seen"
    if flow_initiation_r1:
        flow_initiation_type = "3-way Handshake"
    elif flow_initiation_r2:
        flow_initiation_type = "2-way Handshake"
    elif flow_initiation_r3:
        flow_initiation_type = "Requested Connection"

    return flow_initiation_type
    
def flow_termination_test(packet1=None, packet2=None, packet3=None, is_curr_last_packet=False):
    """If there is an initiation active, checks if packet1/packet2/packet3 form any termination"""
    if (not packet2 and packet3):
        print("[!] flow_termination_test(): Cannot skip packets.")
        exit()

    if packet1: fin1, syn1, rst1, psh1, ack1, urg1, ece1, cwr1 = packet1[-8:]
    if packet2: fin2, syn2, rst2, psh2, ack2, urg2, ece2, cwr2 = packet2[-8:]
    if packet3: fin3, syn3, rst3, psh3, ack3, urg3, ece3, cwr3 = packet3[-8:]

    flow_termination_r1 = False
    flow_termination_r2 = False
    flow_termination_r3 = False
    if packet1 and packet2 and packet3:
        # Graceful termination
        flow_termination_r1 = fin1 and (fin2 and ack2) and ack3
    elif packet1 and packet2:
        pass
    elif packet1:
        # Abort termination
        flow_termination_r2 = rst1
        # Null termination
        flow_termination_r3 = (not rst1) and is_curr_last_packet

    flow_termination_type = "Termination not seen"
    if flow_termination_r1:
        flow_termination_type = "Graceful Termination"
    elif flow_termination_r2:
        flow_termination_type = "Abort Termination"
    elif flow_termination_r3:
        flow_termination_type = "Null Termination"

    return flow_termination_type


# ============================================
# Check flow initiations and flow terminations
# ============================================
# if initiation is not yet complete, then we must test initiation packets
if flow_initiation_type != "3-way Handshake":
    tmp_flow_initiation_type = flow_initiation_test(first_init_packet, second_init_packet, third_init_packet)
    if (flow_initiation_type == "Initiation not seen" and tmp_flow_initiation_type in ("3-way Handshake", "2-way Handshake", "Requested Connection")) \
    or (flow_initiation_type == "Requested Connection" and tmp_flow_initiation_type in ("3-way Handshake", "2-way Handshake")) \
    or (flow_initiation_type == "2-way Handshake" and tmp_flow_initiation_type == "3-way Handshake"):
        # save flow initiation type
        flow_initiation_type = tmp_flow_initiation_type
        # save initation packet
        initiation_packet = i
# ============================================
# Check flow initiations and flow terminations
# ============================================
# if initiation is not yet complete, then we must test initiation packets
if flow_initiation_type != "3-way Handshake":
    tmp_flow_initiation_type = flow_initiation_test(first_init_packet, second_init_packet, third_init_packet)
    if (flow_initiation_type == "Initiation not seen" and tmp_flow_initiation_type in ("3-way Handshake", "2-way Handshake", "Requested Connection")) \
    or (flow_initiation_type == "Requested Connection" and tmp_flow_initiation_type in ("3-way Handshake", "2-way Handshake")) \
    or (flow_initiation_type == "2-way Handshake" and tmp_flow_initiation_type == "3-way Handshake"):
        # save flow initiation type
        flow_initiation_type = tmp_flow_initiation_type
        # save initation packet
        initiation_packet = i
# else, initiation is finished ("3-way Handshake")
# ============================
# TCP Termination Flow Control
# ============================
# if initiation is finished and termination is not yet complete
elif flow_termination_type not in ("Graceful Termination", "Abort Termination", "Null Termination"):
    flow_termination_type = flow_termination_test(first_term_packet, second_term_packet, third_term_packet,\
        is_curr_last_packet=is_curr_last_packet)
    if flow_termination_type != "Termination not seen":
        # save termination packet
        if flow_termination_type == "Graceful Termination":
            termination_packet = i+2
        elif flow_termination_type in ("Abort Termination", "Null Termination"):
            termination_packet = i
