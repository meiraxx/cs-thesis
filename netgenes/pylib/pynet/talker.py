# Standard
from collections import OrderedDict

# 3rdParty
try:
    import numpy as np
except ImportError:
    raise ImportError("You need to do 'pip3 install -r requirements.txt' to be able to use this program.")

# Ours
from pylib.pynet.netobject_utils import *
from pylib.pyaux.utils import datetime_to_unixtime, unixtime_to_datetime

def build_unitalkers(biflow_genes_generator_lst, biflow_ids):
    """Build UniTalkers"""
    unitalkers = dict()
    unitalker_ids = list()

    for biflow_genes in biflow_genes_generator_lst:
        #biflow_id_str = biflow_genes[0]
        #biflow_id = str_to_iterator(biflow_id_str)
        #unitalker_id = biflow_id_to_bitalker_id(biflow_id)
        unitalker_id = tuple(str_to_iterator(biflow_genes[1]))
        try:
            unitalkers[unitalker_id].append(biflow_genes)
        except KeyError:
            unitalker_ids.append(unitalker_id)
            unitalkers[unitalker_id] = [biflow_genes]

    return unitalkers, unitalker_ids

def build_bitalkers(unitalkers, unitalker_ids):
    """Build BiTalkers"""
    def get_unique_matching_unitalker_ids(unitalkers, unitalker_ids):
        """Local helper function to return matching unidirectional talker ids, with fwd_talker_id
        as key and bwd_talker_id as value, and not vice-versa"""
        matching_unitalker_ids_dict = dict()
        fwd_talker_ids = list()
        for unitalker_id in unitalker_ids:
            reversed_unitalker_id = (unitalker_id[1], unitalker_id[0], unitalker_id[2])

            # Note: O(n**2) --> O(n) optimization done using dictionary search
            if reversed_unitalker_id in unitalkers:
                if reversed_unitalker_id not in matching_unitalker_ids_dict:
                    fwd_talker_ids.append(unitalker_id)
                    matching_unitalker_ids_dict[unitalker_id] = reversed_unitalker_id
            else:
                if reversed_unitalker_id not in matching_unitalker_ids_dict:
                    fwd_talker_ids.append(unitalker_id)
                    matching_unitalker_ids_dict[unitalker_id] = False
        return matching_unitalker_ids_dict, fwd_talker_ids

    matching_unitalker_ids_dict, fwd_talker_ids = get_unique_matching_unitalker_ids(unitalkers, unitalker_ids)
    bitalkers = dict()
    bitalker_ids = list()

    for fwd_talker_id in fwd_talker_ids:
        # have in mind every unitalker_id in this list will have been constituted by the first flow ever recorded in that talker,
        # so the researcher defines bitalker_id = fwd_talker_id
        bwd_talker_id = matching_unitalker_ids_dict[fwd_talker_id]
        bitalker_ids.append(fwd_talker_id)
        if bwd_talker_id:
            bitalkers[fwd_talker_id] = unitalkers[fwd_talker_id] + unitalkers[bwd_talker_id]
        else:
            bitalkers[fwd_talker_id] = unitalkers[fwd_talker_id]

    return bitalkers, bitalker_ids

def get_l3_l4_bitalker_gene_generators(genes_dir, bitalkers, bitalker_ids, l4_protocol=None):
    """Return L3-L4 bitalker gene generators"""
    def calculate_l3_l4_bitalker_genes(genes_dir, bitalkers, bitalker_ids, l4_protocol=None):
        """Calculate and yield L3-L4 bitalker genes"""
        time_scale_factor = 1000.0
        # =================
        # IPv4 GENES HEADER
        # =================
        ipv4_bitalker_genes_header_list = get_network_object_header(genes_dir, "bitalker", "ipv4")
        # ===============
        # L4 GENES HEADER
        # ===============
        ipv4_l4_bitalker_genes_header_list = get_network_object_header(genes_dir, "bitalker", "ipv4-l4")
        # ================
        # TCP GENES HEADER
        # ================
        ipv4_tcp_bitalker_genes_header_list = get_network_object_header(genes_dir, "bitalker", "ipv4-tcp")

        # IPv4 Header
        ipv4_all_bitalker_genes_header_list = ipv4_bitalker_genes_header_list
        if l4_protocol:
            # IPv4-L4 Header
            ipv4_all_bitalker_genes_header_list += ipv4_l4_bitalker_genes_header_list
            if l4_protocol == "UDP":
                pass
            elif l4_protocol == "TCP":
                ipv4_all_bitalker_genes_header_list += ipv4_tcp_bitalker_genes_header_list

        for bitalker_id in bitalker_ids:
            # ======================
            # Additional Information
            # ======================
            curr_bitalker = bitalkers[bitalker_id]

            first_biflow = curr_bitalker[0]
            last_biflow = curr_bitalker[-1]
            bitalker_any_first_biflow_initiation_time = first_biflow[6]
            bitalker_any_last_biflow_termination_time = last_biflow[7]
            bitalker_any_first_biflow_initiation_time = datetime_to_unixtime(bitalker_any_first_biflow_initiation_time)
            bitalker_any_last_biflow_termination_time = datetime_to_unixtime(bitalker_any_last_biflow_termination_time)

            # =========================
            # PREPARE DATA STRUCTURES |
            # =========================
            # ======
            # BiFlow
            # ======
            # ----------------------
            # BiFlow Number Features
            # ----------------------
            bitalker_any_n_biflows = len(curr_bitalker)
            bitalker_fwd_n_biflows = 0
            bitalker_bwd_n_biflows = 0

            # ================================
            # BiFlow & Byte Frequency Features
            # ================================
            # done below

            # =============
            # Time Features
            # =============
            bitalker_any_duration = round(\
                (bitalker_any_last_biflow_termination_time - bitalker_any_first_biflow_initiation_time)/time_scale_factor, 3)

            # =========================
            # Destination Port Features
            # =========================
            bitalker_any_biflow_dst_ports = list()
            bitalker_fwd_biflow_dst_ports = list()
            bitalker_bwd_biflow_dst_ports = list()

            # ====================
            # Source Port Features
            # ====================
            bitalker_any_biflow_src_ports = list()
            bitalker_fwd_biflow_src_ports = list()
            bitalker_bwd_biflow_src_ports = list()

            # ===============
            # Packet Features
            # ===============
            bitalker_any_biflow_n_packets = list()
            bitalker_fwd_biflow_n_packets = list()
            bitalker_bwd_biflow_n_packets = list()

            # =========================
            # IPv4 Data Length Features
            # =========================
            bitalker_any_biflow_eth_ipv4_data_lens = list()
            bitalker_fwd_biflow_eth_ipv4_data_lens = list()
            bitalker_bwd_biflow_eth_ipv4_data_lens = list()

            # =======================
            # L4 Data Packet Features
            # =======================
            bitalker_any_eth_ipv4_l4_biflow_n_data_packets = list()
            bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets = list()
            bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets = list()

            # =============
            # Time Features
            # =============
            # ----------------
            # BiFlow Durations
            # ----------------
            bitalker_any_biflow_durations = list()
            bitalker_fwd_biflow_durations = list()
            bitalker_bwd_biflow_durations = list()

            # -----------------------------
            # BiFlow Inter-Initiation Times
            # -----------------------------
            bitalker_any_biflow_iits = list()
            bitalker_fwd_biflow_iits = list()
            bitalker_bwd_biflow_iits = list()

            # ------------------------------
            # BiFlow Inter-Termination Times
            # ------------------------------
            bitalker_any_biflow_itts = list()
            bitalker_fwd_biflow_itts = list()
            bitalker_bwd_biflow_itts = list()

            # -----------------------
            # BiFlow Initiation Types
            # -----------------------
            bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations = list()

            # -----------------------
            # BiFlow Connection Types
            # -----------------------
            bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established = list()
            bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established = list()
            bitalker_eth_ipv4_tcp_biflow_connections_rejected = list()
            bitalker_eth_ipv4_tcp_biflow_connections_dropped = list()

            # ------------------------
            # BiFlow Termination Types
            # ------------------------
            bitalker_eth_ipv4_tcp_biflow_null_terminations = list()
            bitalker_eth_ipv4_tcp_biflow_graceful_terminations = list()
            bitalker_eth_ipv4_tcp_biflow_abort_terminations = list()

            # =================================
            # Additional Information - Reformat
            # =================================
            # Get bihost_id and convert bitalker_id and bihost_id to strings
            bihost_fwd_id = iterator_to_str(bitalker_id_to_bihost_id(bitalker_id))
            bihost_bwd_id = iterator_to_str(bitalker_id_to_bihost_id(bitalker_id, _fwd=False))
            bitalker_id = iterator_to_str(bitalker_id)
            bitalker_any_first_biflow_initiation_time = unixtime_to_datetime(bitalker_any_first_biflow_initiation_time)
            bitalker_any_last_biflow_termination_time = unixtime_to_datetime(bitalker_any_last_biflow_termination_time)

            # ==========================
            # POPULATE DATA STRUCTURES |
            # ==========================
            curr_biflow_index = 0
            while curr_biflow_index < bitalker_any_n_biflows:
                # =================
                # BiFlow Concepts |
                # =================
                if curr_biflow_index >= 1:
                    previous_biflow = curr_bitalker[curr_biflow_index-1]
                    previous_biflow_bitalker_id = previous_biflow[1]
                    previous_biflow_initiation_timestamp = previous_biflow[6]
                    previous_biflow_termination_timestamp = previous_biflow[7]

                curr_biflow = curr_bitalker[curr_biflow_index]
                curr_biflow_id_str = curr_biflow[0]
                curr_biflow_id = str_to_iterator(curr_biflow_id_str)
                curr_biflow_bitalker_id_str = curr_biflow[1]
                curr_biflow_initiation_timestamp = curr_biflow[6]
                curr_biflow_termination_timestamp = curr_biflow[7]

                # BiFlow IIT and ITT require that there's at least two biflows
                if curr_biflow_index >= 1:
                    previous_biflow_initiation_time = datetime_to_unixtime(previous_biflow_initiation_timestamp)
                    curr_biflow_initiation_time = datetime_to_unixtime(curr_biflow_initiation_timestamp)
                    curr_biflow_iit = (curr_biflow_initiation_time - previous_biflow_initiation_time)/time_scale_factor
                    bitalker_any_biflow_iits.append(curr_biflow_iit)

                    previous_biflow_termination_time = datetime_to_unixtime(previous_biflow_termination_timestamp)
                    curr_biflow_termination_time = datetime_to_unixtime(curr_biflow_termination_timestamp)
                    curr_biflow_itt = abs( (curr_biflow_termination_time - previous_biflow_termination_time)/time_scale_factor )
                    bitalker_any_biflow_itts.append(curr_biflow_itt)

                    if previous_biflow_bitalker_id == bitalker_id:
                        bitalker_fwd_biflow_iits.append(curr_biflow_iit)
                        bitalker_fwd_biflow_itts.append(curr_biflow_itt)
                    else:
                        bitalker_bwd_biflow_iits.append(curr_biflow_iit)
                        bitalker_bwd_biflow_itts.append(curr_biflow_itt)

                # =============
                # Time Concepts
                # =============
                curr_biflow_duration = float(curr_biflow[8])
                bitalker_any_biflow_durations.append(curr_biflow_duration)

                # ===============
                # Packet Concepts
                # ===============
                curr_biflow_any_n_packets = int(curr_biflow[9])
                bitalker_any_biflow_n_packets.append(curr_biflow_any_n_packets)

                # =============
                # IPv4 Concepts
                # =============
                curr_biflow_ipv4_data_len_total = int(curr_biflow[54])
                bitalker_any_biflow_eth_ipv4_data_lens.append(curr_biflow_ipv4_data_len_total)

                if curr_biflow_bitalker_id_str == bitalker_id:
                    # Statistical
                    bitalker_fwd_biflow_eth_ipv4_data_lens.append(curr_biflow_ipv4_data_len_total)
                    bitalker_fwd_biflow_n_packets.append(curr_biflow_any_n_packets)
                    bitalker_fwd_biflow_durations.append(curr_biflow_duration)

                    # Conceptual
                    bitalker_fwd_n_biflows += 1
                else:
                    # Statistical
                    bitalker_bwd_biflow_eth_ipv4_data_lens.append(curr_biflow_ipv4_data_len_total)
                    bitalker_bwd_biflow_n_packets.append(curr_biflow_any_n_packets)
                    bitalker_bwd_biflow_durations.append(curr_biflow_duration)

                    # Conceptual
                    bitalker_bwd_n_biflows += 1

                # ===========
                # L4 Concepts
                # ===========
                if l4_protocol:
                    curr_biflow_src_port = curr_biflow_id[1]
                    curr_biflow_dst_port = curr_biflow_id[3]
                    curr_biflow_any_eth_ipv4_l4_n_data_packets = int(curr_biflow[108])

                    bitalker_any_biflow_src_ports.append(curr_biflow_src_port)
                    bitalker_any_biflow_dst_ports.append(curr_biflow_dst_port)
                    bitalker_any_eth_ipv4_l4_biflow_n_data_packets.append(curr_biflow_any_eth_ipv4_l4_n_data_packets)
                    if curr_biflow_bitalker_id_str == bitalker_id:
                        bitalker_fwd_biflow_src_ports.append(curr_biflow_src_port)
                        bitalker_fwd_biflow_dst_ports.append(curr_biflow_dst_port)
                        bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets.append(curr_biflow_any_eth_ipv4_l4_n_data_packets)
                    else:
                        bitalker_bwd_biflow_src_ports.append(curr_biflow_src_port)
                        bitalker_bwd_biflow_dst_ports.append(curr_biflow_dst_port)
                        bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets.append(curr_biflow_any_eth_ipv4_l4_n_data_packets)

                    # ============
                    # TCP Concepts
                    # ============
                    if l4_protocol == "TCP":
                        # DEV-NOTE: "int" function usefully converts True and False into 1 and 0 directly
                        # get initiation type
                        curr_biflow_eth_ipv4_tcp_initiation_two_way_handshake = int(curr_biflow[150]=="True")

                        # get connection type
                        curr_biflow_eth_ipv4_tcp_full_duplex_connection_established = int(curr_biflow[151]=="True")
                        curr_biflow_eth_ipv4_tcp_half_duplex_connection_established = int(curr_biflow[152]=="True")
                        curr_biflow_eth_ipv4_tcp_connection_rejected = int(curr_biflow[153]=="True")
                        curr_biflow_eth_ipv4_tcp_connection_dropped = int(curr_biflow[154]=="True")

                        # get termination type
                        curr_biflow_eth_ipv4_tcp_termination_graceful = int(curr_biflow[155]=="True")
                        curr_biflow_eth_ipv4_tcp_termination_abort = int(curr_biflow[156]=="True")
                        curr_biflow_eth_ipv4_tcp_termination_null = int(curr_biflow[157]=="True")

                        # save initiation type
                        bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations.append(curr_biflow_eth_ipv4_tcp_initiation_two_way_handshake)

                        # save connection type
                        bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established.append(curr_biflow_eth_ipv4_tcp_full_duplex_connection_established)
                        bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established.append(curr_biflow_eth_ipv4_tcp_half_duplex_connection_established)
                        bitalker_eth_ipv4_tcp_biflow_connections_rejected.append(curr_biflow_eth_ipv4_tcp_connection_rejected)
                        bitalker_eth_ipv4_tcp_biflow_connections_dropped.append(curr_biflow_eth_ipv4_tcp_connection_dropped)
                        
                        # save termination type
                        bitalker_eth_ipv4_tcp_biflow_null_terminations.append(curr_biflow_eth_ipv4_tcp_termination_graceful)
                        bitalker_eth_ipv4_tcp_biflow_graceful_terminations.append(curr_biflow_eth_ipv4_tcp_termination_abort)
                        bitalker_eth_ipv4_tcp_biflow_abort_terminations.append(curr_biflow_eth_ipv4_tcp_termination_null)

                # iterate the biflows inside a bitalker
                curr_biflow_index += 1

            # ================================
            # ENRICH AND EXTRACT INFORMATION |
            # ================================
            # ====================
            # Statistical Features
            # ====================
            # ------
            # Packet
            # ------
            bitalker_any_biflow_n_packets_total = round(sum(bitalker_any_biflow_n_packets), 3)
            bitalker_any_biflow_n_packets_mean = round(np.mean(bitalker_any_biflow_n_packets), 3)
            bitalker_any_biflow_n_packets_std = round(np.std(bitalker_any_biflow_n_packets), 3)
            bitalker_any_biflow_n_packets_var = round(np.var(bitalker_any_biflow_n_packets), 3)
            bitalker_any_biflow_n_packets_max = round(max(bitalker_any_biflow_n_packets), 3)
            bitalker_any_biflow_n_packets_min = round(min(bitalker_any_biflow_n_packets), 3)

            bitalker_fwd_biflow_n_packets_total = round(sum(bitalker_fwd_biflow_n_packets), 3)
            bitalker_fwd_biflow_n_packets_mean = round(np.mean(bitalker_fwd_biflow_n_packets), 3)
            bitalker_fwd_biflow_n_packets_std = round(np.std(bitalker_fwd_biflow_n_packets), 3)
            bitalker_fwd_biflow_n_packets_var = round(np.var(bitalker_fwd_biflow_n_packets), 3)
            bitalker_fwd_biflow_n_packets_max = round(max(bitalker_fwd_biflow_n_packets), 3)
            bitalker_fwd_biflow_n_packets_min = round(min(bitalker_fwd_biflow_n_packets), 3)

            if len(bitalker_bwd_biflow_n_packets) == 0:
                bitalker_bwd_biflow_n_packets_total = bitalker_bwd_biflow_n_packets_max = bitalker_bwd_biflow_n_packets_min = 0
                bitalker_bwd_biflow_n_packets_mean = bitalker_bwd_biflow_n_packets_std = bitalker_bwd_biflow_n_packets_var = 0.0
            else:
                bitalker_bwd_biflow_n_packets_total = round(sum(bitalker_bwd_biflow_n_packets), 3)
                bitalker_bwd_biflow_n_packets_mean = round(np.mean(bitalker_bwd_biflow_n_packets), 3)
                bitalker_bwd_biflow_n_packets_std = round(np.std(bitalker_bwd_biflow_n_packets), 3)
                bitalker_bwd_biflow_n_packets_var = round(np.var(bitalker_bwd_biflow_n_packets), 3)
                bitalker_bwd_biflow_n_packets_max = round(max(bitalker_bwd_biflow_n_packets), 3)
                bitalker_bwd_biflow_n_packets_min = round(min(bitalker_bwd_biflow_n_packets), 3)

            # ------------------
            # IPv4 Data Lengthes
            # ------------------
            bitalker_any_biflow_eth_ipv4_data_lens_total = round(sum(bitalker_any_biflow_eth_ipv4_data_lens), 3)
            bitalker_any_biflow_eth_ipv4_data_lens_mean = round(np.mean(bitalker_any_biflow_eth_ipv4_data_lens), 3)
            bitalker_any_biflow_eth_ipv4_data_lens_std = round(np.std(bitalker_any_biflow_eth_ipv4_data_lens), 3)
            bitalker_any_biflow_eth_ipv4_data_lens_var = round(np.var(bitalker_any_biflow_eth_ipv4_data_lens), 3)
            bitalker_any_biflow_eth_ipv4_data_lens_max = round(max(bitalker_any_biflow_eth_ipv4_data_lens), 3)
            bitalker_any_biflow_eth_ipv4_data_lens_min = round(min(bitalker_any_biflow_eth_ipv4_data_lens), 3)

            bitalker_fwd_biflow_eth_ipv4_data_lens_total = round(sum(bitalker_fwd_biflow_eth_ipv4_data_lens), 3)
            bitalker_fwd_biflow_eth_ipv4_data_lens_mean = round(np.mean(bitalker_fwd_biflow_eth_ipv4_data_lens), 3)
            bitalker_fwd_biflow_eth_ipv4_data_lens_std = round(np.std(bitalker_fwd_biflow_eth_ipv4_data_lens), 3)
            bitalker_fwd_biflow_eth_ipv4_data_lens_var = round(np.var(bitalker_fwd_biflow_eth_ipv4_data_lens), 3)
            bitalker_fwd_biflow_eth_ipv4_data_lens_max = round(max(bitalker_fwd_biflow_eth_ipv4_data_lens), 3)
            bitalker_fwd_biflow_eth_ipv4_data_lens_min = round(min(bitalker_fwd_biflow_eth_ipv4_data_lens), 3)

            if len(bitalker_bwd_biflow_eth_ipv4_data_lens) == 0:
                bitalker_bwd_biflow_eth_ipv4_data_lens_total = bitalker_bwd_biflow_eth_ipv4_data_lens_max =\
                    bitalker_bwd_biflow_eth_ipv4_data_lens_min = 0
                bitalker_bwd_biflow_eth_ipv4_data_lens_mean = bitalker_bwd_biflow_eth_ipv4_data_lens_std =\
                    bitalker_bwd_biflow_eth_ipv4_data_lens_var = 0.0
            else:
                bitalker_bwd_biflow_eth_ipv4_data_lens_total = round(sum(bitalker_bwd_biflow_eth_ipv4_data_lens), 3)
                bitalker_bwd_biflow_eth_ipv4_data_lens_mean = round(np.mean(bitalker_bwd_biflow_eth_ipv4_data_lens), 3)
                bitalker_bwd_biflow_eth_ipv4_data_lens_std = round(np.std(bitalker_bwd_biflow_eth_ipv4_data_lens), 3)
                bitalker_bwd_biflow_eth_ipv4_data_lens_var = round(np.var(bitalker_bwd_biflow_eth_ipv4_data_lens), 3)
                bitalker_bwd_biflow_eth_ipv4_data_lens_max = round(max(bitalker_bwd_biflow_eth_ipv4_data_lens), 3)
                bitalker_bwd_biflow_eth_ipv4_data_lens_min = round(min(bitalker_bwd_biflow_eth_ipv4_data_lens), 3)

            # ----------------
            # BiFlow Durations
            # ----------------
            bitalker_any_biflow_duration_total = round(sum(bitalker_any_biflow_durations), 3)
            bitalker_any_biflow_duration_mean = round(np.mean(bitalker_any_biflow_durations), 3)
            bitalker_any_biflow_duration_std = round(np.std(bitalker_any_biflow_durations), 3)
            bitalker_any_biflow_duration_var = round(np.var(bitalker_any_biflow_durations), 3)
            bitalker_any_biflow_duration_max = round(max(bitalker_any_biflow_durations), 3)
            bitalker_any_biflow_duration_min = round(min(bitalker_any_biflow_durations), 3)

            bitalker_fwd_biflow_duration_total = round(sum(bitalker_fwd_biflow_durations), 3)
            bitalker_fwd_biflow_duration_mean = round(np.mean(bitalker_fwd_biflow_durations), 3)
            bitalker_fwd_biflow_duration_std = round(np.std(bitalker_fwd_biflow_durations), 3)
            bitalker_fwd_biflow_duration_var = round(np.var(bitalker_fwd_biflow_durations), 3)
            bitalker_fwd_biflow_duration_max = round(max(bitalker_fwd_biflow_durations), 3)
            bitalker_fwd_biflow_duration_min = round(min(bitalker_fwd_biflow_durations), 3)

            if len(bitalker_bwd_biflow_durations) == 0:
                bitalker_bwd_biflow_duration_total = bitalker_bwd_biflow_duration_max = bitalker_bwd_biflow_duration_min = 0
                bitalker_bwd_biflow_duration_mean = bitalker_bwd_biflow_duration_std = bitalker_bwd_biflow_duration_var = 0.0
            else:
                bitalker_bwd_biflow_duration_total = round(sum(bitalker_bwd_biflow_durations), 3)
                bitalker_bwd_biflow_duration_mean = round(np.mean(bitalker_bwd_biflow_durations), 3)
                bitalker_bwd_biflow_duration_std = round(np.std(bitalker_bwd_biflow_durations), 3)
                bitalker_bwd_biflow_duration_var = round(np.var(bitalker_bwd_biflow_durations), 3)
                bitalker_bwd_biflow_duration_max = round(max(bitalker_bwd_biflow_durations), 3)
                bitalker_bwd_biflow_duration_min = round(min(bitalker_bwd_biflow_durations), 3)

            # -----------------------------
            # BiFlow Inter-Initiation Times
            # -----------------------------
            # Note: need at least 2 BiFlows to populate BiFlow IITs

            if len(bitalker_any_biflow_iits) == 0:
                bitalker_any_biflow_iit_total = bitalker_any_biflow_iit_max = bitalker_any_biflow_iit_min = 0
                bitalker_any_biflow_iit_mean = bitalker_any_biflow_iit_std = bitalker_any_biflow_iit_var = 0.0
            else:
                bitalker_any_biflow_iit_total = round(sum(bitalker_any_biflow_iits), 3)
                bitalker_any_biflow_iit_mean = round(np.mean(bitalker_any_biflow_iits), 3)
                bitalker_any_biflow_iit_std = round(np.std(bitalker_any_biflow_iits), 3)
                bitalker_any_biflow_iit_var = round(np.var(bitalker_any_biflow_iits), 3)
                bitalker_any_biflow_iit_max = round(max(bitalker_any_biflow_iits), 3)
                bitalker_any_biflow_iit_min = round(min(bitalker_any_biflow_iits), 3)

            if len(bitalker_fwd_biflow_iits) == 0:
                bitalker_fwd_biflow_iit_total = bitalker_fwd_biflow_iit_max = bitalker_fwd_biflow_iit_min = 0
                bitalker_fwd_biflow_iit_mean = bitalker_fwd_biflow_iit_std = bitalker_fwd_biflow_iit_var = 0.0
            else:
                bitalker_fwd_biflow_iit_total = round(sum(bitalker_fwd_biflow_iits), 3)
                bitalker_fwd_biflow_iit_mean = round(np.mean(bitalker_fwd_biflow_iits), 3)
                bitalker_fwd_biflow_iit_std = round(np.std(bitalker_fwd_biflow_iits), 3)
                bitalker_fwd_biflow_iit_var = round(np.var(bitalker_fwd_biflow_iits), 3)
                bitalker_fwd_biflow_iit_max = round(max(bitalker_fwd_biflow_iits), 3)
                bitalker_fwd_biflow_iit_min = round(min(bitalker_fwd_biflow_iits), 3)

            if len(bitalker_bwd_biflow_iits) == 0:
                bitalker_bwd_biflow_iit_total = bitalker_bwd_biflow_iit_max = bitalker_bwd_biflow_iit_min = 0
                bitalker_bwd_biflow_iit_mean = bitalker_bwd_biflow_iit_std = bitalker_bwd_biflow_iit_var = 0.0
            else:
                bitalker_bwd_biflow_iit_total = round(sum(bitalker_bwd_biflow_iits), 3)
                bitalker_bwd_biflow_iit_mean = round(np.mean(bitalker_bwd_biflow_iits), 3)
                bitalker_bwd_biflow_iit_std = round(np.std(bitalker_bwd_biflow_iits), 3)
                bitalker_bwd_biflow_iit_var = round(np.var(bitalker_bwd_biflow_iits), 3)
                bitalker_bwd_biflow_iit_max = round(max(bitalker_bwd_biflow_iits), 3)
                bitalker_bwd_biflow_iit_min = round(min(bitalker_bwd_biflow_iits), 3)

            # ------------------------------
            # BiFlow Inter-Termination Times
            # ------------------------------
            # Note: need at least 2 BiFlows to populate BiFlow ITTs
            if len(bitalker_any_biflow_itts) == 0:
                bitalker_any_biflow_itt_total = bitalker_any_biflow_itt_max = bitalker_any_biflow_itt_min = 0
                bitalker_any_biflow_itt_mean = bitalker_any_biflow_itt_std = bitalker_any_biflow_itt_var = 0.0
            else:
                bitalker_any_biflow_itt_total = round(sum(bitalker_any_biflow_itts), 3)
                bitalker_any_biflow_itt_mean = round(np.mean(bitalker_any_biflow_itts), 3)
                bitalker_any_biflow_itt_std = round(np.std(bitalker_any_biflow_itts), 3)
                bitalker_any_biflow_itt_var = round(np.var(bitalker_any_biflow_itts), 3)
                bitalker_any_biflow_itt_max = round(max(bitalker_any_biflow_itts), 3)
                bitalker_any_biflow_itt_min = round(min(bitalker_any_biflow_itts), 3)

            if len(bitalker_fwd_biflow_itts) == 0:
                bitalker_fwd_biflow_itt_total = bitalker_fwd_biflow_itt_max = bitalker_fwd_biflow_itt_min = 0
                bitalker_fwd_biflow_itt_mean = bitalker_fwd_biflow_itt_std = bitalker_fwd_biflow_itt_var = 0.0
            else:
                bitalker_fwd_biflow_itt_total = round(sum(bitalker_fwd_biflow_itts), 3)
                bitalker_fwd_biflow_itt_mean = round(np.mean(bitalker_fwd_biflow_itts), 3)
                bitalker_fwd_biflow_itt_std = round(np.std(bitalker_fwd_biflow_itts), 3)
                bitalker_fwd_biflow_itt_var = round(np.var(bitalker_fwd_biflow_itts), 3)
                bitalker_fwd_biflow_itt_max = round(max(bitalker_fwd_biflow_itts), 3)
                bitalker_fwd_biflow_itt_min = round(min(bitalker_fwd_biflow_itts), 3)

            if len(bitalker_bwd_biflow_itts) == 0:
                bitalker_bwd_biflow_itt_total = bitalker_bwd_biflow_itt_max = bitalker_bwd_biflow_itt_min = 0
                bitalker_bwd_biflow_itt_mean = bitalker_bwd_biflow_itt_std = bitalker_bwd_biflow_itt_var = 0.0
            else:
                bitalker_bwd_biflow_itt_total = round(sum(bitalker_bwd_biflow_itts), 3)
                bitalker_bwd_biflow_itt_mean = round(np.mean(bitalker_bwd_biflow_itts), 3)
                bitalker_bwd_biflow_itt_std = round(np.std(bitalker_bwd_biflow_itts), 3)
                bitalker_bwd_biflow_itt_var = round(np.var(bitalker_bwd_biflow_itts), 3)
                bitalker_bwd_biflow_itt_max = round(max(bitalker_bwd_biflow_itts), 3)
                bitalker_bwd_biflow_itt_min = round(min(bitalker_bwd_biflow_itts), 3)

            # ===========
            # L4 Features
            # ===========
            if l4_protocol:
                # -------------------
                # L4 Unique Dst Ports
                # -------------------
                bitalker_any_biflow_unique_dst_ports = list(OrderedDict.fromkeys(bitalker_any_biflow_dst_ports))
                bitalker_fwd_biflow_unique_dst_ports = list(OrderedDict.fromkeys(bitalker_fwd_biflow_dst_ports))
                bitalker_bwd_biflow_unique_dst_ports = list(OrderedDict.fromkeys(bitalker_bwd_biflow_dst_ports))

                bitalker_any_biflow_n_unique_dst_ports = len(bitalker_any_biflow_unique_dst_ports)
                bitalker_fwd_biflow_n_unique_dst_ports = len(bitalker_fwd_biflow_unique_dst_ports)
                bitalker_bwd_biflow_n_unique_dst_ports = len(bitalker_bwd_biflow_unique_dst_ports)

                # rates use number of biflows since that number is also equal to total number of unique and non-unique ports
                bitalker_any_biflow_unique_dst_ports_rate = round(bitalker_any_biflow_n_unique_dst_ports/bitalker_any_n_biflows, 3)
                bitalker_fwd_biflow_unique_dst_ports_rate = round(bitalker_fwd_biflow_n_unique_dst_ports/bitalker_fwd_n_biflows, 3)\
                    if bitalker_fwd_n_biflows else 0
                bitalker_bwd_biflow_unique_dst_ports_rate = round(bitalker_bwd_biflow_n_unique_dst_ports/bitalker_bwd_n_biflows, 3)\
                    if bitalker_bwd_n_biflows else 0

                # -------------------
                # L4 Unique Src Ports
                # -------------------
                bitalker_any_biflow_unique_src_ports = list(OrderedDict.fromkeys(bitalker_any_biflow_src_ports))
                bitalker_fwd_biflow_unique_src_ports = list(OrderedDict.fromkeys(bitalker_fwd_biflow_src_ports))
                bitalker_bwd_biflow_unique_src_ports = list(OrderedDict.fromkeys(bitalker_bwd_biflow_src_ports))

                bitalker_any_biflow_n_unique_src_ports = len(bitalker_any_biflow_unique_src_ports)
                bitalker_fwd_biflow_n_unique_src_ports = len(bitalker_fwd_biflow_unique_src_ports)
                bitalker_bwd_biflow_n_unique_src_ports = len(bitalker_bwd_biflow_unique_src_ports)

                # rates use number of biflows since that number is also equal to total number of unique and non-unique ports
                bitalker_any_biflow_unique_src_ports_rate = round(bitalker_any_biflow_n_unique_src_ports/bitalker_any_n_biflows, 3)
                bitalker_fwd_biflow_unique_src_ports_rate = round(bitalker_fwd_biflow_n_unique_src_ports/bitalker_fwd_n_biflows, 3)\
                    if bitalker_fwd_n_biflows else 0
                bitalker_bwd_biflow_unique_src_ports_rate = round(bitalker_bwd_biflow_n_unique_src_ports/bitalker_bwd_n_biflows, 3)\
                    if bitalker_bwd_n_biflows else 0

                # ---------------
                # L4 Data Packets
                # ---------------
                bitalker_any_eth_ipv4_l4_biflow_n_data_packets_total = round(sum(bitalker_any_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_any_eth_ipv4_l4_biflow_n_data_packets_mean = round(np.mean(bitalker_any_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_any_eth_ipv4_l4_biflow_n_data_packets_std = round(np.std(bitalker_any_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_any_eth_ipv4_l4_biflow_n_data_packets_var = round(np.var(bitalker_any_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_any_eth_ipv4_l4_biflow_n_data_packets_max = round(max(bitalker_any_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_any_eth_ipv4_l4_biflow_n_data_packets_min = round(min(bitalker_any_eth_ipv4_l4_biflow_n_data_packets), 3)

                bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets_total = round(sum(bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets_mean = round(np.mean(bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets_std = round(np.std(bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets_var = round(np.var(bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets_max = round(max(bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets_min = round(min(bitalker_fwd_eth_ipv4_l4_biflow_n_data_packets), 3)

                if len(bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets) == 0:
                    bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_total = bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_max =\
                        bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_min = 0
                    bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_mean = bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_std =\
                        bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_var = 0.0
                else:
                    bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_total = round(sum(bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                    bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_mean = round(np.mean(bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                    bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_std = round(np.std(bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                    bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_var = round(np.var(bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                    bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_max = round(max(bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets), 3)
                    bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets_min = round(min(bitalker_bwd_eth_ipv4_l4_biflow_n_data_packets), 3)

                # =====================
                # TCP BiTalker Features
                # =====================
                if l4_protocol == "TCP":
                    # ---------------------------
                    # TCP BiFlow Initiation Types
                    # ---------------------------
                    bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_total = round(sum(bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_mean = round(np.mean(bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_std = round(np.std(bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_var = round(np.var(bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_max = round(max(bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_min = round(min(bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)

                    # ---------------------------
                    # TCP BiFlow Connection Types
                    # ---------------------------
                    bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_total = round(sum(bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_mean = round(np.mean(bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_std = round(np.std(bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_var = round(np.var(bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_max = round(max(bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_min = round(min(bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)

                    bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_total = round(sum(bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_mean = round(np.mean(bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_std = round(np.std(bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_var = round(np.var(bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_max = round(max(bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_min = round(min(bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)

                    bitalker_eth_ipv4_tcp_biflow_connections_rejected_total = round(sum(bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_rejected_mean = round(np.mean(bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_rejected_std = round(np.std(bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_rejected_var = round(np.var(bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_rejected_max = round(max(bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_rejected_min = round(min(bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)

                    bitalker_eth_ipv4_tcp_biflow_connections_dropped_total = round(sum(bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_dropped_mean = round(np.mean(bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_dropped_std = round(np.std(bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_dropped_var = round(np.var(bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_dropped_max = round(max(bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    bitalker_eth_ipv4_tcp_biflow_connections_dropped_min = round(min(bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)

                    # ----------------------------
                    # TCP BiFlow Termination Types
                    # ----------------------------
                    bitalker_eth_ipv4_tcp_biflow_null_terminations_total = round(sum(bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_null_terminations_mean = round(np.mean(bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_null_terminations_std = round(np.std(bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_null_terminations_var = round(np.var(bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_null_terminations_max = round(max(bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_null_terminations_min = round(min(bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)

                    bitalker_eth_ipv4_tcp_biflow_graceful_terminations_total = round(sum(bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_graceful_terminations_mean = round(np.mean(bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_graceful_terminations_std = round(np.std(bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_graceful_terminations_var = round(np.var(bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_graceful_terminations_max = round(max(bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_graceful_terminations_min = round(min(bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)

                    bitalker_eth_ipv4_tcp_biflow_abort_terminations_total = round(sum(bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_abort_terminations_mean = round(np.mean(bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_abort_terminations_std = round(np.std(bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_abort_terminations_var = round(np.var(bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_abort_terminations_max = round(max(bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    bitalker_eth_ipv4_tcp_biflow_abort_terminations_min = round(min(bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)

            # ==========================
            # Conceptual Features - More
            # ==========================
            # --------------------------------
            # BiFlow & Byte Frequency Features
            # --------------------------------
            if bitalker_any_duration == 0:
                bitalker_any_biflows_per_sec = bitalker_fwd_biflows_per_sec = bitalker_bwd_biflows_per_sec = 0.0
                bitalker_any_biflow_bytes_per_sec = bitalker_fwd_biflow_bytes_per_sec = bitalker_bwd_biflow_bytes_per_sec = 0.0
            else:
                bitalker_any_biflows_per_sec = round(bitalker_any_n_biflows/bitalker_any_duration, 3)
                bitalker_fwd_biflows_per_sec = round(bitalker_fwd_n_biflows/bitalker_any_duration, 3)
                bitalker_bwd_biflows_per_sec = round(bitalker_bwd_n_biflows/bitalker_any_duration, 3)
                bitalker_any_biflow_bytes_per_sec = round(bitalker_any_biflow_eth_ipv4_data_lens_total/bitalker_any_duration, 3)
                bitalker_fwd_biflow_bytes_per_sec = round(bitalker_fwd_biflow_eth_ipv4_data_lens_total/bitalker_any_duration, 3)
                bitalker_bwd_biflow_bytes_per_sec = round(bitalker_bwd_biflow_eth_ipv4_data_lens_total/bitalker_any_duration, 3)

            # ===============
            # WRAP-UP RESULTS
            # ===============
            bitalker_local_vars = locals()
            bitalker_genes = [str(bitalker_local_vars[var_name]) for var_name in ipv4_all_bitalker_genes_header_list]
            
            yield bitalker_genes

    bitalker_genes_generator = calculate_l3_l4_bitalker_genes(genes_dir, bitalkers, bitalker_ids, l4_protocol=l4_protocol)

    return list(bitalker_genes_generator)
    