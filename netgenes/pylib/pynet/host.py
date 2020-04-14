# 3rdParty
try:
    import numpy as np
except ImportError:
    raise ImportError("You need to do 'pip3 install -r requirements.txt' to be able to use this program.")

# Ours
from pylib.pynet.netobject_utils import *
from pylib.pyaux.utils import datetime_to_unixtime, unixtime_to_datetime

def build_bihosts(bitalker_genes_generator_lst, bitalker_ids):
    """Build BiHosts"""
    bihosts = dict()
    bihost_ids = list()

    for bitalker_genes in bitalker_genes_generator_lst:
        bihost_fwd_id = tuple(str_to_iterator(bitalker_genes[1]))
        bihost_bwd_id = tuple(str_to_iterator(bitalker_genes[2]))

        try:
            bihosts[bihost_fwd_id].append([bitalker_genes, "fwd"])
        except KeyError:
            bihost_ids.append(bihost_fwd_id)
            bihosts[bihost_fwd_id] = [[bitalker_genes, "fwd"], ]

        try:
            bihosts[bihost_bwd_id].append([bitalker_genes, "bwd"])
        except KeyError:
            bihost_ids.append(bihost_bwd_id)
            bihosts[bihost_bwd_id] = [[bitalker_genes, "bwd"], ]

    return bihosts, bihost_ids

def get_l3_l4_bihost_gene_generators(genes_dir, bihosts, bihost_ids, l4_protocol=None):
    """Return L3-L4 bihost gene generators"""
    def calculate_l3_l4_bihost_genes(genes_dir, bihosts, bihost_ids, l4_protocol=None):
        """Calculate and yield L3-L4 bihost genes"""
        time_scale_factor = 1000.0
        # =================
        # IPv4 GENES HEADER
        # =================
        ipv4_bihost_genes_header_list = get_network_object_header(genes_dir, "bihost", "ipv4")
        # ===============
        # L4 GENES HEADER
        # ===============
        ipv4_l4_bihost_genes_header_list = get_network_object_header(genes_dir, "bihost", "ipv4-l4")
        # ================
        # TCP GENES HEADER
        # ================
        ipv4_tcp_bihost_genes_header_list = get_network_object_header(genes_dir, "bihost", "ipv4-tcp")

        # IPv4 Header
        ipv4_all_bihost_genes_header_list = ipv4_bihost_genes_header_list
        if l4_protocol:
            # IPv4-L4 Header
            ipv4_all_bihost_genes_header_list += ipv4_l4_bihost_genes_header_list
            if l4_protocol == "UDP":
                pass
            elif l4_protocol == "TCP":
                ipv4_all_bihost_genes_header_list += ipv4_tcp_bihost_genes_header_list

        for bihost_id in bihost_ids:
            # ======================
            # Additional Information
            # ======================
            curr_bihost = bihosts[bihost_id]

            first_bitalker = curr_bihost[0][0]
            last_bitalker = curr_bihost[-1][0]
            bihost_any_first_bitalker_initiation_time = first_bitalker[3]
            bihost_any_last_bitalker_termination_time = last_bitalker[4]
            bihost_any_first_bitalker_initiation_time = datetime_to_unixtime(bihost_any_first_bitalker_initiation_time)
            bihost_any_last_bitalker_termination_time = datetime_to_unixtime(bihost_any_last_bitalker_termination_time)

            # =========================
            # PREPARE DATA STRUCTURES |
            # =========================
            # ============================
            # BiTalker Conceptual Features
            # ============================
            # ------------------------
            # BiTalker Number Features
            # ------------------------
            bihost_any_n_bitalkers = len(curr_bihost)
            bihost_fwd_n_bitalkers = 0
            bihost_bwd_n_bitalkers = 0

            # -------------
            # Time Features
            # -------------
            bihost_any_duration = round((bihost_any_last_bitalker_termination_time - bihost_any_first_bitalker_initiation_time)/time_scale_factor, 3)

            # ---------------------------
            # BiTalker Frequency Features
            # ---------------------------
            bihost_any_bitalkers_per_sec = 0 if bihost_any_duration == 0 else round(bihost_any_n_bitalkers/bihost_any_duration, 3)

            # ---------------------------------
            # Additional Information - Reformat
            # ---------------------------------
            # Convert bihost_id to string
            bihost_id = iterator_to_str(bihost_id)
            bihost_any_first_bitalker_initiation_time = unixtime_to_datetime(bihost_any_first_bitalker_initiation_time)
            bihost_any_last_bitalker_termination_time = unixtime_to_datetime(bihost_any_last_bitalker_termination_time)

            # =============================
            # BiTalker Statistical Features
            # =============================
            # ------------------
            # IPv4 Data Lengthes
            # ------------------
            bihost_any_bitalker_any_biflow_eth_ipv4_data_lens = list()
            bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens = list()
            bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens = list()

            # --------------------
            # L4 Destination Ports
            # --------------------
            bihost_any_bitalker_any_biflow_n_unique_dst_ports = list()
            bihost_fwd_bitalker_any_biflow_n_unique_dst_ports = list()
            bihost_bwd_bitalker_any_biflow_n_unique_dst_ports = list()

            # ---------------
            # L4 Source Ports
            # ---------------
            bihost_any_bitalker_any_biflow_n_unique_src_ports = list()
            bihost_fwd_bitalker_any_biflow_n_unique_src_ports = list()
            bihost_bwd_bitalker_any_biflow_n_unique_src_ports = list()

            # ---------------------
            # TCP Innitiation Types
            # ---------------------
            bihost_any_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations = list()
            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations = list()
            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations = list()

            # --------------------
            # TCP Connection Types
            # --------------------
            bihost_any_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established = list()
            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established = list()
            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established = list()

            bihost_any_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established = list()
            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established = list()
            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established = list()

            bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_rejected = list()
            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected = list()
            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected = list()

            bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_dropped = list()
            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped = list()
            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped = list()

            # ---------------------
            # TCP Termination Types
            # ---------------------
            bihost_any_bitalker_eth_ipv4_tcp_biflow_null_terminations = list()
            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations = list()
            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations = list()

            bihost_any_bitalker_eth_ipv4_tcp_biflow_graceful_terminations = list()
            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations = list()
            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations = list()

            bihost_any_bitalker_eth_ipv4_tcp_biflow_abort_terminations = list()
            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations = list()
            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations = list()

            # ==========================
            # POPULATE DATA STRUCTURES |
            # ==========================
            curr_bitalker_index = 0
            while curr_bitalker_index < bihost_any_n_bitalkers:
                # ===================
                # BiTalker Concepts |
                # ===================
                if curr_bitalker_index >= 1:
                    previous_bitalker = curr_bihost[curr_bitalker_index-1][0]
                    previous_bitalker_bitalker_id = previous_bitalker[1]
                    previous_bitalker_initiation_timestamp = previous_bitalker[3]
                    previous_bitalker_termination_timestamp = previous_bitalker[4]

                curr_bitalker = curr_bihost[curr_bitalker_index][0]
                curr_bitalker_direction = curr_bihost[curr_bitalker_index][1]
                curr_bitalker_id_str = curr_bitalker[0]
                curr_bitalker_id = str_to_iterator(curr_bitalker_id_str)
                curr_bitalker_bitalker_id_str = curr_bitalker[1]
                curr_bitalker_initiation_timestamp = curr_bitalker[3]
                curr_bitalker_termination_timestamp = curr_bitalker[4]

                # ------------------
                # IPv4 Data Lengthes
                # ------------------
                curr_bitalker_any_biflow_eth_ipv4_data_lens_total = int(curr_bitalker[15])
                bihost_any_bitalker_any_biflow_eth_ipv4_data_lens.append(curr_bitalker_any_biflow_eth_ipv4_data_lens_total)

                if curr_bitalker_direction == "fwd":
                    # Statistical
                    bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens.append(curr_bitalker_any_biflow_eth_ipv4_data_lens_total)

                    # Conceptual
                    bihost_fwd_n_bitalkers += 1
                else:
                    # Statistical
                    bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens.append(curr_bitalker_any_biflow_eth_ipv4_data_lens_total)

                    # Conceptual
                    bihost_bwd_n_bitalkers += 1

                # ===========
                # L4 Concepts
                # ===========
                if l4_protocol:
                    # --------------------
                    # L4 Destination Ports
                    # --------------------
                    curr_bitalker_any_biflow_n_unique_dst_ports = int(curr_bitalker[105])
                    bihost_any_bitalker_any_biflow_n_unique_dst_ports.append(curr_bitalker_any_biflow_n_unique_dst_ports)
                    if curr_bitalker_direction == "fwd":
                        bihost_fwd_bitalker_any_biflow_n_unique_dst_ports.append(curr_bitalker_any_biflow_n_unique_dst_ports)
                    else:
                        bihost_bwd_bitalker_any_biflow_n_unique_dst_ports.append(curr_bitalker_any_biflow_n_unique_dst_ports)

                    # ---------------
                    # L4 Source Ports
                    # ---------------
                    curr_bitalker_any_biflow_n_unique_src_ports = int(curr_bitalker[111])
                    bihost_any_bitalker_any_biflow_n_unique_src_ports.append(curr_bitalker_any_biflow_n_unique_src_ports)
                    if curr_bitalker_direction == "fwd":
                        bihost_fwd_bitalker_any_biflow_n_unique_src_ports.append(curr_bitalker_any_biflow_n_unique_src_ports)
                    else:
                        bihost_bwd_bitalker_any_biflow_n_unique_src_ports.append(curr_bitalker_any_biflow_n_unique_src_ports)

                    # ============
                    # TCP Concepts
                    # ============
                    if l4_protocol == "TCP":
                        # --------------------
                        # TCP Initiation Types
                        # --------------------
                        curr_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations = int(curr_bitalker[135])
                        bihost_any_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations.append(curr_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations)

                        # --------------------
                        # TCP Connection Types
                        # --------------------
                        curr_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established = int(curr_bitalker[141])
                        bihost_any_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established.append(curr_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established)

                        curr_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established = int(curr_bitalker[147])
                        bihost_any_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established.append(curr_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established)

                        curr_bitalker_eth_ipv4_tcp_biflow_connections_rejected = int(curr_bitalker[153])
                        bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_rejected.append(curr_bitalker_eth_ipv4_tcp_biflow_connections_rejected)

                        curr_bitalker_eth_ipv4_tcp_biflow_connections_dropped = int(curr_bitalker[159])
                        bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_dropped.append(curr_bitalker_eth_ipv4_tcp_biflow_connections_dropped)

                        # ---------------------
                        # TCP Termination Types
                        # ---------------------
                        curr_bitalker_eth_ipv4_tcp_biflow_null_terminations = int(curr_bitalker[165])
                        bihost_any_bitalker_eth_ipv4_tcp_biflow_null_terminations.append(curr_bitalker_eth_ipv4_tcp_biflow_null_terminations)

                        curr_bitalker_eth_ipv4_tcp_biflow_graceful_terminations = int(curr_bitalker[171])
                        bihost_any_bitalker_eth_ipv4_tcp_biflow_graceful_terminations.append(curr_bitalker_eth_ipv4_tcp_biflow_graceful_terminations)

                        curr_bitalker_eth_ipv4_tcp_biflow_abort_terminations = int(curr_bitalker[177])
                        bihost_any_bitalker_eth_ipv4_tcp_biflow_abort_terminations.append(curr_bitalker_eth_ipv4_tcp_biflow_abort_terminations)

                        if curr_bitalker_direction == "fwd":
                            # init
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations.append(curr_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations)
                            # connect
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established.append(curr_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established)
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established.append(curr_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established)
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected.append(curr_bitalker_eth_ipv4_tcp_biflow_connections_rejected)
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped.append(curr_bitalker_eth_ipv4_tcp_biflow_connections_dropped)

                            # end
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations.append(curr_bitalker_eth_ipv4_tcp_biflow_null_terminations)
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations.append(curr_bitalker_eth_ipv4_tcp_biflow_graceful_terminations)
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations.append(curr_bitalker_eth_ipv4_tcp_biflow_abort_terminations)
                        else:
                            # init
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations.append(curr_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations)
                            # connect
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established.append(curr_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established)
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established.append(curr_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established)
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected.append(curr_bitalker_eth_ipv4_tcp_biflow_connections_rejected)
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped.append(curr_bitalker_eth_ipv4_tcp_biflow_connections_dropped)
                            # end
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations.append(curr_bitalker_eth_ipv4_tcp_biflow_null_terminations)
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations.append(curr_bitalker_eth_ipv4_tcp_biflow_graceful_terminations)
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations.append(curr_bitalker_eth_ipv4_tcp_biflow_abort_terminations)
                # iterate the bitalkers inside a bihost
                curr_bitalker_index += 1

            # =============================
            # Statistical Features - Calc |
            # =============================
            # ------------------
            # IPv4 Data Lengthes
            # ------------------
            bihost_any_bitalker_any_biflow_eth_ipv4_data_lens_total = round(sum(bihost_any_bitalker_any_biflow_eth_ipv4_data_lens), 3)
            bihost_any_bitalker_any_biflow_eth_ipv4_data_lens_mean = round(np.mean(bihost_any_bitalker_any_biflow_eth_ipv4_data_lens), 3)
            bihost_any_bitalker_any_biflow_eth_ipv4_data_lens_std = round(np.std(bihost_any_bitalker_any_biflow_eth_ipv4_data_lens), 3)
            bihost_any_bitalker_any_biflow_eth_ipv4_data_lens_var = round(np.var(bihost_any_bitalker_any_biflow_eth_ipv4_data_lens), 3)
            bihost_any_bitalker_any_biflow_eth_ipv4_data_lens_max = round(max(bihost_any_bitalker_any_biflow_eth_ipv4_data_lens), 3)
            bihost_any_bitalker_any_biflow_eth_ipv4_data_lens_min = round(min(bihost_any_bitalker_any_biflow_eth_ipv4_data_lens), 3)

            if len(bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens) == 0:
                bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens_total = bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens_max = \
                    bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens_min = 0
                bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens_mean = bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens_std = \
                    bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens_var = 0.0
            else:
                bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens_total = round(sum(bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens), 3)
                bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens_mean = round(np.mean(bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens), 3)
                bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens_std = round(np.std(bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens), 3)
                bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens_var = round(np.var(bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens), 3)
                bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens_max = round(max(bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens), 3)
                bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens_min = round(min(bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens), 3)

            if len(bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens) == 0:
                bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens_total = bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens_max = \
                    bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens_min = 0
                bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens_mean = bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens_std = \
                    bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens_var = 0.0
            else:
                bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens_total = round(sum(bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens), 3)
                bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens_mean = round(np.mean(bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens), 3)
                bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens_std = round(np.std(bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens), 3)
                bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens_var = round(np.var(bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens), 3)
                bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens_max = round(max(bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens), 3)
                bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens_min = round(min(bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens), 3)

            # ---------------------------
            # BiTalker Frequency Features
            # ---------------------------
            bihost_fwd_bitalkers_per_sec = 0 if bihost_any_duration == 0 else round(bihost_fwd_n_bitalkers/bihost_any_duration, 3)
            bihost_bwd_bitalkers_per_sec = 0 if bihost_any_duration == 0 else round(bihost_bwd_n_bitalkers/bihost_any_duration, 3)

            # ===========
            # L4 Concepts
            # ===========
            if l4_protocol:
                # --------------------
                # L4 Destination Ports
                # --------------------
                bihost_any_bitalker_any_biflow_n_unique_dst_ports_total = round(sum(bihost_any_bitalker_any_biflow_n_unique_dst_ports), 3)
                bihost_any_bitalker_any_biflow_n_unique_dst_ports_mean = round(np.mean(bihost_any_bitalker_any_biflow_n_unique_dst_ports), 3)
                bihost_any_bitalker_any_biflow_n_unique_dst_ports_std = round(np.std(bihost_any_bitalker_any_biflow_n_unique_dst_ports), 3)
                bihost_any_bitalker_any_biflow_n_unique_dst_ports_var = round(np.var(bihost_any_bitalker_any_biflow_n_unique_dst_ports), 3)
                bihost_any_bitalker_any_biflow_n_unique_dst_ports_max = round(max(bihost_any_bitalker_any_biflow_n_unique_dst_ports), 3)
                bihost_any_bitalker_any_biflow_n_unique_dst_ports_min = round(min(bihost_any_bitalker_any_biflow_n_unique_dst_ports), 3)

                if len(bihost_fwd_bitalker_any_biflow_n_unique_dst_ports) == 0:
                    bihost_fwd_bitalker_any_biflow_n_unique_dst_ports_total = bihost_fwd_bitalker_any_biflow_n_unique_dst_ports_max = \
                        bihost_fwd_bitalker_any_biflow_n_unique_dst_ports_min = 0
                    bihost_fwd_bitalker_any_biflow_n_unique_dst_ports_mean = bihost_fwd_bitalker_any_biflow_n_unique_dst_ports_std = \
                        bihost_fwd_bitalker_any_biflow_n_unique_dst_ports_var = 0.0
                else:
                    bihost_fwd_bitalker_any_biflow_n_unique_dst_ports_total = round(sum(bihost_fwd_bitalker_any_biflow_n_unique_dst_ports), 3)
                    bihost_fwd_bitalker_any_biflow_n_unique_dst_ports_mean = round(np.mean(bihost_fwd_bitalker_any_biflow_n_unique_dst_ports), 3)
                    bihost_fwd_bitalker_any_biflow_n_unique_dst_ports_std = round(np.std(bihost_fwd_bitalker_any_biflow_n_unique_dst_ports), 3)
                    bihost_fwd_bitalker_any_biflow_n_unique_dst_ports_var = round(np.var(bihost_fwd_bitalker_any_biflow_n_unique_dst_ports), 3)
                    bihost_fwd_bitalker_any_biflow_n_unique_dst_ports_max = round(max(bihost_fwd_bitalker_any_biflow_n_unique_dst_ports), 3)
                    bihost_fwd_bitalker_any_biflow_n_unique_dst_ports_min = round(min(bihost_fwd_bitalker_any_biflow_n_unique_dst_ports), 3)

                if len(bihost_bwd_bitalker_any_biflow_n_unique_dst_ports) == 0:
                    bihost_bwd_bitalker_any_biflow_n_unique_dst_ports_total = bihost_bwd_bitalker_any_biflow_n_unique_dst_ports_max = \
                        bihost_bwd_bitalker_any_biflow_n_unique_dst_ports_min = 0
                    bihost_bwd_bitalker_any_biflow_n_unique_dst_ports_mean = bihost_bwd_bitalker_any_biflow_n_unique_dst_ports_std = \
                        bihost_bwd_bitalker_any_biflow_n_unique_dst_ports_var = 0.0
                else:
                    bihost_bwd_bitalker_any_biflow_n_unique_dst_ports_total = round(sum(bihost_bwd_bitalker_any_biflow_n_unique_dst_ports), 3)
                    bihost_bwd_bitalker_any_biflow_n_unique_dst_ports_mean = round(np.mean(bihost_bwd_bitalker_any_biflow_n_unique_dst_ports), 3)
                    bihost_bwd_bitalker_any_biflow_n_unique_dst_ports_std = round(np.std(bihost_bwd_bitalker_any_biflow_n_unique_dst_ports), 3)
                    bihost_bwd_bitalker_any_biflow_n_unique_dst_ports_var = round(np.var(bihost_bwd_bitalker_any_biflow_n_unique_dst_ports), 3)
                    bihost_bwd_bitalker_any_biflow_n_unique_dst_ports_max = round(max(bihost_bwd_bitalker_any_biflow_n_unique_dst_ports), 3)
                    bihost_bwd_bitalker_any_biflow_n_unique_dst_ports_min = round(min(bihost_bwd_bitalker_any_biflow_n_unique_dst_ports), 3)

                # ---------------
                # L4 Source Ports
                # ---------------
                bihost_any_bitalker_any_biflow_n_unique_src_ports_total = round(sum(bihost_any_bitalker_any_biflow_n_unique_src_ports), 3)
                bihost_any_bitalker_any_biflow_n_unique_src_ports_mean = round(np.mean(bihost_any_bitalker_any_biflow_n_unique_src_ports), 3)
                bihost_any_bitalker_any_biflow_n_unique_src_ports_std = round(np.std(bihost_any_bitalker_any_biflow_n_unique_src_ports), 3)
                bihost_any_bitalker_any_biflow_n_unique_src_ports_var = round(np.var(bihost_any_bitalker_any_biflow_n_unique_src_ports), 3)
                bihost_any_bitalker_any_biflow_n_unique_src_ports_max = round(max(bihost_any_bitalker_any_biflow_n_unique_src_ports), 3)
                bihost_any_bitalker_any_biflow_n_unique_src_ports_min = round(min(bihost_any_bitalker_any_biflow_n_unique_src_ports), 3)

                if len(bihost_fwd_bitalker_any_biflow_n_unique_src_ports) == 0:
                    bihost_fwd_bitalker_any_biflow_n_unique_src_ports_total = bihost_fwd_bitalker_any_biflow_n_unique_src_ports_max = \
                        bihost_fwd_bitalker_any_biflow_n_unique_src_ports_min = 0
                    bihost_fwd_bitalker_any_biflow_n_unique_src_ports_mean = bihost_fwd_bitalker_any_biflow_n_unique_src_ports_std = \
                        bihost_fwd_bitalker_any_biflow_n_unique_src_ports_var = 0.0
                else:
                    bihost_fwd_bitalker_any_biflow_n_unique_src_ports_total = round(sum(bihost_fwd_bitalker_any_biflow_n_unique_src_ports), 3)
                    bihost_fwd_bitalker_any_biflow_n_unique_src_ports_mean = round(np.mean(bihost_fwd_bitalker_any_biflow_n_unique_src_ports), 3)
                    bihost_fwd_bitalker_any_biflow_n_unique_src_ports_std = round(np.std(bihost_fwd_bitalker_any_biflow_n_unique_src_ports), 3)
                    bihost_fwd_bitalker_any_biflow_n_unique_src_ports_var = round(np.var(bihost_fwd_bitalker_any_biflow_n_unique_src_ports), 3)
                    bihost_fwd_bitalker_any_biflow_n_unique_src_ports_max = round(max(bihost_fwd_bitalker_any_biflow_n_unique_src_ports), 3)
                    bihost_fwd_bitalker_any_biflow_n_unique_src_ports_min = round(min(bihost_fwd_bitalker_any_biflow_n_unique_src_ports), 3)

                if len(bihost_bwd_bitalker_any_biflow_n_unique_src_ports) == 0:
                    bihost_bwd_bitalker_any_biflow_n_unique_src_ports_total = bihost_bwd_bitalker_any_biflow_n_unique_src_ports_max = \
                        bihost_bwd_bitalker_any_biflow_n_unique_src_ports_min = 0
                    bihost_bwd_bitalker_any_biflow_n_unique_src_ports_mean = bihost_bwd_bitalker_any_biflow_n_unique_src_ports_std = \
                        bihost_bwd_bitalker_any_biflow_n_unique_src_ports_var = 0.0
                else:
                    bihost_bwd_bitalker_any_biflow_n_unique_src_ports_total = round(sum(bihost_bwd_bitalker_any_biflow_n_unique_src_ports), 3)
                    bihost_bwd_bitalker_any_biflow_n_unique_src_ports_mean = round(np.mean(bihost_bwd_bitalker_any_biflow_n_unique_src_ports), 3)
                    bihost_bwd_bitalker_any_biflow_n_unique_src_ports_std = round(np.std(bihost_bwd_bitalker_any_biflow_n_unique_src_ports), 3)
                    bihost_bwd_bitalker_any_biflow_n_unique_src_ports_var = round(np.var(bihost_bwd_bitalker_any_biflow_n_unique_src_ports), 3)
                    bihost_bwd_bitalker_any_biflow_n_unique_src_ports_max = round(max(bihost_bwd_bitalker_any_biflow_n_unique_src_ports), 3)
                    bihost_bwd_bitalker_any_biflow_n_unique_src_ports_min = round(min(bihost_bwd_bitalker_any_biflow_n_unique_src_ports), 3)

                # ============
                # TCP Concepts
                # ============
                if l4_protocol == "TCP":
                    # ------------------------------
                    # TCP BiTalker Innitiation Types
                    # ------------------------------
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_total = round(sum(bihost_any_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_mean = round(np.mean(bihost_any_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_std = round(np.std(bihost_any_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_var = round(np.var(bihost_any_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_max = round(max(bihost_any_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_min = round(min(bihost_any_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)

                    if len(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations) == 0:
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_total = bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_max = \
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_min = 0
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_mean = bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_std = \
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_var = 0.0
                    else:
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_total = round(sum(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_mean = round(np.mean(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_std = round(np.std(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_var = round(np.var(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_max = round(max(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_min = round(min(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    
                    if len(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations) == 0:
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_total = bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_max = \
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_min = 0
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_mean = bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_std = \
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_var = 0.0
                    else:
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_total = round(sum(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_mean = round(np.mean(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_std = round(np.std(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_var = round(np.var(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_max = round(max(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_min = round(min(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)

                    # -----------------------------
                    # TCP BiTalker Connection Types
                    # -----------------------------
                    # FULL DUPLEX
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_total = round(sum(bihost_any_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_mean = round(np.mean(bihost_any_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_std = round(np.std(bihost_any_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_var = round(np.var(bihost_any_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_max = round(max(bihost_any_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_min = round(min(bihost_any_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)

                    if len(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established) == 0:
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_total = bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_max = \
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_min = 0
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_mean = bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_std = \
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_var = 0.0
                    else:
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_total = round(sum(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_mean = round(np.mean(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_std = round(np.std(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_var = round(np.var(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_max = round(max(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_min = round(min(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)

                    if len(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established) == 0:
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_total = bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_max = \
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_min = 0
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_mean = bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_std = \
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_var = 0.0
                    else:
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_total = round(sum(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_mean = round(np.mean(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_std = round(np.std(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_var = round(np.var(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_max = round(max(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_min = round(min(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)

                    # HALF DUPLEX
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_total = round(sum(bihost_any_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_mean = round(np.mean(bihost_any_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_std = round(np.std(bihost_any_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_var = round(np.var(bihost_any_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_max = round(max(bihost_any_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_min = round(min(bihost_any_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)

                    if len(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established) == 0:
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_total = bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_max = \
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_min = 0
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_mean = bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_std = \
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_var = 0.0
                    else:
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_total = round(sum(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_mean = round(np.mean(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_std = round(np.std(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_var = round(np.var(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_max = round(max(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_min = round(min(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)

                    if len(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established) == 0:
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_total = bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_max = \
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_min = 0
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_mean = bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_std = \
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_var = 0.0
                    else:
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_total = round(sum(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_mean = round(np.mean(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_std = round(np.std(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_var = round(np.var(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_max = round(max(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_min = round(min(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)

                    # CONNECTION REJECTED
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_rejected_total = round(sum(bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_rejected_mean = round(np.mean(bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_rejected_std = round(np.std(bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_rejected_var = round(np.var(bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_rejected_max = round(max(bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_rejected_min = round(min(bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)

                    if len(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected) == 0:
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_total = bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_max = \
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_min = 0
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_mean = bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_std = \
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_var = 0.0
                    else:
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_total = round(sum(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_mean = round(np.mean(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_std = round(np.std(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_var = round(np.var(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_max = round(max(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_min = round(min(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)

                    if len(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected) == 0:
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_total = bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_max = \
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_min = 0
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_mean = bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_std = \
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_var = 0.0
                    else:
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_total = round(sum(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_mean = round(np.mean(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_std = round(np.std(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_var = round(np.var(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_max = round(max(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected_min = round(min(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)

                    # CONNECTION DROPPED
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_dropped_total = round(sum(bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_dropped_mean = round(np.mean(bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_dropped_std = round(np.std(bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_dropped_var = round(np.var(bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_dropped_max = round(max(bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_dropped_min = round(min(bihost_any_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)

                    if len(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped) == 0:
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_total = bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_max = \
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_min = 0
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_mean = bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_std = \
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_var = 0.0
                    else:
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_total = round(sum(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_mean = round(np.mean(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_std = round(np.std(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_var = round(np.var(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_max = round(max(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_min = round(min(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)

                    if len(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped) == 0:
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_total = bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_max = \
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_min = 0
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_mean = bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_std = \
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_var = 0.0
                    else:
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_total = round(sum(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_mean = round(np.mean(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_std = round(np.std(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_var = round(np.var(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_max = round(max(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped_min = round(min(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)

                    # ------------------------------
                    # TCP BiTalker Termination Types
                    # ------------------------------
                    # NULL TERMINATION
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_null_terminations_total = round(sum(bihost_any_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_null_terminations_mean = round(np.mean(bihost_any_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_null_terminations_std = round(np.std(bihost_any_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_null_terminations_var = round(np.var(bihost_any_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_null_terminations_max = round(max(bihost_any_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_null_terminations_min = round(min(bihost_any_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)

                    if len(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations) == 0:
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_total = bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_max = \
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_min = 0
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_mean = bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_std = \
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_var = 0.0
                    else:
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_total = round(sum(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_mean = round(np.mean(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_std = round(np.std(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_var = round(np.var(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_max = round(max(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_min = round(min(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)

                    if len(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations) == 0:
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_total = bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_max = \
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_min = 0
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_mean = bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_std = \
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_var = 0.0
                    else:
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_total = round(sum(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_mean = round(np.mean(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_std = round(np.std(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_var = round(np.var(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_max = round(max(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations_min = round(min(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)

                    # GRACEFUL TERMINATION
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_total = round(sum(bihost_any_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_mean = round(np.mean(bihost_any_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_std = round(np.std(bihost_any_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_var = round(np.var(bihost_any_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_max = round(max(bihost_any_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_min = round(min(bihost_any_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)

                    if len(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations) == 0:
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_total = bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_max = \
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_min = 0
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_mean = bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_std = \
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_var = 0.0
                    else:
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_total = round(sum(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_mean = round(np.mean(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_std = round(np.std(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_var = round(np.var(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_max = round(max(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_min = round(min(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)

                    if len(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations) == 0:
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_total = bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_max = \
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_min = 0
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_mean = bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_std = \
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_var = 0.0
                    else:
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_total = round(sum(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_mean = round(np.mean(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_std = round(np.std(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_var = round(np.var(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_max = round(max(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_min = round(min(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)

                    # ABORT TERMINATION
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_abort_terminations_total = round(sum(bihost_any_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_abort_terminations_mean = round(np.mean(bihost_any_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_abort_terminations_std = round(np.std(bihost_any_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_abort_terminations_var = round(np.var(bihost_any_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_abort_terminations_max = round(max(bihost_any_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    bihost_any_bitalker_eth_ipv4_tcp_biflow_abort_terminations_min = round(min(bihost_any_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)

                    if len(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations) == 0:
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_total = bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_max = \
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_min = 0
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_mean = bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_std = \
                            bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_var = 0.0
                    else:
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_total = round(sum(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_mean = round(np.mean(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_std = round(np.std(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_var = round(np.var(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_max = round(max(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                        bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_min = round(min(bihost_fwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)

                    if len(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations) == 0:
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_total = bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_max = \
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_min = 0
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_mean = bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_std = \
                            bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_var = 0.0
                    else:
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_total = round(sum(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_mean = round(np.mean(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_std = round(np.std(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_var = round(np.var(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_max = round(max(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                        bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations_min = round(min(bihost_bwd_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
            # ==========================
            # Conceptual Features - More
            # ==========================
            # --------------------------------
            # BiTalker Byte Frequency Features
            # --------------------------------
            bihost_any_bitalker_bytes_per_sec = 0 if bihost_any_duration == 0 else\
                round(bihost_any_bitalker_any_biflow_eth_ipv4_data_lens_total/bihost_any_duration, 3)
            bihost_fwd_bitalker_bytes_per_sec = 0 if bihost_any_duration == 0 else\
                round(bihost_fwd_bitalker_any_biflow_eth_ipv4_data_lens_total/bihost_any_duration, 3)
            bihost_bwd_bitalker_bytes_per_sec = 0 if bihost_any_duration == 0 else\
                round(bihost_bwd_bitalker_any_biflow_eth_ipv4_data_lens_total/bihost_any_duration, 3)
            # ===============
            # WRAP-UP RESULTS
            # ===============
            bihost_local_vars = locals()
            bihost_genes = [str(bihost_local_vars[var_name]) for var_name in ipv4_all_bihost_genes_header_list]

            yield bihost_genes

    bihost_genes_generator = calculate_l3_l4_bihost_genes(genes_dir, bihosts, bihost_ids, l4_protocol=l4_protocol)

    return list(bihost_genes_generator)