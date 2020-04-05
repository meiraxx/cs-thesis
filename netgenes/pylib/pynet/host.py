# 3rdParty
try:
    import numpy as np
except ImportError:
    raise ImportError("You need to do 'pip3 install -r requirements.txt' to be able to use this program.")

# Ours
from pylib.pynet.netobject_utils import *
from pylib.pyaux.utils import datetime_to_unixtime, unixtime_to_datetime

def build_unihosts(bitalker_genes_generator_lst, bitalker_ids):
    """Build UniHosts"""
    # Note: unihost_ids in both directions are the same as bihost_ids (however, not contemplated)
    unihosts = dict()
    unihost_ids = list()

    for bitalker_genes in bitalker_genes_generator_lst:
        bitalker_id_str = bitalker_genes[0]
        bitalker_id = str_to_iterator(bitalker_id_str)
        fwd_unihost_id = bitalker_id_to_unihost_id(bitalker_id)
        bwd_unihost_id = bitalker_id_to_unihost_id(bitalker_id, _reversed=True)

        try:
            unihosts[fwd_unihost_id].append(bitalker_genes)
        except KeyError:
            unihost_ids.append(fwd_unihost_id)
            unihosts[fwd_unihost_id] = [bitalker_genes]

    return unihosts, unihost_ids

def get_l3_l4_unihost_gene_generators(genes_dir, unihosts, unihost_ids, l4_protocol=None):
    """Return L3-L4 unihost gene generators"""
    def calculate_l3_l4_unihost_genes(genes_dir, unihosts, unihost_ids, l4_protocol=None):
        """Calculate and yield L3-L4 unihost genes"""
        time_scale_factor = 1000.0
        # =================
        # IPv4 GENES HEADER
        # =================
        ipv4_unihost_genes_header_list = get_network_object_header(genes_dir, "unihost", "ipv4")
        # ===============
        # L4 GENES HEADER
        # ===============
        ipv4_l4_unihost_genes_header_list = get_network_object_header(genes_dir, "unihost", "ipv4-l4")
        # ================
        # TCP GENES HEADER
        # ================
        ipv4_tcp_unihost_genes_header_list = get_network_object_header(genes_dir, "unihost", "ipv4-tcp")

        # IPv4 Header
        ipv4_all_unihost_genes_header_list = ipv4_unihost_genes_header_list
        if l4_protocol:
            # IPv4-L4 Header
            ipv4_all_unihost_genes_header_list += ipv4_l4_unihost_genes_header_list
            if l4_protocol == "UDP":
                pass
            elif l4_protocol == "TCP":
                ipv4_all_unihost_genes_header_list += ipv4_tcp_unihost_genes_header_list

        for unihost_id in unihost_ids:
            # ======================
            # Additional Information
            # ======================
            curr_unihost = unihosts[unihost_id]

            first_bitalker = curr_unihost[0]
            last_bitalker = curr_unihost[-1]
            unihost_first_bitalker_initiation_time = first_bitalker[2]
            unihost_last_bitalker_termination_time = last_bitalker[3]
            unihost_first_bitalker_initiation_time = datetime_to_unixtime(unihost_first_bitalker_initiation_time)
            unihost_last_bitalker_termination_time = datetime_to_unixtime(unihost_last_bitalker_termination_time)

            # =========================
            # PREPARE DATA STRUCTURES |
            # =========================
            # ============================
            # BiTalker Conceptual Features
            # ============================
            # ------------------------
            # BiTalker Number Features
            # ------------------------
            unihost_n_bitalkers = len(curr_unihost)

            # -------------
            # Time Features
            # -------------
            unihost_duration = round((unihost_last_bitalker_termination_time - unihost_first_bitalker_initiation_time)/time_scale_factor, 3)

            # ---------------------------
            # BiTalker Frequency Features
            # ---------------------------
            unihost_bitalkers_per_sec = 0 if unihost_duration == 0 else round(unihost_n_bitalkers/unihost_duration, 3)

            # ---------------------------------
            # Additional Information - Reformat
            # ---------------------------------
            # Convert unihost_id to string
            unihost_id = iterator_to_str(unihost_id)
            unihost_first_bitalker_initiation_time = unixtime_to_datetime(unihost_first_bitalker_initiation_time)
            unihost_last_bitalker_termination_time = unixtime_to_datetime(unihost_last_bitalker_termination_time)

            # =============================
            # BiTalker Statistical Features
            # =============================
            # ------------------
            # IPv4 Data Lengthes
            # ------------------
            unihost_bitalker_any_biflow_eth_ipv4_data_lens = list()

            # --------------------
            # L4 Destination Ports
            # --------------------
            unihost_bitalker_any_biflow_n_unique_dst_ports = list()
            unihost_bitalker_fwd_biflow_n_unique_dst_ports = list()
            unihost_bitalker_bwd_biflow_n_unique_dst_ports = list()

            # ---------------------
            # TCP Innitiation Types
            # ---------------------
            unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations = list()

            # --------------------
            # TCP Connection Types
            # --------------------
            unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established = list()
            unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established = list()
            unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected = list()
            unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped = list()

            # ---------------------
            # TCP Termination Types
            # ---------------------
            unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations = list()
            unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations = list()
            unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations = list()

            # ==========================
            # POPULATE DATA STRUCTURES |
            # ==========================
            curr_bitalker_index = 0
            while curr_bitalker_index < unihost_n_bitalkers:
                # ===================
                # BiTalker Concepts |
                # ===================
                if curr_bitalker_index >= 1:
                    previous_bitalker = curr_unihost[curr_bitalker_index-1]
                    previous_bitalker_bitalker_id = previous_bitalker[1]
                    previous_bitalker_initiation_timestamp = previous_bitalker[2]
                    previous_bitalker_termination_timestamp = previous_bitalker[3]

                curr_bitalker = curr_unihost[curr_bitalker_index]
                curr_bitalker_id_str = curr_bitalker[0]
                curr_bitalker_id = str_to_iterator(curr_bitalker_id_str)
                curr_bitalker_bitalker_id_str = curr_bitalker[1]
                curr_bitalker_initiation_timestamp = curr_bitalker[2]
                curr_bitalker_termination_timestamp = curr_bitalker[3]

                # ------------------
                # IPv4 Data Lengthes
                # ------------------
                curr_bitalker_any_biflow_eth_ipv4_data_lens_total = int(curr_bitalker[14])
                unihost_bitalker_any_biflow_eth_ipv4_data_lens.append(curr_bitalker_any_biflow_eth_ipv4_data_lens_total)

                # ===========
                # L4 Concepts
                # ===========
                if l4_protocol:
                    # --------------------
                    # L4 Destination Ports
                    # --------------------
                    curr_bitalker_any_biflow_n_unique_dst_ports = int(curr_bitalker[104])
                    curr_bitalker_fwd_biflow_n_unique_dst_ports = int(curr_bitalker[105])
                    curr_bitalker_bwd_biflow_n_unique_dst_ports = int(curr_bitalker[106])
                    unihost_bitalker_any_biflow_n_unique_dst_ports.append(curr_bitalker_any_biflow_n_unique_dst_ports)
                    unihost_bitalker_fwd_biflow_n_unique_dst_ports.append(curr_bitalker_fwd_biflow_n_unique_dst_ports)
                    unihost_bitalker_bwd_biflow_n_unique_dst_ports.append(curr_bitalker_bwd_biflow_n_unique_dst_ports)

                    # ============
                    # TCP Concepts
                    # ============
                    if l4_protocol == "TCP":
                        # --------------------
                        # TCP Initiation Types
                        # --------------------
                        curr_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations = int(curr_bitalker[125])
                        unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations.append(curr_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations)

                        # --------------------
                        # TCP Connection Types
                        # --------------------
                        curr_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established = int(curr_bitalker[131])
                        unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established.append(curr_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established)

                        curr_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established = int(curr_bitalker[137])
                        unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established.append(curr_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established)

                        curr_bitalker_eth_ipv4_tcp_biflow_connections_rejected = int(curr_bitalker[143])
                        unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected.append(curr_bitalker_eth_ipv4_tcp_biflow_connections_rejected)

                        curr_bitalker_eth_ipv4_tcp_biflow_connections_dropped = int(curr_bitalker[149])
                        unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped.append(curr_bitalker_eth_ipv4_tcp_biflow_connections_dropped)

                        # ---------------------
                        # TCP Termination Types
                        # ---------------------
                        curr_bitalker_eth_ipv4_tcp_biflow_null_terminations = int(curr_bitalker[155])
                        unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations.append(curr_bitalker_eth_ipv4_tcp_biflow_null_terminations)

                        curr_bitalker_eth_ipv4_tcp_biflow_graceful_terminations = int(curr_bitalker[161])
                        unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations.append(curr_bitalker_eth_ipv4_tcp_biflow_graceful_terminations)

                        curr_bitalker_eth_ipv4_tcp_biflow_abort_terminations = int(curr_bitalker[167])
                        unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations.append(curr_bitalker_eth_ipv4_tcp_biflow_abort_terminations)
                # iterate the bitalkers inside a unihost
                curr_bitalker_index += 1

            # =============================
            # Statistical Features - Calc |
            # =============================
            # ------------------
            # IPv4 Data Lengthes
            # ------------------
            unihost_bitalker_any_biflow_eth_ipv4_data_lens_total = round(sum(unihost_bitalker_any_biflow_eth_ipv4_data_lens), 3)
            unihost_bitalker_any_biflow_eth_ipv4_data_lens_mean = round(np.mean(unihost_bitalker_any_biflow_eth_ipv4_data_lens), 3)
            unihost_bitalker_any_biflow_eth_ipv4_data_lens_std = round(np.std(unihost_bitalker_any_biflow_eth_ipv4_data_lens), 3)
            unihost_bitalker_any_biflow_eth_ipv4_data_lens_var = round(np.var(unihost_bitalker_any_biflow_eth_ipv4_data_lens), 3)
            unihost_bitalker_any_biflow_eth_ipv4_data_lens_max = round(max(unihost_bitalker_any_biflow_eth_ipv4_data_lens), 3)
            unihost_bitalker_any_biflow_eth_ipv4_data_lens_min = round(min(unihost_bitalker_any_biflow_eth_ipv4_data_lens), 3)

            # ===========
            # L4 Concepts
            # ===========
            if l4_protocol:
                # --------------------
                # L4 Destination Ports
                # --------------------
                unihost_bitalker_any_biflow_n_unique_dst_ports_total = round(sum(unihost_bitalker_any_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_any_biflow_n_unique_dst_ports_mean = round(np.mean(unihost_bitalker_any_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_any_biflow_n_unique_dst_ports_std = round(np.std(unihost_bitalker_any_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_any_biflow_n_unique_dst_ports_var = round(np.var(unihost_bitalker_any_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_any_biflow_n_unique_dst_ports_max = round(max(unihost_bitalker_any_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_any_biflow_n_unique_dst_ports_min = round(min(unihost_bitalker_any_biflow_n_unique_dst_ports), 3)

                unihost_bitalker_fwd_biflow_n_unique_dst_ports_total = round(sum(unihost_bitalker_fwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_fwd_biflow_n_unique_dst_ports_mean = round(np.mean(unihost_bitalker_fwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_fwd_biflow_n_unique_dst_ports_std = round(np.std(unihost_bitalker_fwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_fwd_biflow_n_unique_dst_ports_var = round(np.var(unihost_bitalker_fwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_fwd_biflow_n_unique_dst_ports_max = round(max(unihost_bitalker_fwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_fwd_biflow_n_unique_dst_ports_min = round(min(unihost_bitalker_fwd_biflow_n_unique_dst_ports), 3)

                unihost_bitalker_bwd_biflow_n_unique_dst_ports_total = round(sum(unihost_bitalker_bwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_bwd_biflow_n_unique_dst_ports_mean = round(np.mean(unihost_bitalker_bwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_bwd_biflow_n_unique_dst_ports_std = round(np.std(unihost_bitalker_bwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_bwd_biflow_n_unique_dst_ports_var = round(np.var(unihost_bitalker_bwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_bwd_biflow_n_unique_dst_ports_max = round(max(unihost_bitalker_bwd_biflow_n_unique_dst_ports), 3)
                unihost_bitalker_bwd_biflow_n_unique_dst_ports_min = round(min(unihost_bitalker_bwd_biflow_n_unique_dst_ports), 3)

                # ============
                # TCP Concepts
                # ============
                if l4_protocol == "TCP":
                    # ------------------------------
                    # TCP BiTalker Innitiation Types
                    # ------------------------------
                    unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_total = round(sum(unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_mean = round(np.mean(unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_std = round(np.std(unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_var = round(np.var(unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_max = round(max(unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations_min = round(min(unihost_bitalker_eth_ipv4_tcp_biflow_two_way_handshake_initiations), 3)

                    # -----------------------------
                    # TCP BiTalker Connection Types
                    # -----------------------------
                    unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_total = round(sum(unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_mean = round(np.mean(unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_std = round(np.std(unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_var = round(np.var(unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_max = round(max(unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established_min = round(min(unihost_bitalker_eth_ipv4_tcp_biflow_full_duplex_connections_established), 3)

                    unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_total = round(sum(unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_mean = round(np.mean(unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_std = round(np.std(unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_var = round(np.var(unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_max = round(max(unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established_min = round(min(unihost_bitalker_eth_ipv4_tcp_biflow_half_duplex_connections_established), 3)

                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected_total = round(sum(unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected_mean = round(np.mean(unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected_std = round(np.std(unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected_var = round(np.var(unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected_max = round(max(unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected_min = round(min(unihost_bitalker_eth_ipv4_tcp_biflow_connections_rejected), 3)

                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped_total = round(sum(unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped_mean = round(np.mean(unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped_std = round(np.std(unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped_var = round(np.var(unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped_max = round(max(unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped_min = round(min(unihost_bitalker_eth_ipv4_tcp_biflow_connections_dropped), 3)

                    # ------------------------------
                    # TCP BiTalker Termination Types
                    # ------------------------------
                    unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations_total = round(sum(unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations_mean = round(np.mean(unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations_std = round(np.std(unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations_var = round(np.var(unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations_max = round(max(unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations_min = round(min(unihost_bitalker_eth_ipv4_tcp_biflow_null_terminations), 3)

                    unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_total = round(sum(unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_mean = round(np.mean(unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_std = round(np.std(unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_var = round(np.var(unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_max = round(max(unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations_min = round(min(unihost_bitalker_eth_ipv4_tcp_biflow_graceful_terminations), 3)

                    unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations_total = round(sum(unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations_mean = round(np.mean(unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations_std = round(np.std(unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations_var = round(np.var(unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations_max = round(max(unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
                    unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations_min = round(min(unihost_bitalker_eth_ipv4_tcp_biflow_abort_terminations), 3)
            # ==========================
            # Conceptual Features - More
            # ==========================
            # --------------------------------
            # BiTalker Byte Frequency Features
            # --------------------------------
            unihost_bitalker_bytes_per_sec = 0 if unihost_duration == 0 else\
                round(unihost_bitalker_any_biflow_eth_ipv4_data_lens_total/unihost_duration, 3)

            # ===============
            # WRAP-UP RESULTS
            # ===============
            unihost_local_vars = locals()
            unihost_genes = [str(unihost_local_vars[var_name]) for var_name in ipv4_all_unihost_genes_header_list]

            yield unihost_genes

    unihost_genes_generator = calculate_l3_l4_unihost_genes(genes_dir, unihosts, unihost_ids, l4_protocol=l4_protocol)

    return list(unihost_genes_generator)