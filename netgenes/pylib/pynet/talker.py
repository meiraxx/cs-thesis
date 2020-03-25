from pylib.pynet.netobject_utils import *

def build_l4_unitalkers(ipv4_udp_biflow_genes_generator_lst, udp_biflow_ids, ipv4_tcp_biflow_genes_generator_lst, tcp_biflow_ids):
    """Build L4 UniTalkers"""
    def build_unitalkers(biflow_genes_generator_lst, biflow_ids):
        """Build UniTalkers"""
        unitalkers = dict()
        unitalker_ids = list()

        for biflow_genes in biflow_genes_generator_lst:
            biflow_id_str = biflow_genes[0]
            biflow_id = str_to_iterator(biflow_id_str)
            unitalker_id = biflow_id_to_bitalker_id(biflow_id)

            try:
                unitalkers[unitalker_id].append(biflow_genes)
            except KeyError:
                unitalker_ids.append(unitalker_id)
                unitalkers[unitalker_id] = [biflow_genes]

        return unitalkers, unitalker_ids

    udp_unitalkers, udp_unitalker_ids = build_unitalkers(ipv4_udp_biflow_genes_generator_lst, udp_biflow_ids)
    tcp_unitalkers, tcp_unitalker_ids = build_unitalkers(ipv4_tcp_biflow_genes_generator_lst, tcp_biflow_ids)

    return udp_unitalkers, udp_unitalker_ids, tcp_unitalkers, tcp_unitalker_ids

def build_l4_bitalkers(udp_unitalkers, udp_unitalker_ids, tcp_unitalkers, tcp_unitalker_ids):
    """Build L4 BiTalkers"""
    def build_bitalkers(l4_unitalkers, l4_unitalker_ids):
        """Build BiTalkers"""
        def get_unique_matching_l4_unitalker_ids(l4_unitalkers, l4_unitalker_ids):
            """Local helper function to return matching unidirectional talker ids, with l4_fwd_talker_id
            as key and l4_bwd_talker_id as value, and not vice-versa"""
            matching_l4_unitalker_ids_dict = dict()
            l4_fwd_talker_ids = list()
            for l4_unitalker_id in l4_unitalker_ids:
                reversed_l4_unitalker_id = (l4_unitalker_id[1], l4_unitalker_id[0], l4_unitalker_id[2])

                # Note: O(n**2) --> O(n) optimization done using dictionary search
                if reversed_l4_unitalker_id in l4_unitalkers:
                    if reversed_l4_unitalker_id not in matching_l4_unitalker_ids_dict:
                        l4_fwd_talker_ids.append(l4_unitalker_id)
                        matching_l4_unitalker_ids_dict[l4_unitalker_id] = reversed_l4_unitalker_id
                else:
                    if reversed_l4_unitalker_id not in matching_l4_unitalker_ids_dict:
                        l4_fwd_talker_ids.append(l4_unitalker_id)
                        matching_l4_unitalker_ids_dict[l4_unitalker_id] = False
            return matching_l4_unitalker_ids_dict, l4_fwd_talker_ids

        matching_l4_unitalker_ids_dict, l4_fwd_talker_ids = get_unique_matching_l4_unitalker_ids(l4_unitalkers, l4_unitalker_ids)
        l4_bitalkers = dict()
        l4_bitalker_ids = list()

        for l4_fwd_talker_id in l4_fwd_talker_ids:
            # have in mind every l4_unitalker_id in this list will have been constituted by the first flow ever recorded in that talker,
            # so the researcher defines l4_bitalker_id = l4_fwd_talker_id
            l4_bwd_talker_id = matching_l4_unitalker_ids_dict[l4_fwd_talker_id]
            l4_bitalker_ids.append(l4_fwd_talker_id)
            if l4_bwd_talker_id:
                l4_bitalkers[l4_fwd_talker_id] = l4_unitalkers[l4_fwd_talker_id] + l4_unitalkers[l4_bwd_talker_id]
            else:
                l4_bitalkers[l4_fwd_talker_id] = l4_unitalkers[l4_fwd_talker_id]

        return l4_bitalkers, l4_bitalker_ids

    udp_bitalkers, udp_bitalker_ids = build_bitalkers(udp_unitalkers, udp_unitalker_ids)
    tcp_bitalkers, tcp_bitalker_ids = build_bitalkers(tcp_unitalkers, tcp_unitalker_ids)

    return udp_bitalkers, udp_bitalker_ids, tcp_bitalkers, tcp_bitalker_ids
