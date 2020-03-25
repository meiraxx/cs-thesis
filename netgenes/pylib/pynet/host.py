from pylib.pynet.netobject_utils import *

def build_l4_unihosts(ipv4_udp_bitalker_genes_generator_lst, udp_bitalker_ids, ipv4_tcp_bitalker_genes_generator_lst, tcp_bitalker_ids):
    """Build L4 UniHosts"""
    def build_unihosts(bitalker_genes_generator_lst, bitalker_ids):
        """Build UniHosts"""
        # Note: l4_unihost_ids in both directions are the same as l4_unihost_ids
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

    udp_unihosts, udp_unihost_ids = build_unihosts(ipv4_udp_bitalker_genes_generator_lst, udp_bitalker_ids)
    tcp_unihosts, tcp_unihost_ids = build_unihosts(ipv4_tcp_bitalker_genes_generator_lst, tcp_bitalker_ids)

    return udp_unihosts, udp_unihost_ids, tcp_unihosts, tcp_unihost_ids
