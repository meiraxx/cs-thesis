def build_l4_bihosts(udp_unihosts, udp_unihost_ids, tcp_unihosts, tcp_unihost_ids):
    """Build L4 BiHosts"""
    def build_bihosts(l4_unihosts, l4_unihost_ids):
        """Build BiHosts"""
        # Note: l4_unihost_ids in both directions are the same as l4_bihost_ids
        def get_unique_matching_l4_unihost_ids(l4_unihost_ids):
            """Local helper function to return matching unidirectional host ids, with l4_fwd_host_id
            as key and l4_bwd_host_id as value, and not vice-versa"""
            matching_l4_unihost_ids_dict = dict()
            l4_fwd_host_ids = list()
            for l4_unihost_id in l4_unihost_ids:
                reversed_l4_unihost_id = (l4_unihost_id[0], l4_unihost_id[1])
                if reversed_l4_unihost_id in l4_unihost_ids:
                    if reversed_l4_unihost_id not in matching_l4_unihost_ids_dict:
                        l4_fwd_host_ids.append(l4_unihost_id)
                        matching_l4_unihost_ids_dict[l4_unihost_id] = reversed_l4_unihost_id
                else:
                    if reversed_l4_unihost_id not in matching_l4_unihost_ids_dict:
                        l4_fwd_host_ids.append(l4_unihost_id)
                        matching_l4_unihost_ids_dict[l4_unihost_id] = False

            return matching_l4_unihost_ids_dict, l4_fwd_host_ids

        matching_l4_unihost_ids_dict, l4_fwd_host_ids = get_unique_matching_l4_unihost_ids(l4_unihost_ids)
        l4_bihosts = dict()
        l4_bihost_ids = list()

        for l4_fwd_host_id in l4_fwd_host_ids:
            # have in mind every l4_unihost_id in this list will have been constituted by the first talker ever recorded in that host,
            # so the researcher defines l4_bihost_id = l4_fwd_host_id, which will also be l4_bwd_host_id
            l4_bwd_host_id = matching_l4_unihost_ids_dict[l4_fwd_host_id]
            l4_bihost_ids.append(l4_fwd_host_id)
            if l4_bwd_host_id:
                l4_bihosts[l4_fwd_host_id] = l4_unihosts[l4_fwd_host_id] + l4_unihosts[l4_bwd_host_id]
            else:
                l4_bihosts[l4_fwd_host_id] = l4_unihosts[l4_fwd_host_id]

        return l4_bihosts, l4_bihost_ids

    udp_bihosts, udp_bihost_ids = build_bihosts(udp_unihosts, udp_unihost_ids)
    tcp_bihosts, tcp_bihost_ids = build_bihosts(tcp_unihosts, tcp_unihost_ids)

    return udp_bihosts, udp_bihost_ids, tcp_bihosts, tcp_bihost_ids


# ====================
# Bidirectional Hosts
# ====================
if args.verbose:
    module_init_time = time.time()
    print(make_header_string("6.2. IPv4+GenericL4+(UDP|TCP) Bidirectional Hosts"), flush=True)

udp_bihosts, udp_bihost_ids, tcp_bihosts, tcp_bihost_ids = build_l4_bihosts(udp_unihosts, udp_unihost_ids, tcp_unihosts, tcp_unihost_ids)
del(udp_unihosts, udp_unihost_ids, tcp_unihosts, tcp_unihost_ids)

if args.verbose:
    n_contemplated_ipv4_udp_bitalkers = sum([len(udp_bihosts[udp_bihost_id]) for udp_bihost_id in udp_bihost_ids])
    n_contemplated_ipv4_tcp_bitalkers = sum([len(tcp_bihosts[tcp_bihost_id]) for tcp_bihost_id in tcp_bihost_ids])
    n_ipv4_udp_bihosts = len(udp_bihost_ids)
    n_ipv4_tcp_bihosts = len(tcp_bihost_ids)

    print("[+] IPv4-UDP BiTalkers contemplated:", n_contemplated_ipv4_udp_bitalkers, "IPv4-UDP BiTalkers", flush=True)
    print("[+] IPv4-TCP BiTalkers contemplated:", n_contemplated_ipv4_tcp_bitalkers, "IPv4-TCP BiTalkers", flush=True)
    print("[+] IPv4-UDP BiHosts detected:" + cterminal.colors.GREEN, n_ipv4_udp_bihosts, "IPv4-UDP BiHosts" + cterminal.colors.ENDC, flush=True)
    print("[+] IPv4-TCP BiHosts detected:" + cterminal.colors.GREEN, n_ipv4_tcp_bihosts, "IPv4-TCP BiHosts" + cterminal.colors.ENDC, flush=True)
    print("[T] Built in:" + cterminal.colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + cterminal.colors.ENDC, flush=True, end="\n\n")





""" This code could be included in the build_l4_unihosts function to get bihosts,
but would need some work to get it working afterwards in the gene extraction phase.
Furthermore, bihosts do not, apparently, offer much advantage in a network analysis
point of view for detecting threats, at least for the ones I've been researching.
If it is in fact needed, this code should be used"""
# Note: BWD Hosts will not be contemplated (inclusion code below)
try:
    unihosts[bwd_unihost_id].append(bitalker_genes)
except KeyError:
    unihost_ids.append(bwd_unihost_id)
    unihosts[bwd_unihost_id] = [bitalker_genes]