    # ==============================
    # IPv4-L4-(UDP|TCP) BiFlow Genes
    # ==============================
    if args.verbose:
        print(make_header_string("3. Layer-3/Layer-4 Bidirectional Flow Genes", "=", "=", big_header_factor=2), flush=True)
    # ------------------------------------------
    # IPv4-L4-(UDP|TCP) BiFlow Gene Calculations
    # ------------------------------------------
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("3.1. IPv4+GenericL4+(UDP|TCP) BiFlow Genes"), flush=True)

    # UDP
    ipv4_udp_biflow_genes_generator_lst = flow.get_l3_l4_biflow_gene_generators(\
        netgenes_globals.genes_dir, udp_biflows, udp_biflow_ids, l4_protocol="UDP", verbose=args.verbose)
    del(udp_biflows)
    output_net_genes(ipv4_udp_biflow_genes_generator_lst, "UDP", "biflow")

    # TCP
    ipv4_tcp_biflow_genes_generator_lst = flow.get_l3_l4_biflow_gene_generators(\
        netgenes_globals.genes_dir, tcp_biflows, tcp_biflow_ids,\
        l4_protocol="TCP", l4_conceptual_features=rfc793_tcp_biflow_conceptual_features, verbose=args.verbose)
    del(tcp_biflows, rfc793_tcp_biflow_conceptual_features)
    output_net_genes(ipv4_tcp_biflow_genes_generator_lst, "TCP", "biflow")
    if args.verbose:
        # minus 4 to remove biflow_id, bitalker_id, biflow_any_first_packet_time and biflow_any_last_packet_time
        ipv4_biflow_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "biflow", "ipv4")) - 4
        ipv4_l4_biflow_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "biflow", "ipv4-l4"))
        ipv4_tcp_biflow_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "biflow", "ipv4-tcp"))

        print("[+] Calculated IPv4 BiFlow Genes:", ipv4_biflow_genes_count, "BiFlow Genes", flush=True)
        print("[+] Calculated IPv4+GenericL4 BiFlow Genes:", ipv4_biflow_genes_count + ipv4_l4_biflow_genes_count, "BiFlow Genes", flush=True)
        print("[+] Calculated IPv4+GenericL4+UDP BiFlow Genes:" + Colors.GREEN, \
            ipv4_biflow_genes_count + ipv4_l4_biflow_genes_count, "BiFlow Genes" + Colors.ENDC, flush=True)
        print("[+] Calculated IPv4+GenericL4+TCP BiFlow Genes:" + Colors.GREEN, \
            ipv4_biflow_genes_count + ipv4_l4_biflow_genes_count + ipv4_tcp_biflow_genes_count, "BiFlow Genes" + Colors.ENDC, flush=True)
        print("[T] Calculated and saved in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True)

    # =========
    # Talkers |
    # =========
    if args.verbose:
        print(make_header_string("4. Layer-3/Layer-4 Talker Construction", "=", "=", big_header_factor=2), flush=True)

    # ======================
    # Unidirectional Talkers
    # ======================
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("4.1. IPv4+GenericL4+(UDP|TCP) Unidirectional Talkers"), flush=True)
        
    # UDP
    udp_unitalkers, udp_unitalker_ids, = talker.build_unitalkers(ipv4_udp_biflow_genes_generator_lst, udp_biflow_ids)
    del(ipv4_udp_biflow_genes_generator_lst, udp_biflow_ids)

    # TCP
    tcp_unitalkers, tcp_unitalker_ids = talker.build_unitalkers(ipv4_tcp_biflow_genes_generator_lst, tcp_biflow_ids)
    del(ipv4_tcp_biflow_genes_generator_lst, tcp_biflow_ids)

    if args.verbose:
        n_contemplated_ipv4_udp_biflows = sum([len(udp_unitalkers[udp_unitalker_id]) for udp_unitalker_id in udp_unitalker_ids])
        n_contemplated_ipv4_tcp_biflows = sum([len(tcp_unitalkers[tcp_unitalker_id]) for tcp_unitalker_id in tcp_unitalker_ids])
        n_ipv4_udp_unitalkers = len(udp_unitalker_ids)
        n_ipv4_tcp_unitalkers = len(tcp_unitalker_ids)

        print("[+] IPv4-UDP BiFlows contemplated:", n_contemplated_ipv4_udp_biflows, "IPv4-UDP BiFlows", flush=True)
        print("[+] IPv4-TCP BiFlows contemplated:", n_contemplated_ipv4_tcp_biflows, "IPv4-TCP BiFlows", flush=True)
        print("[+] IPv4-UDP UniTalkers detected:" + Colors.GREEN, n_ipv4_udp_unitalkers, "IPv4-UDP UniTalkers" + Colors.ENDC, flush=True)
        print("[+] IPv4-TCP UniTalkers detected:" + Colors.GREEN, n_ipv4_tcp_unitalkers, "IPv4-TCP UniTalkers" + Colors.ENDC, flush=True)
        print("[T] Built in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # =====================
    # Bidirectional Talkers
    # =====================
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("4.2. IPv4+GenericL4+(UDP|TCP) Bidirectional Talkers"), flush=True)

    # UDP
    udp_bitalkers, udp_bitalker_ids = talker.build_bitalkers(udp_unitalkers, udp_unitalker_ids)
    del(udp_unitalkers, udp_unitalker_ids)

    # TCP
    tcp_bitalkers, tcp_bitalker_ids = talker.build_bitalkers(tcp_unitalkers, tcp_unitalker_ids)
    del(tcp_unitalkers, tcp_unitalker_ids)

    if args.verbose:
        n_contemplated_ipv4_udp_biflows = sum([len(udp_bitalkers[udp_bitalker_id]) for udp_bitalker_id in udp_bitalker_ids])
        n_contemplated_ipv4_tcp_biflows = sum([len(tcp_bitalkers[tcp_bitalker_id]) for tcp_bitalker_id in tcp_bitalker_ids])
        n_ipv4_udp_bitalkers = len(udp_bitalker_ids)
        n_ipv4_tcp_bitalkers = len(tcp_bitalker_ids)

        print("[+] IPv4-UDP BiFlows contemplated:", n_contemplated_ipv4_udp_biflows, "IPv4-UDP BiFlows", flush=True)
        print("[+] IPv4-TCP BiFlows contemplated:", n_contemplated_ipv4_tcp_biflows, "IPv4-TCP BiFlows", flush=True)
        print("[+] IPv4-UDP BiTalkers detected:" + Colors.GREEN, n_ipv4_udp_bitalkers, "IPv4-UDP BiTalkers" + Colors.ENDC, flush=True)
        print("[+] IPv4-TCP BiTalkers detected:" + Colors.GREEN, n_ipv4_tcp_bitalkers, "IPv4-TCP BiTalkers" + Colors.ENDC, flush=True)
        print("[T] Built in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # ================================
    # IPv4-L4-(UDP|TCP) BiTalker Genes
    # ================================
    if args.verbose:
        print(make_header_string("5. Layer-3/Layer-4 Bidirectional Talker Genes", "=", "=", big_header_factor=2), flush=True)

    # --------------------------------------------
    # IPv4-L4-(UDP|TCP) BiTalker Gene Calculations
    # --------------------------------------------
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("5.1. IPv4+GenericL4+(UDP|TCP) BiTalker Genes"), flush=True)

    # UDP
    ipv4_udp_bitalker_genes_generator_lst = talker.get_l3_l4_bitalker_gene_generators(\
        netgenes_globals.genes_dir, udp_bitalkers, udp_bitalker_ids, l4_protocol="UDP")
    del(udp_bitalkers)
    output_net_genes(ipv4_udp_bitalker_genes_generator_lst, "UDP", "bitalker")

    # TCP
    ipv4_tcp_bitalker_genes_generator_lst = talker.get_l3_l4_bitalker_gene_generators(\
        netgenes_globals.genes_dir, tcp_bitalkers, tcp_bitalker_ids, l4_protocol="TCP")
    del(tcp_bitalkers)
    output_net_genes(ipv4_tcp_bitalker_genes_generator_lst, "TCP", "bitalker")

    if args.verbose:
        # minus 4 to remove bitalker_id, unihost_id, bitalker_any_first_biflow_initiation_time
        # and bitalker_any_last_biflow_termination_time
        ipv4_bitalker_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "bitalker", "ipv4")) - 4
        ipv4_l4_bitalker_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "bitalker", "ipv4-l4"))
        ipv4_tcp_bitalker_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "bitalker", "ipv4-tcp"))

        print("[+] Calculated IPv4 BiTalker Genes:", ipv4_bitalker_genes_count, "BiTalker Genes", flush=True)
        print("[+] Calculated IPv4+GenericL4 BiTalker Genes:", ipv4_bitalker_genes_count + ipv4_l4_bitalker_genes_count, "BiTalker Genes", flush=True)
        print("[+] Calculated IPv4+GenericL4+UDP BiTalker Genes:" + Colors.GREEN, \
            ipv4_bitalker_genes_count + ipv4_l4_bitalker_genes_count, "BiTalker Genes" + Colors.ENDC, flush=True)
        print("[+] Calculated IPv4+GenericL4+TCP BiTalker Genes:" + Colors.GREEN, \
            ipv4_bitalker_genes_count + ipv4_l4_bitalker_genes_count + ipv4_tcp_bitalker_genes_count, "BiTalker Genes" + Colors.ENDC, flush=True)
        print("[T] Calculated and saved in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # =======
    # Hosts |
    # =======
    if args.verbose:
        print(make_header_string("6. Layer-3/Layer-4 Host Construction", "=", "=", big_header_factor=2), flush=True)

    # ====================
    # Unidirectional Hosts
    # ====================
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("6.1. IPv4+GenericL4+(UDP|TCP) Unidirectional Hosts"), flush=True)

    # UDP
    udp_unihosts, udp_unihost_ids = host.build_unihosts(ipv4_udp_bitalker_genes_generator_lst, udp_bitalker_ids)
    del(ipv4_udp_bitalker_genes_generator_lst, udp_bitalker_ids)

    # TCP
    tcp_unihosts, tcp_unihost_ids = host.build_unihosts(ipv4_tcp_bitalker_genes_generator_lst, tcp_bitalker_ids)
    del(ipv4_tcp_bitalker_genes_generator_lst, tcp_bitalker_ids)

    if args.verbose:
        n_contemplated_ipv4_udp_bitalkers = sum([len(udp_unihosts[udp_unihost_id]) for udp_unihost_id in udp_unihost_ids])
        n_contemplated_ipv4_tcp_bitalkers = sum([len(tcp_unihosts[tcp_unihost_id]) for tcp_unihost_id in tcp_unihost_ids])
        n_ipv4_udp_unihosts = len(udp_unihost_ids)
        n_ipv4_tcp_unihosts = len(tcp_unihost_ids)

        print("[+] IPv4-UDP BiTalkers contemplated:", n_contemplated_ipv4_udp_bitalkers, "IPv4-UDP BiTalkers", flush=True)
        print("[+] IPv4-TCP BiTalkers contemplated:", n_contemplated_ipv4_tcp_bitalkers, "IPv4-TCP BiTalkers", flush=True)
        print("[+] IPv4-UDP UniHosts detected:" + Colors.GREEN, n_ipv4_udp_unihosts, "IPv4-UDP UniHosts" + Colors.ENDC, flush=True)
        print("[+] IPv4-TCP UniHosts detected:" + Colors.GREEN, n_ipv4_tcp_unihosts, "IPv4-TCP UniHosts" + Colors.ENDC, flush=True)
        print("[T] Built in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")

    # ================================
    # IPv4-L4-(UDP|TCP) UniHost Genes
    # ================================
    if args.verbose:
        print(make_header_string("7. Layer-3/Layer-4 Unidirectional Host Genes", "=", "=", big_header_factor=2), flush=True)

    # --------------------------------------------
    # IPv4-L4-(UDP|TCP) UniHost Gene Calculations
    # --------------------------------------------
    if args.verbose:
        module_init_time = time.time()
        print(make_header_string("7.1. IPv4+GenericL4+(UDP|TCP) UniHost Genes"), flush=True)

    # UDP
    ipv4_udp_unihost_genes_generator_lst = host.get_l3_l4_unihost_gene_generators(\
        netgenes_globals.genes_dir, udp_unihosts, udp_unihost_ids, l4_protocol="UDP")
    del(udp_unihosts)
    output_net_genes(ipv4_udp_unihost_genes_generator_lst, "UDP", "unihost")

    # TCP
    ipv4_tcp_unihost_genes_generator_lst = host.get_l3_l4_unihost_gene_generators(\
        netgenes_globals.genes_dir, tcp_unihosts, tcp_unihost_ids, l4_protocol="TCP")
    del(tcp_unihosts)
    output_net_genes(ipv4_tcp_unihost_genes_generator_lst, "TCP", "unihost")

    if args.verbose:
        # minus 3 to remove unihost_id, unihost_first_bitalker_initiation_time
        # and unihost_first_bitalker_termination_time
        ipv4_unihost_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "unihost", "ipv4")) - 3
        ipv4_l4_unihost_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "unihost", "ipv4-l4"))
        ipv4_tcp_unihost_genes_count = len(get_network_object_header(netgenes_globals.genes_dir, "unihost", "ipv4-tcp"))

        print("[+] Calculated IPv4 UniHost Genes:", ipv4_unihost_genes_count, "UniHost Genes", flush=True)
        print("[+] Calculated IPv4+GenericL4 UniHost Genes:", ipv4_unihost_genes_count + ipv4_l4_unihost_genes_count, "UniHost Genes", flush=True)
        print("[+] Calculated IPv4+GenericL4+UDP UniHost Genes:" + Colors.GREEN, \
            ipv4_unihost_genes_count + ipv4_l4_unihost_genes_count, "UniHost Genes" + Colors.ENDC, flush=True)
        print("[+] Calculated IPv4+GenericL4+TCP UniHost Genes:" + Colors.GREEN, \
            ipv4_unihost_genes_count + ipv4_l4_unihost_genes_count + ipv4_tcp_unihost_genes_count, "UniHost Genes" + Colors.ENDC, flush=True)
        print("[T] Calculated and saved in:" + Colors.YELLOW, round(time.time() - module_init_time, 3), "seconds" + Colors.ENDC, flush=True, end="\n\n")