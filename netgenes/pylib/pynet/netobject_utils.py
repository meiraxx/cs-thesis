# ========================
# Network Object to String
# ========================
def iterator_to_str(iterator, separator="-"):
    """Convert iterable to string"""
    return separator.join(map(str,iterator))

def str_to_iterator(string, separator="-"):
    """Convert string to iterable"""
    return string.split(separator)
    
# ================================
# Network Object to Network Object
# ================================
def biflow_id_to_bitalker_id(biflow_id):
    """Get biflow_id's correspondent bitalker_id"""
    # Note: the researcher remodified the definition of bitalker to keep the BiFlow protocol_stack because then
    # it's possible to cluster most biflow genes while considering different protocols at this level
    bitalker_id = (biflow_id[0], biflow_id[2], biflow_id[4])
    return bitalker_id

def bitalker_id_to_unihost_id(bitalker_id, _reversed=False):
    """Get bitalker_id's correspondent unihost_id"""
    # Note: the researcher will keep the protocol_stack in this network object definition because we want to analyze
    # each protocol_stack independently (for now, at least)
    if not _reversed:
        unihost_id = (bitalker_id[0], bitalker_id[2])
    else:
        unihost_id = (bitalker_id[1], bitalker_id[2])

    return unihost_id

# ===============================
# Network Objects to PCAP Filters
# ===============================
def biflow_id_to_pcap_filter(biflow_id):
    """ Auxiliary function to convert a biflow id to a pcap filter. Right now, just used for debugging."""
    src_ip = biflow_id[0]
    src_port_str = str(biflow_id[1])
    dst_ip = biflow_id[2]
    dst_port_str = str(biflow_id[3])
    l4_protocol = biflow_id[4]

    src_ip_filter = "(" +\
        "(ip.addr==" + src_ip + ")" +\
        "&&" +\
        "(ip.addr==" + dst_ip + ")" +\
        ")"

    src_port_filter = "(" +\
        "(" + l4_protocol.lower() + ".srcport==" + src_port_str + "&&" + l4_protocol.lower() + ".dstport==" + dst_port_str + ")" +\
        "||" +\
        "(" + l4_protocol.lower() + ".srcport==" + dst_port_str + "&&" + l4_protocol.lower() + ".dstport==" + src_port_str + ")" +\
        ")"
    pcap_filter = src_ip_filter + "&&" + src_port_filter
    return pcap_filter

def bitalker_id_to_pcap_filter(bitalker_id):
    """ Auxiliary function to convert a biflow id to a pcap filter. Right now, just used for debugging."""
    src_ip = bitalker_id[0]
    dst_ip = bitalker_id[1]

    src_ip_filter = "(" +\
        "(ip.addr==" + src_ip + ")" +\
        "&&" +\
        "(ip.addr==" + dst_ip + ")" +\
        ")"

    pcap_filter = src_ip_filter
    return pcap_filter