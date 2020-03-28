# Standard
import os

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

def check_supported_network_objects(network_object_type):
    """ Check if network object type is supported"""
    if network_object_type not in ("biflow", "bitalker", "unihost"):
        print("[!] Network object type \"" + network_object_type + "\" not supported. Supported protocol stacks: biflow, bitalker, unihost",\
            file=sys.stderr, flush=True)
        sys.exit(1)

def check_supported_protocol_stacks(protocol_stack):
    """ Check if protocol stack is supported"""
    if protocol_stack not in ("ipv4", "ipv4-l4", "ipv4-tcp"):
        print("[!] Protocol stack \"" + protocol_stack + "\" not supported. Supported protocol stacks: ipv4, ipv4-l4, ipv4-tcp",\
            file=sys.stderr, flush=True)
        sys.exit(1)

def get_network_object_header(genes_dir, network_object_type, protocol_stack):
    """Use L3-L4 protocol stack to fetch correct biflow headers and return them as a list"""

    # Check network object type
    check_supported_network_objects(network_object_type)
    # Check protocol stack
    check_supported_protocol_stacks(protocol_stack)

    # Get NetGenes header in the form of a list
    net_genes_filepath = genes_dir + os.sep + "%s-%s-header.txt"%(network_object_type, protocol_stack)
    f = open(net_genes_filepath, "r")
    net_genes_header_lst = f.read().split("\n")
    f.close()

    return net_genes_header_lst