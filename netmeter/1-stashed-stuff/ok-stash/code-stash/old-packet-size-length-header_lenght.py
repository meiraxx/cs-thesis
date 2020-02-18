# I do not remember why I did this like this, but I see no point in keeping it, flow data can be thoroughly organized in layers

# ethernet frame minimum size (minimum packet length)
packet_len_minimum = 64

# packet header definition includes all except tcp.data (ip header, ip options, tcp header, tcp options)
packet_header_len = 14 + ip_header_len + transport_header_len

# ethernet zero-byte padding until 64 bytes are reached
if frame_len >= packet_len_minimum:
    packet_len = frame_len
    # packet size (tcp data length)
    packet_size = packet_len - packet_header_len
else:
    eth_padding_bytes = frame_len - packet_header_len
    # header len will ignore eth padding bytes
    # in this case, packet_len = packet_header_len
    packet_len = frame_len - eth_padding_bytes
    # ethernet zero-byte padding until 64 bytes are reached
    packet_size = packet_len - packet_header_len


print("Packet header length:", packet_header_len, flush=True)
print("Packet size:", packet_size, flush=True)
print("Packet length:", packet_len, flush=True)