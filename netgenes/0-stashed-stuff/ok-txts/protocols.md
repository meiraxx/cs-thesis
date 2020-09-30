## Layer 4 Protocol summary

Both datagrams and segments are meant to transport data. However, while a datagram is just an individual datagram and not necessarily part of a flow, a segment is a datagram that is necessarily part of a flow of multiple other segments meant to deliver strictly-ordered data to the target. Although these terms are the correct ones to refer to any TCP or UDP packet, an SCTP packet would have to be called something else since it may or may not be part of a stream, as well as other L4 protocols that we do not consider here as well. As such, the term "packet" is used throughout this work for any protocol running over IP because the IP protocol is the least common denominator analyzed in this work and it would be cumbersome to constantly switch terminology when that is not the focus of this work. As for L1 and L2 protocols, we'll refer to their respective text-book terms: "bitstream" and "frame".

### UDP
**Description**:  
The User Datagram Protocol (UDP) is a message-oriented protocol which allows for direct data exchanges to take place without the need for a connection, thus making it a more lightweight protocol in what it comes to the flow concept. By not providing the many useful features that TCP provides (e.g. reliability, ordered data delivery, flow control, congestion control, security mechanisms) and not having to carry so much metadata associated with an established connection on the transport protocol header, both the packet size and the time needed for packet validation operations become smaller, ultimately resulting higher data transfer speeds.

**Flow Properties**:
- Does not support connections.
- Does not require any handshake between two communicating hosts.

### TCP
**Description:**  
The Transmission Control Protocol (TCP) is a connection-oriented protocol that provides reliability (using TCP retransmissions), ordered data delivery, flow control, congestion control and security. In a TCP connection scenario, the client (source host) uses a port (chosen based on the current state of the system, out of a wide port interval used to establish outbound connections) to send an initial SYN packet to the server (destination host) that is running a TCP service on a fixed port.

**Flow Properties:**  
- Supports two states of connection: half open and full open.
- In order to establish a half-open connection, TCP requires a 2-way handshake between client and server (client sends a SYN packet, server responds with a SYN-ACK packet).
- In order to establish a full-open connection, after the half-open connection establishment, the protocol requires the termination of the 3-way handshake (client sends ACK packet back to server), resulting in a full-open connection where both client and server may bidirectionally exchange data with each other. The connection process and the data exchanged are all part of what we consider a "TCP flow".

### SCTP
**Description:**  
The Stream Control Transmission Protocol (SCTP) is a relatively new alternative to the TCP and UDP protocols, combining most characteristics of TCP and UDP. On top of TCP and UDP features, it adds multi-homing and multi-streaming features, as well as improved security and fault tolerance mechanisms. SCTP has the potential to be used for most applications that TCP and UDP are currently used for, but its use is still very restricted to SS7-over-IP and SIGTRAN related services for telco companies.  

**Flow Properties:**  
- Exclusively supports full-open connections.
- Requires a 4-way handshake between two communicating hosts before a full-open connection is established and data can be orderly exchanged.