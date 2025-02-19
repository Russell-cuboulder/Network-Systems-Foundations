#!/usr/bin/python3

from scapy.all import *

# This class captures some information about a unidirectional flow
class FlowTracking:
    def __init__(self, startSeqNum, ackNumReceived, srcIP, dstIP):
        self.startSeqNum = startSeqNum
        self.ackNumReceived = ackNumReceived
        self.highestSeqNum = startSeqNum
        self.pktLenOfHighestSeqNumPacket = 0
        self.srcIP = srcIP
        self.dstIP = dstIP

# Returns FlowTracking object for the server side
def readHandShake(pkts):
    # Read SYN (client -> server)
    syn_pkt = pkts[0]
    if not (TCP in syn_pkt and syn_pkt[TCP].flags == "S"):
        raise ValueError("First packet is not a SYN packet.")
    seqInit = syn_pkt[TCP].seq
    srcInit = syn_pkt[IP].src
    dstInit = syn_pkt[IP].dst

    # Read SYN-ACK (server -> client)
    syn_ack_pkt = pkts[1]
    if not (TCP in syn_ack_pkt and syn_ack_pkt[TCP].flags == "SA"):
        raise ValueError("Second packet is not a SYN-ACK packet.")
    if syn_ack_pkt[TCP].ack != seqInit + 1:
        raise ValueError(f"SYN-ACK ack number mismatch: expected {seqInit + 1}, got {syn_ack_pkt[TCP].ack}")
    if syn_ack_pkt[IP].src != dstInit or syn_ack_pkt[IP].dst != srcInit:
        raise ValueError("SYN-ACK IP addresses do not match SYN packet.")

    seqOther = syn_ack_pkt[TCP].seq

    # Read ACK (client -> server)
    ack_pkt = pkts[2]
    if not (TCP in ack_pkt and ack_pkt[TCP].flags == "A"):
        raise ValueError("Third packet is not an ACK packet.")
    if ack_pkt[TCP].ack != seqOther + 1:
        raise ValueError(f"ACK ack number mismatch: expected {seqOther + 1}, got {ack_pkt[TCP].ack}")
    if ack_pkt[IP].src != srcInit or ack_pkt[IP].dst != dstInit:
        raise ValueError("ACK IP addresses do not match SYN packet.")

    return FlowTracking(seqOther, seqOther + 1, dstInit, srcInit)

# Returns true if the packet is in the direction of the unidirectional flow represented by f
def isFlowEgress(pkt, flow):
    return pkt[IP].src == flow.srcIP and pkt[IP].dst == flow.dstIP

# Given a pcap file name as a string, this function will return the max number of bytes
# that were in flight (unacknowledged) for this stream.
def findMaxBytesInFlight(pcap_file):
    try:
        pkts = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"Error: File {pcap_file} not found.")
        return -1

    # Read the handshake to initialize flow tracking
    try:
        flow = readHandShake(pkts)
    except ValueError as e:
        print(f"Error reading handshake: {e}")
        return -1

    max_bytes_in_flight = 0
    current_bytes_in_flight = 0

    # Process packets after the handshake
    for pkt in pkts[3:]:
        if IP in pkt and TCP in pkt:
            if isFlowEgress(pkt, flow):
                # Update highest sequence number and packet length
                if pkt[TCP].seq > flow.highestSeqNum:
                    flow.highestSeqNum = pkt[TCP].seq
                    flow.pktLenOfHighestSeqNumPacket = len(pkt[TCP].payload)

                # Calculate bytes in flight
                current_bytes_in_flight = flow.highestSeqNum - flow.ackNumReceived + flow.pktLenOfHighestSeqNumPacket
                max_bytes_in_flight = max(max_bytes_in_flight, current_bytes_in_flight)

            elif pkt[IP].src == flow.dstIP and pkt[IP].dst == flow.srcIP:
                # Update acknowledgment number
                flow.ackNumReceived = max(flow.ackNumReceived, pkt[TCP].ack)

    return max_bytes_in_flight

if __name__ == "__main__":
    pcap_files = [
        "simple-tcp-session.pcap",
        "out_10m_0p.pcap",
        "out_10m_2p.pcap"
    ]

    for pcap_file in pcap_files:
        print(f"Processing {pcap_file}:")
        max_bytes = findMaxBytesInFlight(pcap_file)
        if max_bytes != -1:
            print(f"Max bytes in flight: {max_bytes}")