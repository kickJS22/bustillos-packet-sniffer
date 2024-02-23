from scapy.all import sniff, TCP, UDP, raw, IP
import socket
def packet_callback(packet):


    load= raw(packet)
    
    ipSrc = packet[IP].src
    
    ipDst = packet[IP].dst

    service=""

    try:
        service=socket.getservbyport(packet.dport)
    except:
        service=socket.getservbyport(packet.sport)
          
    route = packet.route()[0]

    # Creating a list with the provided words:

    protocolList = [
        "HOPOPT", "ICMP", "IGMP", "GGP", "IP-in-IP", "ST", "TCP", "CBT", "EGP", "IGP",
        "BBN-RCC-MON", "NVP-II", "PUP", "ARGUS", "EMCON", "XNET", "CHAOS", "UDP", "MUX",
        "DCN-MEAS", "HMP", "PRM", "XNS-IDP", "TRUNK-1", "TRUNK-2", "LEAF-1", "LEAF-2",
        "RDP", "IRTP", "ISO-TP4", "NETBLT", "MFE-NSP", "MERIT-INP", "DCCP", "3PC", "IDPR",
        "XTP", "DDP", "IDPR-CMTP", "TP++", "IL", "IPv6", "SDRP", "IPv6-Route", "IPv6-Frag",
        "IDRP", "RSVP", "GRE", "DSR", "BNA", "ESP", "AH", "I-NLSP", "SwIPe", "NARP",
        "MOBILE", "TLSP", "SKIP", "IPv6-ICMP", "IPv6-NoNxt", "IPv6-Opts", "CFTP", "SAT-EXPAK",
        "KRYPTOLAN", "RVD", "IPPC", "SAT-MON", "VISA", "IPCU", "CPNX", "CPHB", "WSN", "PVP",
        "BR-SAT-MON", "SUN-ND", "WB-MON", "WB-EXPAK", "ISO-IP", "VMTP", "SECURE-VMTP", "VINES",
        "TTP", "IPTM", "NSFNET-IGP", "DGP", "TCF", "EIGRP", "OSPF", "Sprite-RPC", "LARP",
        "MTP", "AX.25", "OS", "MICP", "SCC-SP", "ETHERIP", "ENCAP", "GMTP", "IFMP", "PNNI",
        "PIM", "ARIS", "SCPS", "QNX", "A/N", "IPComp", "SNP", "Compaq-Peer", "IPX-in-IP",
        "VRRP", "PGM", "L2TP", "DDX", "IATP", "STP", "SRP", "UTI", "SMP", "SM", "PTP",
        "IS-IS over IPv4", "FIRE", "CRTP", "CRUDP", "SSCOPMCE", "IPLT", "SPS", "PIPE",
        "SCTP", "FC", "RSVP-E2E-IGNORE", "Mobility Header", "UDPLite", "MPLS-in-IP",
        "manet", "HIP", "Shim6", "WESP", "ROHC", "Ethernet", "AGGFRAG", "NSH"
    ]
    
    print(f"ROUTE: {route}, IP SRC: {ipSrc}, IP DST: {ipDst}, Protocol: {protocolList[packet.proto]}, Length: {packet.len}, SRC PORT: {packet.sport}, DST PORT: {packet.dport}, SERVICE: {service}")
        
    

sniff(prn=packet_callback, store=0)



