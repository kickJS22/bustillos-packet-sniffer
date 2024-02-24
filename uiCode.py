from scapy.all import sniff, TCP, UDP, raw, IP
import socket
import pandas as pd

import tkinter as tk
from tkinter import ttk

window = tk.Tk()
window.geometry("1920x1080")
window.title("Packet Table")

table = ttk.Treeview(window, columns=("id","route","proto","type","ttl","ipVer","ipSrc", "ipDst", "chkSum", "serv", "url", "load"),show="headings")
table.heading("id",text="ID")
table.heading("route",text="Route")
table.heading("proto",text="Protocol")
table.heading("type",text="Type")
table.heading("ttl",text="TTL")
table.heading("ipVer",text="IP Version")
table.heading("ipSrc",text="IP Source")
table.heading("ipDst",text="IP Destination")
table.heading("chkSum",text="CheckSum")
table.heading("serv",text="Service")
table.heading("url",text="URL")
table.heading("load",text="Load")
table.pack()

window.mainloop()
protocolList = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IPv4",
    5: "ST",
    6: "TCP",
    7: "CBT",
    8: "EGP",
    9: "IGP",
    10: "BBN-RCC-MON",
    11: "NVP-II",
    12: "PUP",
    13: "ARGUS (deprecated)",
    14: "EMCON",
    15: "XNET",
    16: "CHAOS",
    17: "UDP",
    18: "MUX",
    19: "DCN-MEAS",
    20: "HMP",
    21: "PRM",
    22: "XNS-IDP",
    23: "TRUNK-1",
    24: "TRUNK-2",
    25: "LEAF-1",
    26: "LEAF-2",
    27: "RDP",
    28: "IRTP",
    29: "ISO-TP4",
    30: "NETBLT",
    31: "MFE-NSP",
    32: "MERIT-INP",
    33: "DCCP",
    34: "3PC",
    35: "IDPR",
    36: "XTP",
    37: "DDP",
    38: "IDPR-CMTP",
    39: "TP++",
    40: "IL",
    41: "IPv6",
    42: "SDRP",
    43: "IPv6-Route",
    44: "IPv6-Frag",
    45: "IDRP",
    46: "RSVP",
    47: "GRE",
    48: "DSR",
    49: "BNA",
    50: "ESP",
    51: "AH",
    52: "I-NLSP",
    53: "SWIPE (deprecated)",
    54: "NARP",
    55: "Min-IPv4",
    56: "TLSP",
    57: "SKIP",
    58: "IPv6-ICMP",
    59: "IPv6-NoNxt",
    60: "IPv6-Opts",
    61: "Unknown",
    62: "CFTP",
    64: "SAT-EXPAK",
    65: "KRYPTOLAN",
    66: "RVD",
    67: "IPPC",
    69: "SAT-MON",
    70: "VISA",
    71: "IPCV",
    72: "CPNX",
    73: "CPHB",
    74: "WSN",
    75: "PVP",
    76: "BR-SAT-MON",
    77: "SUN-ND",
    78: "WB-MON",
    79: "WB-EXPAK",
    80: "ISO-IP",
    81: "VMTP",
    82: "SECURE-VMTP",
    83: "VINES",
    84: "IPTM",
    85: "NSFNET-IGP",
    86: "DGP",
    87: "TCF",
    88: "EIGRP",
    89: "OSPFIGP",
    90: "Sprite-RPC",
    91: "LARP",
    92: "MTP",
    93: "AX.25",
    94: "IPIP",
    95: "MICP (deprecated)",
    96: "SCC-SP",
    97: "ETHERIP",
    98: "ENCAP",
    99: "Unknown",
    100: "GMTP",
    101: "IFMP",
    102: "PNNI",
    103: "PIM",
    104: "ARIS",
    105: "SCPS",
    106: "QNX",
    107: "A/N",
    108: "IPComp",
    109: "SNP",
    110: "Compaq-Peer",
    111: "IPX-in-IP",
    112: "VRRP",
    113: "PGM",
    115: "L2TP",
    116: "DDX",
    117: "IATP",
    118: "STP",
    119: "SRP",
    120: "UTI",
    121: "SMP",
    122: "SM (deprecated)",
    123: "PTP",
    124: "ISIS over IPv4",
    125: "FIRE",
    126: "CRTP",
    127: "CRUDP",
    128: "SSCOPMCE",
    129: "IPLT",
    130: "SPS",
    131: "PIPE",
    132: "SCTP",
    133: "FC",
    134: "RSVP-E2E-IGNORE",
    135: "Mobility Header",
    136: "UDPLite",
    137: "MPLS-in-IP",
    138: "manet",
    139: "HIP",
    140: "Shim6",
    141: "WESP",
    142: "ROHC",
    143: "Ethernet",
    144: "AGGFRAG",
    145: "NSH",
    146: "Unknown",
    253: "Unknown",
    254: "Unknown",
    255: "Reserved"
}

protocolIdentifier = {
    1633: "DLOG",
    2048: "Internet Protocol version 4 (IPv4)",
    2049: "X.75 Internet",
    2050: "NBS Internet",
    2051: "ECMA Internet",
    2052: "Chaosnet",
    2053: "X.25 Level 3",
    2054: "Address Resolution Protocol (ARP)",
    2055: "XNS Compatability",
    2056: "Frame Relay ARP",
    2076: "Symbolics Private",
    2184: "Xyplex",
    2304: "Ungermann-Bass net debugr",
    2560: "Xerox IEEE802.3 PUP",
    2561: "PUP Addr Trans",
    2989: "Banyan VINES",
    2990: "VINES Loopback",
    2991: "VINES Echo",
    4096: "Berkeley Trailer nego",
    4097: "Berkeley Trailer encap/IP",
    5632: "Valid Systems",
    8947: "TRILL",
    8948: "L2-IS-IS",
    16962: "PCS Basic Block Protocol",
    21000: "BBN Simnet",
    24576: "DEC Unassigned (Exp.)",
    24577: "DEC MOP Dump/Load",
    24578: "DEC MOP Remote Console",
    24579: "DEC DECNET Phase IV Route",
    24580: "DEC LAT",
    24581: "DEC Diagnostic Protocol",
    24582: "DEC Customer Protocol",
    24583: "DEC LAVC, SCA",
    24584: "DEC Unassigned",
    24585: "DEC Unassigned",
    24592: "3Com Corporation",
    25944: "Trans Ether Bridging",
    25945: "Raw Frame Relay",
    28672: "Ungermann-Bass download",
    28674: "Ungermann-Bass dia/loop",
    28704: "LRT",
    28720: "Proteon",
    28724: "Cabletron",
    32771: "Cronus VLN",
    32772: "Cronus Direct",
    32773: "HP Probe",
    32774: "Nestar",
    32776: "AT&T",
    32784: "Excelan",
    32787: "SGI diagnostics",
    32788: "SGI network games",
    32789: "SGI reserved",
    32790: "SGI bounce server",
    32793: "Apollo Domain",
    32814: "Tymshare",
    32815: "Tigan, Inc.",
    32821: "Reverse Address Resolution Protocol (RARP)",
    32822: "Aeonic Systems",
    32824: "DEC LANBridge",
    32825: "DEC Unassigned",
    32829: "DEC Ethernet Encryption",
    32831: "DEC LAN Traffic Monitor",
    32832: "Planning Research Corp.",
    32836: "AT&T",
    32838: "AT&T",
    32841: "ExperData",
    32859: "Stanford V Kernel exp.",
    32860: "Stanford V Kernel prod.",
    32861: "Evans & Sutherland",
    32864: "Little Machines",
    32866: "Counterpoint Computers",
    32869: "Univ. of Mass. @ Amherst",
    32870: "Univ. of Mass. @ Amherst",
    32871: "Veeco Integrated Auto.",
    32872: "General Dynamics",
    32873: "AT&T",
    32874: "Autophon",
    32876: "ComDesign",
    32877: "Computgraphic Corp.",
    32878: "Landmark Graphics Corp.",
    32890: "Matra",
    32891: "Dansk Data Elektronik",
    32892: "Merit Internodal",
    32893: "Vitalink Communications",
    32896: "Vitalink TransLAN III",
    32923: "Appletalk",
    32924: "Datability",
    32927: "Spider Systems Ltd.",
    32931: "Nixdorf Computers",
    32932: "Siemens Gammasonics Inc.",
    32960: "DCA Data Exchange Cluster",
    32964: "Banyan Systems",
    32965: "Banyan Systems",
    32966: "Pacer Software",
    32967: "Applitek Corporation",
    32968: "Intergraph Corporation",
    32973: "Harris Corporation",
    32974: "Harris Corporation",
    32975: "Taylor Instrument",
    32979: "Rosemount Corporation",
    32980: "Rosemount Corporation",
    32981: "IBM SNA Service on Ether",
    32989: "Varian Associates",
    32990: "Integrated Solutions TRFS",
    32992: "Allen-Bradley",
    33010: "Retix",
    33011: "AppleTalk AARP (Kinetics)",
    33012: "Kinetics",
    33015: "Apollo Computer",
    33023: "Wellfleet Communications",
    33024: "Customer VLAN Tag Type (C-Tag, formerly called the Q-Tag) (initially Wellfleet)",
    33025: "Wellfleet Communications",
    33031: "Symbolics Private",
    33072: "Hayes Microcomputers",
    33073: "VG Laboratory Systems",
    33074: "Bridge Communications",
    33079: "Novell, Inc.",
    33080: "Novell, Inc.",
    33100: "SNMP",
    33101: "BIIN",
    33102: "BIIN",
    33103: "Technically Elite Concept",
    33104: "Rational Corp",
    33105: "Qualcomm",
    33116: "Computer Protocol Pty Ltd",
    33124: "Charles River Data System",
    33149: "XTP",
    33150: "SGI/Time Warner prop.",
    33152: "HIPPI-FP encapsulation",
    33153: "STP, HIPPI-ST",
    33154: "Reserved for HIPPI-6400",
    33156: "Silicon Graphics prop.",
    33165: "Motorola Computer",
    33178: "Qualcomm",
    33188: "ARAI Bunkichi",
    33207: "Xyplex",
    33228: "Apricot Computers",
    33238: "Artisoft",
    33254: "Polygon",
    33264: "Comsat Labs",
    33313: "Ascom Banking Systems",
    33342: "Advanced Encryption Systems",
    33407: "Athena Programming",
    33379: "Charles River Data System",
    33434: "Inst Ind Info Tech",
    33436: "Taurus Controls",
    33452: "Walker Richer & Quinn",
    34452: "Idea Courier",
    34462: "Computer Network Tech",
    34467: "Gateway Communications",
    34523: "SECTRA",
    34526: "Delta Controls",
    34525: "Internet Protocol version 6 (IPv6)",
    34527: "ATOMIC",
    34528: "Landis & Gyr Powers",
    34560: "Motorola",
    34667: "TCP/IP Compression",
    34668: "IP Autonomous Systems",
    34669: "Secure Data",
    34824: "IEEE Std 802.3 - Ethernet Passive Optical Network (EPON)",
    34825: "Slow Protocols (Link Aggregation, OAM, etc.)",
    34827: "Point-to-Point Protocol (PPP)",
    34828: "General Switch Management Protocol (GSMP)",
    34850: "Ethernet NIC hardware and software testing",
    34887: "MPLS",
    34888: "MPLS with upstream-assigned label",
    34913: "Multicast Channel Allocation Protocol (MCAP)",
    34915: "PPP over Ethernet (PPPoE) Discovery Stage",
    34916: "PPP over Ethernet (PPPoE) Session Stage",
    34958: "IEEE Std 802.1X - Port-based network access control",
    34984: "IEEE Std 802.1Q - Service VLAN tag identifier (S-Tag)",
    35478: "Invisible Software",
    34997: "IEEE Std 802 - Local Experimental Ethertype",
    34998: "IEEE Std 802 - Local Experimental Ethertype",
    34999: "IEEE Std 802 - OUI Extended Ethertype",
    35015: "IEEE Std 802.11 - Pre-Authentication (802.11i)",
    35020: "IEEE Std 802.1AB - Link Layer Discovery Protocol (LLDP)",
    35045: "IEEE Std 802.1AE - Media Access Control Security",
    35047: "Provider Backbone Bridging Instance tag",
    35061: "IEEE Std 802.1Q - Multiple VLAN Registration Protocol (MVRP)",
    35062: "IEEE Std 802.1Q - Multiple Multicast Registration Protocol (MMRP)",
    35063: "Precision Time Protocol",
    35085: "IEEE Std 802.11 - Fast Roaming Remote Request (802.11r)",
    35095: "IEEE Std 802.21 - Media Independent Handover Protocol",
    35113: "IEEE Std 802.1Qbe - Multiple I-SID Registration Protocol",
    35131: "TRILL Fine Grained Labeling (FGL)",
    35136: "IEEE Std 802.1Qbg - ECP Protocol (also used in 802.1BR)",
    35142: "TRILL RBridge Channel",
    35143: "GeoNetworking as defined in ETSI EN 302 636-4-1",
    35151: "NSH (Network Service Header)",
    36864: "Loopback",
    36865: "3Com(Bridge) XNS Sys Mgmt",
    36866: "3Com(Bridge) TCP-IP Sys",
    36867: "3Com(Bridge) loop detect",
    39458: "Multi-Topology",
    41197: "LoWPAN encapsulation",
    47082: "GRE control messages encapsulated",
    65280: "BBN VITAL-LanBridge cache private protocol.",
    65535: "Reserved"
}


def packet_callback(packet):
    
    id= packet.id    
    
    route = packet.route()[0]
    
    protocol = protocolList[packet.proto]

    type = protocolIdentifier[packet.type]
    typeNum = packet.type

    ttl = packet.ttl

    ipVer = packet[IP].version
    
    ipSrc = packet[IP].src
    
    ipDst = packet[IP].dst


    checkSumHex = hex(packet[IP].chksum)
    checkSum = packet[IP].chksum

    service=""

    url=""

    load= raw(packet)
    
    try:       
        service = socket.getservbyport(packet.dport, protocol.lower() +"")
    except:
        try:
            service=socket.getservbyport(packet.sport, protocol.lower() +"")
        except:
            service= f"Not identified, protocol({protocol})"
    
    try:       
        url = socket.gethostbyaddr(ipSrc)
    except:
        try:
            url = socket.gethostbyaddr(ipDst)
        except:
            url = "Can't resolve"    


    
# TO DO: The realtime table
# sniff(prn=packet_callback, store=0)



