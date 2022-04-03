/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package iptables

import "strconv"

// Created by gen.go, don't edit manually
// Generated at 2022-03-21 20:30:51

type Protocol int

func (proto Protocol) Type() string {
	return "Protocol"
}

func (proto Protocol) Value() string {
	return strconv.Itoa(int(proto))
}

const (
	ProtocolIP              Protocol = 0   // internet protocol, pseudo protocol number
	ProtocolHOPOPT          Protocol = 0   // hop-by-hop options for ipv6
	ProtocolICMP            Protocol = 1   // internet control message protocol
	ProtocolIGMP            Protocol = 2   // internet group management protocol
	ProtocolGGP             Protocol = 3   // gateway-gateway protocol
	ProtocolIPv4            Protocol = 4   // IPv4 encapsulation
	ProtocolST              Protocol = 5   // ST datagram mode
	ProtocolTCP             Protocol = 6   // transmission control protocol
	ProtocolCBT             Protocol = 7   // CBT, Tony Ballardie <A.Ballardie@cs.ucl.ac.uk>
	ProtocolEGP             Protocol = 8   // exterior gateway protocol
	ProtocolIGP             Protocol = 9   // any private interior gateway (Cisco: for IGRP)
	ProtocolBBN_RCC_MON     Protocol = 10  // BBN RCC Monitoring
	ProtocolNVP_II          Protocol = 11  // Network Voice Protocol
	ProtocolPUP             Protocol = 12  // PARC universal packet protocol
	ProtocolARGUS           Protocol = 13  // ARGUS
	ProtocolEMCON           Protocol = 14  // EMCON
	ProtocolXNET            Protocol = 15  // Cross Net Debugger
	ProtocolCHAOS           Protocol = 16  // Chaos
	ProtocolUDP             Protocol = 17  // user datagram protocol
	ProtocolMUX             Protocol = 18  // Multiplexing protocol
	ProtocolDCN_MEAS        Protocol = 19  // DCN Measurement Subsystems
	ProtocolHMP             Protocol = 20  // host monitoring protocol
	ProtocolPRM             Protocol = 21  // packet radio measurement protocol
	ProtocolXNS_IDP         Protocol = 22  // Xerox NS IDP
	ProtocolTRUNK_1         Protocol = 23  // Trunk-1
	ProtocolTRUNK_2         Protocol = 24  // Trunk-2
	ProtocolLEAF_1          Protocol = 25  // Leaf-1
	ProtocolLEAF_2          Protocol = 26  // Leaf-2
	ProtocolRDP             Protocol = 27  // &#34;reliable datagram&#34; protocol
	ProtocolIRTP            Protocol = 28  // Internet Reliable Transaction Protocol
	ProtocolISO_TP4         Protocol = 29  // ISO Transport Protocol Class 4
	ProtocolNETBLT          Protocol = 30  // Bulk Data Transfer Protocol
	ProtocolMFE_NSP         Protocol = 31  // MFE Network Services Protocol
	ProtocolMERIT_INP       Protocol = 32  // MERIT Internodal Protocol
	ProtocolDCCP            Protocol = 33  // Datagram Congestion Control Protocol
	Protocol3PC             Protocol = 34  // Third Party Connect Protocol
	ProtocolIDPR            Protocol = 35  // Inter-Domain Policy Routing Protocol
	ProtocolXTP             Protocol = 36  // Xpress Tranfer Protocol
	ProtocolDDP             Protocol = 37  // Datagram Delivery Protocol
	ProtocolIDPR_CMTP       Protocol = 38  // IDPR Control Message Transport Proto
	ProtocolTPPlusPlus      Protocol = 39  // TP++; Transport Protocol
	ProtocolIL              Protocol = 40  // IL Transport Protocol
	ProtocolIPv6            Protocol = 41  // IPv6 encapsulation
	ProtocolSDRP            Protocol = 42  // Source Demand Routing Protocol
	ProtocolIPv6_Route      Protocol = 43  // Routing Header for IPv6
	ProtocolIPv6_Frag       Protocol = 44  // Fragment Header for IPv6
	ProtocolIDRP            Protocol = 45  // Inter-Domain Routing Protocol
	ProtocolRSVP            Protocol = 46  // Resource ReSerVation Protocol
	ProtocolGRE             Protocol = 47  // Generic Routing Encapsulation
	ProtocolDSR             Protocol = 48  // Dynamic Source Routing Protocol
	ProtocolBNA             Protocol = 49  // BNA
	ProtocolESP             Protocol = 50  // Encap Security Payload
	ProtocolIPv6_Crypt      Protocol = 50  // Encryption Header for IPv6 (not in official list)
	ProtocolAH              Protocol = 51  // Authentication Header
	ProtocolIPv6_Auth       Protocol = 51  // Authentication Header for IPv6 (not in official list)
	ProtocolI_NLSP          Protocol = 52  // Integrated Net Layer Security TUBA
	ProtocolSWIPE           Protocol = 53  // IP with Encryption
	ProtocolNARP            Protocol = 54  // NBMA Address Resolution Protocol
	ProtocolMOBILE          Protocol = 55  // IP Mobility
	ProtocolTLSP            Protocol = 56  // Transport Layer Security Protocol
	ProtocolSKIP            Protocol = 57  // SKIP
	ProtocolIPv6_ICMP       Protocol = 58  // ICMP for IPv6
	ProtocolIPv6_NoNxt      Protocol = 59  // No Next Header for IPv6
	ProtocolIPv6_Opts       Protocol = 60  // Destination Options for IPv6
	ProtocolCFTP            Protocol = 62  // CFTP
	ProtocolSAT_EXPAK       Protocol = 64  // SATNET and Backroom EXPAK
	ProtocolKRYPTOLAN       Protocol = 65  // Kryptolan
	ProtocolRVD             Protocol = 66  // MIT Remote Virtual Disk Protocol
	ProtocolIPPC            Protocol = 67  // Internet Pluribus Packet Core
	ProtocolSAT_MON         Protocol = 69  // SATNET Monitoring
	ProtocolVISA            Protocol = 70  // VISA Protocol
	ProtocolIPCV            Protocol = 71  // Internet Packet Core Utility
	ProtocolCPNX            Protocol = 72  // Computer Protocol Network Executive
	ProtocolCPHB            Protocol = 73  // Computer Protocol Heart Beat
	ProtocolWSN             Protocol = 74  // Wang Span Network
	ProtocolPVP             Protocol = 75  // Packet Video Protocol
	ProtocolBR_SAT_MON      Protocol = 76  // Backroom SATNET Monitoring
	ProtocolSUN_ND          Protocol = 77  // SUN ND PROTOCOL-Temporary
	ProtocolWB_MON          Protocol = 78  // WIDEBAND Monitoring
	ProtocolWB_EXPAK        Protocol = 79  // WIDEBAND EXPAK
	ProtocolISO_IP          Protocol = 80  // ISO Internet Protocol
	ProtocolVMTP            Protocol = 81  // Versatile Message Transport
	ProtocolSECURE_VMTP     Protocol = 82  // SECURE-VMTP
	ProtocolVINES           Protocol = 83  // VINES
	ProtocolTTP             Protocol = 84  // TTP
	ProtocolNSFNET_IGP      Protocol = 85  // NSFNET-IGP
	ProtocolDGP             Protocol = 86  // Dissimilar Gateway Protocol
	ProtocolTCF             Protocol = 87  // TCF
	ProtocolEIGRP           Protocol = 88  // Enhanced Interior Routing Protocol (Cisco)
	ProtocolOSPFIGP         Protocol = 89  // Open Shortest Path First IGP
	ProtocolSprite_RPC      Protocol = 90  // Sprite RPC Protocol
	ProtocolLARP            Protocol = 91  // Locus Address Resolution Protocol
	ProtocolMTP             Protocol = 92  // Multicast Transport Protocol
	ProtocolAXDot25         Protocol = 93  // AX.25 Frames
	ProtocolIPIP            Protocol = 94  // Yet Another IP encapsulation
	ProtocolMICP            Protocol = 95  // Mobile Internetworking Control Pro.
	ProtocolSCC_SP          Protocol = 96  // Semaphore Communications Sec. Pro.
	ProtocolETHERIP         Protocol = 97  // Ethernet-within-IP Encapsulation
	ProtocolENCAP           Protocol = 98  // Yet Another IP encapsulation
	ProtocolGMTP            Protocol = 100 // GMTP
	ProtocolIFMP            Protocol = 101 // Ipsilon Flow Management Protocol
	ProtocolPNNI            Protocol = 102 // PNNI over IP
	ProtocolPIM             Protocol = 103 // Protocol Independent Multicast
	ProtocolARIS            Protocol = 104 // ARIS
	ProtocolSCPS            Protocol = 105 // SCPS
	ProtocolQNX             Protocol = 106 // QNX
	ProtocolA_N             Protocol = 107 // Active Networks
	ProtocolIPComp          Protocol = 108 // IP Payload Compression Protocol
	ProtocolSNP             Protocol = 109 // Sitara Networks Protocol
	ProtocolCompaq_Peer     Protocol = 110 // Compaq Peer Protocol
	ProtocolIPX_in_IP       Protocol = 111 // IPX in IP
	ProtocolVRRP            Protocol = 112 // Virtual Router Redundancy Protocol
	ProtocolPGM             Protocol = 113 // PGM Reliable Transport Protocol
	ProtocolL2TP            Protocol = 115 // Layer Two Tunneling Protocol
	ProtocolDDX             Protocol = 116 // D-II Data Exchange
	ProtocolIATP            Protocol = 117 // Interactive Agent Transfer Protocol
	ProtocolSTP             Protocol = 118 // Schedule Transfer
	ProtocolSRP             Protocol = 119 // SpectraLink Radio Protocol
	ProtocolUTI             Protocol = 120 // UTI
	ProtocolSMP             Protocol = 121 // Simple Message Protocol
	ProtocolSM              Protocol = 122 // SM
	ProtocolPTP             Protocol = 123 // Performance Transparency Protocol
	ProtocolISIS            Protocol = 124 // ISIS over IPv4
	ProtocolFIRE            Protocol = 125 //
	ProtocolCRTP            Protocol = 126 // Combat Radio Transport Protocol
	ProtocolCRUDP           Protocol = 127 // Combat Radio User Datagram
	ProtocolSSCOPMCE        Protocol = 128 //
	ProtocolIPLT            Protocol = 129 //
	ProtocolSPS             Protocol = 130 // Secure Packet Shield
	ProtocolPIPE            Protocol = 131 // Private IP Encapsulation within IP
	ProtocolSCTP            Protocol = 132 // Stream Control Transmission Protocol
	ProtocolFC              Protocol = 133 // Fibre Channel
	ProtocolRSVP_E2E_IGNORE Protocol = 134 //
	ProtocolMobility_Header Protocol = 135 // Mobility Header
	ProtocolUDPLite         Protocol = 136 //
	ProtocolMPLS_in_IP      Protocol = 137 //
	Protocolmanet           Protocol = 138 // MANET Protocols
	ProtocolHIP             Protocol = 139 // Host Identity Protocol
	ProtocolShim6           Protocol = 140 // Shim6 Protocol
	ProtocolWESP            Protocol = 141 // Wrapped Encapsulating Security Payload
	ProtocolROHC            Protocol = 142 // Robust Header Compression
)
