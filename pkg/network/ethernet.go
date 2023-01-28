package network

import "fmt"

// refer to github.com/google/gopacket and /etc/ethertypes
type EthernetType uint16

func (ethernetType EthernetType) String() string {
	return fmt.Sprintf("0x%04x", uint16(ethernetType))
}

const (
	// EthernetTypeLLC is not an actual ethernet type.  It is instead a
	// placeholder we use in Ethernet frames that use the 802.3 standard of
	// srcmac|dstmac|length|LLC instead of srcmac|dstmac|ethertype.
	EthernetTypeLLC                         EthernetType = 0x0000
	EthernetTypeIPv4                        EthernetType = 0x0800
	EthernetTypeX25                         EthernetType = 0x0805
	EthernetTypeARP                         EthernetType = 0x0806
	EthernetTypeFR_ARP                      EthernetType = 0x0808 // Frame Relay ARP [RFC1701]
	EthernetTypeBPQ                         EthernetType = 0x08ff // G8BPQ AX.25 Ethernet Packet
	EthernetTypeDEC                         EthernetType = 0x6000 // DEC Assigned proto
	EthernetTypeDNA_DL                      EthernetType = 0x6001 // DEC DNA Dump/Load
	EthernetTypeDNA_RC                      EthernetType = 0x6002 // DEC DNA Remote Console
	EthernetTypeDNA_RT                      EthernetType = 0x6003 // DEC DNA Routing
	EthernetTypeLAT                         EthernetType = 0x6004 // DEC LAT
	EthernetTypeDIAG                        EthernetType = 0x6005 // DEC Diagnostics
	EthernetTypeCUST                        EthernetType = 0x6006 // DEC Customer use
	EthernetTypeSCA                         EthernetType = 0x6007 // DEC Systems Comms Arch
	EthernetTypeRAW_FR                      EthernetType = 0x6559 // Raw Frame Relay [RFC1701]
	EthernetTypeAARP                        EthernetType = 0x80f3 // Appletalk AARP
	EthernetTypeATALK                       EthernetType = 0x808b // Appletalk
	EthernetType802_1Q                      EthernetType = 0x8100 // 802.1Q Virtual LAN tagged frame
	EthernetTypeIPX                         EthernetType = 0x8137 // Novell IPX
	EthernetTypeNetBEUI                     EthernetType = 0x8191
	EthernetTypeIPv6                        EthernetType = 0x8dd6
	EthernetTypeCiscoDiscovery              EthernetType = 0x2000
	EthernetTypeNortelDiscovery             EthernetType = 0x01a2
	EthernetTypeTransparentEthernetBridging EthernetType = 0x6558
	EthernetTypePPP                         EthernetType = 0x880b
	EthernetTypeMPLSUnicast                 EthernetType = 0x8847
	EthernetTypeATMMPOA                     EthernetType = 0x884c
	EthernetTypeMPLSMulticast               EthernetType = 0x8848
	EthernetTypePPPoEDiscovery              EthernetType = 0x8863 // PPPoE discoverty messages
	EthernetTypePPPoESession                EthernetType = 0x8864 // PPPoE session messages
	EthernetTypeATMFATE                     EthernetType = 0x8884 // Frame-based ATM Transport over Ethernet
	EthernetTypeEAPOL                       EthernetType = 0x888e
	EthernetTypeERSPAN                      EthernetType = 0x88be
	EthernetTypeQinQ                        EthernetType = 0x88a8
	EthernetTypeLinkLayerDiscovery          EthernetType = 0x88cc
	EthernetTypeEthernetCTP                 EthernetType = 0x9000
)
