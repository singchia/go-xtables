package network

import (
	"fmt"
	"strconv"
)

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
	EthernetTypeRARP                        EthernetType = 0x8035 // RARP
	EthernetTypeATALK                       EthernetType = 0x808b // Appletalk
	EthernetTypeAARP                        EthernetType = 0x80f3 // Appletalk AARP
	EthernetType802_1Q                      EthernetType = 0x8100 // 802.1Q Virtual LAN tagged frame
	EthernetTypeIPX                         EthernetType = 0x8137 // Novell IPX
	EthernetTypeNetBEUI                     EthernetType = 0x8191
	EthernetTypeIPv6                        EthernetType = 0x8dd6
	EthernetTypeCiscoDiscovery              EthernetType = 0x2000
	EthernetTypeNortelDiscovery             EthernetType = 0x01a2
	EthernetTypeTransparentEthernetBridging EthernetType = 0x6558
	EthernetTypePPP                         EthernetType = 0x880b
	EthernetTypeMPLS                        EthernetType = 0x8847
	EthernetTypeMPLS_UNICAST                EthernetType = 0x8847
	EthernetTypeMPLSMulticast               EthernetType = 0x8848
	EthernetTypeMPLS_MULTI                  EthernetType = 0x8848
	EthernetTypeATMMPOA                     EthernetType = 0x884c
	EthernetTypePPP_DISC                    EthernetType = 0x8863
	EthernetTypePPPoEDiscovery              EthernetType = 0x8863 // PPPoE discoverty messages
	EthernetTypePPP_SES                     EthernetType = 0x8864
	EthernetTypePPPoESession                EthernetType = 0x8864 // PPPoE session messages
	EthernetTypeATMFATE                     EthernetType = 0x8884 // Frame-based ATM Transport over Ethernet
	EthernetTypeEAPOL                       EthernetType = 0x888e
	EthernetTypeERSPAN                      EthernetType = 0x88be
	EthernetTypeS_TAG                       EthernetType = 0x88a8
	EthernetTypeQinQ                        EthernetType = 0x88a8
	EthernetTypeEAP_PREAUTH                 EthernetType = 0x88c7
	EthernetTypeLLDP                        EthernetType = 0x88cc
	EthernetTypeLinkLayerDiscovery          EthernetType = 0x88cc
	EthernetTypeMACSEC                      EthernetType = 0x88e5
	EthernetTypePBB                         EthernetType = 0x88e7
	EthernetTypeMVRP                        EthernetType = 0x88f5
	EthernetTypePTP                         EthernetType = 0x88f7
	EthernetTypeFCOE                        EthernetType = 0x8906
	EthernetTypeFIP                         EthernetType = 0x8914
	EthernetTypeROCE                        EthernetType = 0x8915
	EthernetTypeEthernetCTP                 EthernetType = 0x9000
)

var (
	EthernetTypes = map[string]EthernetType{
		"IPv4":                        EthernetTypeIPv4,
		"X25":                         EthernetTypeX25,
		"ARP":                         EthernetTypeARP,
		"FR_ARP":                      EthernetTypeFR_ARP,
		"BPQ":                         EthernetTypeBPQ,
		"DEC":                         EthernetTypeDEC,
		"DNA_DL":                      EthernetTypeDNA_DL,
		"DNA_RC":                      EthernetTypeDNA_RC,
		"DNA_RT":                      EthernetTypeDNA_RT,
		"LAT":                         EthernetTypeLAT,
		"DIAG":                        EthernetTypeDIAG,
		"CUST":                        EthernetTypeCUST,
		"SCA":                         EthernetTypeSCA,
		"RAW_FR":                      EthernetTypeRAW_FR,
		"RARP":                        EthernetTypeRARP,
		"ATALK":                       EthernetTypeATALK,
		"802_1Q":                      EthernetType802_1Q,
		"IPX":                         EthernetTypeIPX,
		"NetBEUI":                     EthernetTypeNetBEUI,
		"IPv6":                        EthernetTypeIPv6,
		"CiscoDiscovery":              EthernetTypeCiscoDiscovery,
		"NortelDiscovery":             EthernetTypeNortelDiscovery,
		"TransparentEthernetBridging": EthernetTypeTransparentEthernetBridging,
		"PPP":                         EthernetTypePPP,
		"MPLS":                        EthernetTypeMPLS,
		"MPLS_UNICAST":                EthernetTypeMPLS_UNICAST,
		"MPLSMulticast":               EthernetTypeMPLSMulticast,
		"MPLS_MULTI":                  EthernetTypeMPLS_MULTI,
		"ATMMPOA":                     EthernetTypeATMMPOA,
		"PPP_DISC":                    EthernetTypePPP_DISC,
		"PPPoeDiscovery":              EthernetTypePPPoEDiscovery,
		"PPP_SES":                     EthernetTypePPP_SES,
		"PPPoeSession":                EthernetTypePPPoESession,
		"ATMFATE":                     EthernetTypeATMFATE,
		"EAPOL":                       EthernetTypeEAPOL,
		"ERSPAN":                      EthernetTypeERSPAN,
		"S_TAG":                       EthernetTypeS_TAG,
		"QinQ":                        EthernetTypeQinQ,
		"EAP_PREAUTH":                 EthernetTypeEAP_PREAUTH,
		"LLDP":                        EthernetTypeLinkLayerDiscovery,
		"MACSEC":                      EthernetTypeMACSEC,
		"PBB":                         EthernetTypePBB,
		"MVRP":                        EthernetTypeMVRP,
		"PTP":                         EthernetTypePTP,
		"FCOE":                        EthernetTypeFCOE,
		"FIP":                         EthernetTypeFIP,
		"ROCE":                        EthernetTypeROCE,
		"EthernetTCP":                 EthernetTypeEthernetCTP,
	}
)

func ParseEthernetType(etype string) (EthernetType, error) {
	typ, err := strconv.ParseUint(etype, 10, 16)
	if err == nil {
		return EthernetType(typ), nil
	}
	value, ok := EthernetTypes[etype]
	if ok {
		return value, nil
	}
	return 0, err
}
