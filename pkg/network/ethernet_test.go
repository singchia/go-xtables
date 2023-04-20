package network

import "testing"

func TestEthernetType(t *testing.T) {
	maps := map[EthernetType]string{
		EthernetTypeLLC:                         "0x0000",
		EthernetTypeIPv4:                        "0x0800",
		EthernetTypeX25:                         "0x0805",
		EthernetTypeARP:                         "0x0806",
		EthernetTypeFR_ARP:                      "0x0808",
		EthernetTypeBPQ:                         "0x08ff",
		EthernetTypeDEC:                         "0x6000",
		EthernetTypeDNA_DL:                      "0x6001",
		EthernetTypeDNA_RC:                      "0x6002",
		EthernetTypeDNA_RT:                      "0x6003",
		EthernetTypeLAT:                         "0x6004",
		EthernetTypeDIAG:                        "0x6005",
		EthernetTypeCUST:                        "0x6006",
		EthernetTypeSCA:                         "0x6007",
		EthernetTypeRAW_FR:                      "0x6559",
		EthernetTypeAARP:                        "0x80f3",
		EthernetTypeATALK:                       "0x808b",
		EthernetType802_1Q:                      "0x8100",
		EthernetTypeIPX:                         "0x8137",
		EthernetTypeNetBEUI:                     "0x8191",
		EthernetTypeIPv6:                        "0x8dd6",
		EthernetTypeCiscoDiscovery:              "0x2000",
		EthernetTypeNortelDiscovery:             "0x01a2",
		EthernetTypeTransparentEthernetBridging: "0x6558",
		EthernetTypePPP:                         "0x880b",
		EthernetTypePPPoEDiscovery:              "0x8863",
		EthernetTypePPPoESession:                "0x8864",
		EthernetTypeMPLSUnicast:                 "0x8847",
		EthernetTypeATMMPOA:                     "0x884c",
		EthernetTypeMPLSMulticast:               "0x8848",
		EthernetTypeATMFATE:                     "0x8884",
		EthernetTypeEAPOL:                       "0x888e",
		EthernetTypeERSPAN:                      "0x88be",
		EthernetTypeQinQ:                        "0x88a8",
		EthernetTypeLinkLayerDiscovery:          "0x88cc",
		EthernetTypeEthernetCTP:                 "0x9000",
	}
	for k, v := range maps {
		if k.String() != v {
			t.Error("unmatched ethernet type", k.String(), v)
			return
		}
	}
}
