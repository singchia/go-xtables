package network

import (
	"strconv"
)

// refer to github.com/google/gopacket and iana arp-parameters.
// HardwareType is an enumeration of link types, and acts as a decoder for any
// link type it supports.
type HardwareType uint16

func (hwType HardwareType) String() string {
	return strconv.Itoa(int(hwType))
}

func (hwType HardwareType) Hex() [2]byte {
	buf := [2]byte{}
	// little endian
	buf[0] = byte(hwType)
	buf[1] = byte(hwType >> 8)
	return buf
}

const (
	// According to pcap-linktype(7) and http://www.tcpdump.org/linktypes.html
	HardwareTypeNull                   HardwareType = 0
	HardwareTypeEthernet               HardwareType = 1
	HardwareTypeExperimentalEthernet   HardwareType = 2
	HardwareTypeAX25                   HardwareType = 3
	HardwareTypeProteonProNETTokenRing HardwareType = 4
	HardwareTypeChaos                  HardwareType = 5
	HardwareTypeTokenRing              HardwareType = 6
	HardwareTypeArcNet                 HardwareType = 7
	HardwareTypeSLIP                   HardwareType = 8
	HardwareTypePPP                    HardwareType = 9
	HardwareTypeFDDI                   HardwareType = 10
	HardwareTypeLocalTalk              HardwareType = 11
	HardwareTypeLocalNet               HardwareType = 12
	HardwareTypeUltralink              HardwareType = 13
	HardwareTypeSMDS                   HardwareType = 14
	HardwareTypeFrameRelay             HardwareType = 15
	HardwareTypeATM16                  HardwareType = 16
	HardwareTypeHDLC                   HardwareType = 17
	HardwareTypeFibreChannel           HardwareType = 18
	HardwareTypeATM19                  HardwareType = 19
	HardwareTypeSerialline             HardwareType = 20
	HardwareTypeATM21                  HardwareType = 21
	HardwareTypePPP_HDLC               HardwareType = 50
	HardwareTypePPPEthernet            HardwareType = 51
	HardwareTypeATM_RFC1483            HardwareType = 100
	HardwareTypeRaw                    HardwareType = 101
	HardwareTypeC_HDLC                 HardwareType = 104
	HardwareTypeIEEE802_11             HardwareType = 105
	HardwareTypeFRelay                 HardwareType = 107
	HardwareTypeLoop                   HardwareType = 108
	HardwareTypeLinuxSLL               HardwareType = 113
	HardwareTypeLTalk                  HardwareType = 114
	HardwareTypePFLog                  HardwareType = 117
	HardwareTypePrismHeader            HardwareType = 119
	HardwareTypeIPOverFC               HardwareType = 122
	HardwareTypeSunATM                 HardwareType = 123
	HardwareTypeIEEE80211Radio         HardwareType = 127
	HardwareTypeARCNetLinux            HardwareType = 129
	HardwareTypeIPOver1394             HardwareType = 138
	HardwareTypeMTP2Phdr               HardwareType = 139
	HardwareTypeMTP2                   HardwareType = 140
	HardwareTypeMTP3                   HardwareType = 141
	HardwareTypeSCCP                   HardwareType = 142
	HardwareTypeDOCSIS                 HardwareType = 143
	HardwareTypeLinuxIRDA              HardwareType = 144
	HardwareTypeLinuxLAPD              HardwareType = 177
	HardwareTypeLinuxUSB               HardwareType = 220
	HardwareTypeFC2                    HardwareType = 224
	HardwareTypeFC2Framed              HardwareType = 225
	HardwareTypeIPv4                   HardwareType = 228
	HardwareTypeIPv6                   HardwareType = 229
	HardwareTypeAEthernet              HardwareType = 257
)
