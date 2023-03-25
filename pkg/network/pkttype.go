package network

import "errors"

type PktType int

func (pktType PktType) String() string {
	switch pktType {
	case PktTypeUnicast:
		return "unicast"
	case PktTypeBroadcast:
		return "broadcast"
	case PktTypeMulticast:
		return "multicast"
	case PktTypeHost:
		return "host"
	case PktTypeOtherHost:
		return "otherhost"
	default:
		return ""
	}
}

const (
	PktTypeUnicast PktType = 1 << iota
	PktTypeBroadcast
	PktTypeMulticast
	PktTypeHost
	PktTypeOtherHost
)

func ParsePktType(typ string) (PktType, error) {
	switch typ {
	case "unicast":
		return PktTypeUnicast, nil
	case "broadcast":
		return PktTypeBroadcast, nil
	case "multicast":
		return PktTypeMulticast, nil
	case "host":
		return PktTypeHost, nil
	case "otherhost":
		return PktTypeOtherHost, nil
	}
	return 0, errors.New("unknown pkt type")
}
