package network

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
