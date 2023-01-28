package network

import "strconv"

type ICMPv6Type ICMPType

func (typ ICMPv6Type) String() string {
	return strconv.Itoa(int(typ))
}

type ICMPv6Code ICMPCode // we need -1 to present existence.

func (code ICMPv6Code) String() string {
	return strconv.Itoa(int(code))
}

// refer to github.com/google/gopacket
const (
	// The following are from RFC 4443
	ICMPv6TypeNull                   ICMPv6Type = 0
	ICMPv6TypeDestinationUnreachable ICMPv6Type = 1
	ICMPv6TypePacketTooBig           ICMPv6Type = 2
	ICMPv6TypeTimeExceeded           ICMPv6Type = 3
	ICMPv6TypeParameterProblem       ICMPv6Type = 4
	ICMPv6TypeEchoRequest            ICMPv6Type = 128
	ICMPv6TypePing                   ICMPv6Type = 128
	ICMPv6TypeEchoReply              ICMPv6Type = 129
	ICMPv6TypePong                   ICMPv6Type = 129

	// The following are from RFC 4861
	ICMPv6TypeRouterSolicitation     ICMPv6Type = 133
	ICMPv6TypeRouterAdvertisement    ICMPv6Type = 134
	ICMPv6TypeNeighbourSolicitation  ICMPv6Type = 135
	ICMPv6TypeNeighborSolicitation   ICMPv6Type = 135
	ICMPv6TypeNeighbourAdvertisement ICMPv6Type = 136
	ICMPv6TypeNeighborAdvertisement  ICMPv6Type = 136
	ICMPv6TypeRedirect               ICMPv6Type = 137

	// The following are from RFC 2710
	ICMPv6TypeMLDv1MulticastListenerQueryMessage  ICMPv6Type = 130
	ICMPv6TypeMLDv1MulticastListenerReportMessage ICMPv6Type = 131
	ICMPv6TypeMLDv1MulticastListenerDoneMessage   ICMPv6Type = 132

	// The following are from RFC 3810
	ICMPv6TypeMLDv2MulticastListenerReportMessageV2 ICMPv6Type = 143
)

const (
	ICMPv6CodeNull ICMPv6Code = 0
	// DestinationUnreachable
	ICMPv6CodeNoRouteToDst            ICMPv6Code = 0
	ICMPv6CodeAdminProhibited         ICMPv6Code = 1
	ICMPv6CodeCommunicationProhibited ICMPv6Code = 1
	ICMPv6CodeBeyondScopeOfSrc        ICMPv6Code = 2
	ICMPv6CodeAddressUnreachable      ICMPv6Code = 3
	ICMPv6CodePortUnreachable         ICMPv6Code = 4
	ICMPv6CodeSrcAddressFailedPolicy  ICMPv6Code = 5
	ICMPv6CodeRejectRouteToDst        ICMPv6Code = 6

	// TimeExceeded
	ICMPv6CodeHopLimitExceeded               ICMPv6Code = 0
	ICMPv6CodeFragmentReassemblyTimeExceeded ICMPv6Code = 1

	// ParameterProblem
	ICMPv6CodeErroneousHeaderField   ICMPv6Code = 0
	ICMPv6CodeUnrecognizedNextHeader ICMPv6Code = 1
	ICMPv6CodeUnrecognizedIPv6Option ICMPv6Code = 2
)

var (
	ICMPv6TypeMap = map[string]ICMPv6Type{
		"destination-unreachable": ICMPv6TypeDestinationUnreachable,
		"packet-too-big":          ICMPv6TypePacketTooBig,
		"time-exceeded":           ICMPv6TypeTimeExceeded,
		"parameter-problem":       ICMPv6TypeParameterProblem,
		"echo-request":            ICMPv6TypeEchoRequest,
		"ping":                    ICMPv6TypePing,
		"echo-reply":              ICMPv6TypeEchoReply,
		"pong":                    ICMPv6TypePong,
		"router-solicitation":     ICMPv6TypeRouterSolicitation,
		"router-advertisement":    ICMPv6TypeRouterAdvertisement,
		"neighbour-solicitation":  ICMPv6TypeNeighbourSolicitation,
		"neighbor-solicitation":   ICMPv6TypeNeighborSolicitation,
		"neighbour-advertisement": ICMPv6TypeNeighbourAdvertisement,
		"neighbor-advertisement":  ICMPv6TypeNeighborAdvertisement,
		"redirect":                ICMPv6TypeRedirect,
	}

	ICMPv6CodeMap = map[string]ICMPv6Code{
		"no-route":                   ICMPv6CodeNoRouteToDst,
		"communication-prohibited":   ICMPv6CodeAdminProhibited,
		"beyond-scope":               ICMPv6CodeBeyondScopeOfSrc,
		"address-unreachable":        ICMPv6CodeAddressUnreachable,
		"port-unreachable":           ICMPv6CodePortUnreachable,
		"failed-policy":              ICMPv6CodeSrcAddressFailedPolicy,
		"reject-route":               ICMPv6CodeRejectRouteToDst,
		"ttl-zero-during-transit":    ICMPv6CodeHopLimitExceeded,
		"ttl-zero-during-reassembly": ICMPv6CodeFragmentReassemblyTimeExceeded,
		"bad-header":                 ICMPv6CodeErroneousHeaderField,
		"unknown-header-type":        ICMPv6CodeUnrecognizedNextHeader,
		"unknown-option":             ICMPv6CodeUnrecognizedIPv6Option,
	}

	ICMPv6Codes = map[string]struct {
		Code ICMPv6Code
		Type ICMPv6Type
	}{
		"no-route": struct {
			Code ICMPv6Code
			Type ICMPv6Type
		}{ICMPv6CodeNoRouteToDst, ICMPv6TypeDestinationUnreachable},
		"communication-prohibited": struct {
			Code ICMPv6Code
			Type ICMPv6Type
		}{ICMPv6CodeCommunicationProhibited, ICMPv6TypeDestinationUnreachable},
		"beyond-scope": struct {
			Code ICMPv6Code
			Type ICMPv6Type
		}{ICMPv6CodeBeyondScopeOfSrc, ICMPv6TypeDestinationUnreachable},
		"address-unreachable": struct {
			Code ICMPv6Code
			Type ICMPv6Type
		}{ICMPv6CodeAddressUnreachable, ICMPv6TypeDestinationUnreachable},
		"port-unreachable": struct {
			Code ICMPv6Code
			Type ICMPv6Type
		}{ICMPv6CodePortUnreachable, ICMPv6TypeDestinationUnreachable},
		"failed-policy": struct {
			Code ICMPv6Code
			Type ICMPv6Type
		}{ICMPv6CodeSrcAddressFailedPolicy, ICMPv6TypeDestinationUnreachable},
		"reject-route": struct {
			Code ICMPv6Code
			Type ICMPv6Type
		}{ICMPv6CodeRejectRouteToDst, ICMPv6TypeDestinationUnreachable},
		"ttl-zero-during-transit": struct {
			Code ICMPv6Code
			Type ICMPv6Type
		}{ICMPv6CodeHopLimitExceeded, ICMPv6TypeTimeExceeded},
		"ttl-zero-during-reassembly": struct {
			Code ICMPv6Code
			Type ICMPv6Type
		}{ICMPv6CodeFragmentReassemblyTimeExceeded, ICMPv6TypeTimeExceeded},
		"bad-header": struct {
			Code ICMPv6Code
			Type ICMPv6Type
		}{ICMPv6CodeErroneousHeaderField, ICMPv6TypeParameterProblem},
		"unknown-header-type": struct {
			Code ICMPv6Code
			Type ICMPv6Type
		}{ICMPv6CodeUnrecognizedNextHeader, ICMPv6TypeParameterProblem},
		"unknown-option": struct {
			Code ICMPv6Code
			Type ICMPv6Type
		}{ICMPv6CodeUnrecognizedIPv6Option, ICMPv6TypeParameterProblem},
	}
)
