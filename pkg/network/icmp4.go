package network

import "strconv"

type ICMPType int

func (typ ICMPType) String() string {
	return strconv.Itoa(int(typ))
}

type ICMPCode int

func (code ICMPCode) String() string {
	return strconv.Itoa(int(code))
}

type ICMP4Type ICMPType

const (
	Any                    ICMP4Type = 255
	EchoReqply             ICMP4Type = 0
	Pong                   ICMP4Type = 0
	DestinationUnreachable ICMP4Type = 3
	SourceQuench           ICMP4Type = 4
	Redirect               ICMP4Type = 5
	EchoRequest            ICMP4Type = 8
	Ping                   ICMP4Type = 8
	RouterAdvertisement    ICMP4Type = 9
	RouterSolicitation     ICMP4Type = 10
	TimeExceeded           ICMP4Type = 11
	TTLExceeded            ICMP4Type = 11
	ParameterProblem       ICMP4Type = 12
	TimestampRequest       ICMP4Type = 13
	TimestampReply         ICMP4Type = 14
	AddressMaskRequest     ICMP4Type = 17
	AddressMaskReply       ICMP4Type = 18
)

var (
	ICMP4Types = map[string]ICMP4Type{
		"any":                     Any,
		"echo-reply":              EchoReqply,
		"pong":                    Pong,
		"destination-unreachable": DestinationUnreachable,
		"source-quench":           SourceQuench,
		"redirect":                Redirect,
		"echo-request":            EchoRequest,
		"ping":                    Ping,
		"router-advertisement":    RouterAdvertisement,
		"router-solicitation":     RouterSolicitation,
		"time-exceeded":           TimeExceeded,
		"ttl-exceeded":            TTLExceeded,
		"parameter-problem":       ParameterProblem,
		"timestamp-request":       TimestampRequest,
		"timestamp-reply":         TimestampReply,
		"address-mask-request":    AddressMaskRequest,
		"address-mask-reply":      AddressMaskReply,
	}
)

type ICMP4Code ICMPCode

const (
	// destination unreachable
	NetworkUnreachable       ICMP4Code = 0
	HostUnreachable          ICMP4Code = 1
	ProtocolUnreachable      ICMP4Code = 2
	PortUnreachable          ICMP4Code = 3
	FragmentationUnreachable ICMP4Code = 4
	SourceRouteFailed        ICMP4Code = 5
	NetworkUnknown           ICMP4Code = 6
	HostUnknown              ICMP4Code = 7
	NetworkProhibited        ICMP4Code = 9
	HostProhibited           ICMP4Code = 10
	TOSNetworkUnreachable    ICMP4Code = 11
	TOSHostUnreachable       ICMP4Code = 12
	CommunicationProhibited  ICMP4Code = 13
	HostPrecedenceViolation  ICMP4Code = 14
	PrecedenceCutoff         ICMP4Code = 15
	// redirect
	NetworkRedirect    ICMP4Code = 0
	HostRedirect       ICMP4Code = 1
	TOSNetworkRedirect ICMP4Code = 2
	TOSHostRedirect    ICMP4Code = 3
	// time exceeded
	TTLZeroDuringTransit    ICMP4Code = 0
	TTLZeroDuringReassembly ICMP4Code = 0
	// parameter problem
	IPHeaderBad           ICMP4Code = 0
	RequiredOptionMissing ICMP4Code = 1
)

var (
	ICMP4Codes = map[string]struct {
		Code ICMP4Code
		Type ICMP4Type
	}{
		"network-unreachable": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{NetworkUnreachable, DestinationUnreachable},
		"host-unreachable": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{HostUnreachable, DestinationUnreachable},
		"protocol-unreachable": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{ProtocolUnreachable, DestinationUnreachable},
		"port-unreachable": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{PortUnreachable, DestinationUnreachable},
		"fragmentation-needed": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{FragmentationUnreachable, DestinationUnreachable},
		"source-route-failed": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{SourceRouteFailed, DestinationUnreachable},
		"network-unknown": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{NetworkUnknown, DestinationUnreachable},
		"host-unknown": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{HostUnknown, DestinationUnreachable},
		"network-prohibited": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{NetworkProhibited, DestinationUnreachable},
		"host-prohibited": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{HostProhibited, DestinationUnreachable},
		"TOS-network-unreachable": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{TOSNetworkUnreachable, DestinationUnreachable},
		"TOS-host-unreachable": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{TOSHostUnreachable, DestinationUnreachable},
		"communication-prohibited": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{CommunicationProhibited, DestinationUnreachable},
		"host-precedence-violation": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{HostPrecedenceViolation, DestinationUnreachable},
		"precedence-cutoff": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{PrecedenceCutoff, DestinationUnreachable},
		"network-redirect": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{NetworkRedirect, Redirect},
		"host-redirect": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{HostRedirect, Redirect},
		"TOS-network-redirect": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{TOSNetworkRedirect, Redirect},
		"TOS-host-redirect": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{TOSHostRedirect, Redirect},
		"ttl-zero-during-transit": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{TTLZeroDuringTransit, TimeExceeded},
		"ttl-zero-during-reassembly": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{TTLZeroDuringReassembly, TimeExceeded},
		"ip-header-bad": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{IPHeaderBad, ParameterProblem},
		"required-option-missing": struct {
			Code ICMP4Code
			Type ICMP4Type
		}{RequiredOptionMissing, ParameterProblem},
	}
)
