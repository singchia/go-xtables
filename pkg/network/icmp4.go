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
	EchoReply              ICMP4Type = 0
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
		"echo-reply":              EchoReply,
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
		"network-unreachable":        {NetworkUnreachable, DestinationUnreachable},
		"host-unreachable":           {HostUnreachable, DestinationUnreachable},
		"protocol-unreachable":       {ProtocolUnreachable, DestinationUnreachable},
		"port-unreachable":           {PortUnreachable, DestinationUnreachable},
		"fragmentation-needed":       {FragmentationUnreachable, DestinationUnreachable},
		"source-route-failed":        {SourceRouteFailed, DestinationUnreachable},
		"network-unknown":            {NetworkUnknown, DestinationUnreachable},
		"host-unknown":               {HostUnknown, DestinationUnreachable},
		"network-prohibited":         {NetworkProhibited, DestinationUnreachable},
		"host-prohibited":            {HostProhibited, DestinationUnreachable},
		"TOS-network-unreachable":    {TOSNetworkUnreachable, DestinationUnreachable},
		"TOS-host-unreachable":       {TOSHostUnreachable, DestinationUnreachable},
		"communication-prohibited":   {CommunicationProhibited, DestinationUnreachable},
		"host-precedence-violation":  {HostPrecedenceViolation, DestinationUnreachable},
		"precedence-cutoff":          {PrecedenceCutoff, DestinationUnreachable},
		"network-redirect":           {NetworkRedirect, Redirect},
		"host-redirect":              {HostRedirect, Redirect},
		"TOS-network-redirect":       {TOSNetworkRedirect, Redirect},
		"TOS-host-redirect":          {TOSHostRedirect, Redirect},
		"ttl-zero-during-transit":    {TTLZeroDuringTransit, TimeExceeded},
		"ttl-zero-during-reassembly": {TTLZeroDuringReassembly, TimeExceeded},
		"ip-header-bad":              {IPHeaderBad, ParameterProblem},
		"required-option-missing":    {RequiredOptionMissing, ParameterProblem},
	}
)
