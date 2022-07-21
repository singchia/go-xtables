package iptables

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Rate struct {
	Rate int
	Unit Unit
}

func (rate Rate) String() string {
	unit := "second"
	switch rate.Unit {
	case Minute:
		unit = "minute"
	case Hour:
		unit = "hour"
	case Day:
		unit = "day"
	default:
		return ""
	}
	return strconv.Itoa(rate.Rate) + "/" + unit
}

type RateFloat struct {
	Rate float64
	Unit Unit
}

func (rateFloat RateFloat) Sting() string {
	unit := "second"
	switch rateFloat.Unit {
	case Microsecond:
		unit = "us"
	case Millisecond:
		unit = "ms"
	case Second:
		unit = "s"
	default:
		return ""
	}
	return strconv.FormatFloat(rateFloat.Rate, 'f', 2, 64) + unit
}

type PortRange struct {
	Start int
	End   int
}

type Dir int

func (dir Dir) String() string {
	switch dir {
	case In:
		return "in"
	case Out:
		return "out"
	default:
		return ""
	}
}

const (
	In Dir = 1 << iota
	Out
)

type MatchRange int

func (matchRange MatchRange) String() string {
	switch matchRange {
	case ANY:
		return "any"
	case ALL:
		return "all"
	case ONLY:
		return "only"
	default:
		return ""
	}
}

const (
	_ MatchRange = iota
	ANY
	ALL
	ONLY
)

// TCP related
type TCPFlag int

func (tcpFlag TCPFlag) String() string {
	flag := ""
	sep := ""
	if tcpFlag&TCPFlagFIN != 0 {
		flag += sep + "FIN"
		sep = ","
	}
	if tcpFlag&TCPFlagSYN != 0 {
		flag += sep + "SYN"
		sep = ","
	}
	if tcpFlag&TCPFlagRST != 0 {
		flag += sep + "RST"
		sep = ","
	}
	if tcpFlag&TCPFlagPSH != 0 {
		flag += sep + "PSH"
		sep = ","
	}
	if tcpFlag&TCPFlagACK != 0 {
		flag += sep + "ACK"
		sep = ","
	}
	if tcpFlag&TCPFlagURG != 0 {
		flag += sep + "URG"
		sep = ","
	}
	return flag
}

const (
	TCPFlagFIN TCPFlag = 1 << iota
	TCPFlagSYN
	TCPFlagRST
	TCPFlagPSH
	TCPFlagACK
	TCPFlagURG
	TCPFlagALL  TCPFlag = TCPFlagFIN | TCPFlagSYN | TCPFlagRST | TCPFlagPSH | TCPFlagACK | TCPFlagURG
	TCPFlagNONE TCPFlag = 0
)

var (
	TCPFlags = map[string]TCPFlag{
		"NONE": TCPFlagNONE,
		"FIN":  TCPFlagFIN,
		"SYN":  TCPFlagSYN,
		"RST":  TCPFlagRST,
		"PSH":  TCPFlagPSH,
		"ACK":  TCPFlagACK,
		"URG":  TCPFlagURG,
		"ALL":  TCPFlagALL,
	}
)

type TCPOpt uint8

const (
	TCPOptMD5           TCPOpt = 19
	TCPOptMSS           TCPOpt = 2
	TCPOptWindowScale   TCPOpt = 3
	TCPOptSACKPermitted TCPOpt = 4
	TCPOptSACK          TCPOpt = 5
	TCPOptTimestamp     TCPOpt = 8
)

var (
	TCPOpts = map[string]TCPOpt{
		"wscale":         TCPOptWindowScale,
		"mss":            TCPOptMSS,
		"sack-permitted": TCPOptSACKPermitted,
		"sack":           TCPOptSACK,
		"timestamp":      TCPOptTimestamp,
		"md5":            TCPOptMD5,
	}
)

// time related
type Unit int

const (
	_ Unit = iota
	Microsecond
	Millisecond
	Second
	Minute
	Hour
	Day
	BPS  // bytes per second
	KBPS // kilo bytes per second
	MBPS // million bytes per second
)

type Daytime struct {
	Hour   int8
	Minute int8
	Second int8
	sets   int
}

func (dt *Daytime) String() string {
	daytime := ""
	sep := ""
	if dt.Hour >= 0 && dt.Hour <= 23 {
		daytime += sep + fmt.Sprintf("%2d", dt.Hour)
		sep = ":"
		dt.sets += 1
	}
	if dt.Minute >= 0 && dt.Minute <= 59 {
		daytime += sep + fmt.Sprintf("%2d", dt.Minute)
		sep = ":"
		dt.sets += 1
	}
	if dt.Second >= 0 && dt.Second <= 59 {
		daytime += sep + fmt.Sprintf("%2d", dt.Second)
		sep = ":"
		dt.sets += 1
	}
	return daytime
}

func ParseDaytime(daytime string) (*Daytime, error) {
	dt := &Daytime{-1, -1, -1, 0}
	err := error(nil)
	parts := strings.Split(daytime, ":")
	if len(parts) != 3 {
		err = errors.New("wrong elems")
		return dt, err
	}
	for index, part := range parts {
		switch index {
		case 0:
			hour, err := strconv.ParseInt(part, 10, 8)
			if err != nil {
				return dt, err
			}
			dt.Hour = int8(hour)
		case 1:
			minute, err := strconv.ParseInt(part, 10, 8)
			if err != nil {
				return dt, err
			}
			dt.Minute = int8(minute)
		case 2:
			second, err := strconv.ParseInt(part, 10, 8)
			if err != nil {
				return dt, err
			}
			dt.Second = int8(second)
		}
	}
	return dt, nil
}

type Yeartime struct {
	Year  int16
	Month int8
	Day   int8
	sets  int
}

func (yt *Yeartime) String() string {
	yeartime := ""
	sep := ""
	if yt.Year > -1 {
		yeartime += sep + fmt.Sprintf("%4d", yt.Year)
		sep = ":"
		yt.sets += 1
	}
	if yt.Month >= 1 && yt.Month <= 12 {
		yeartime += sep + fmt.Sprintf("%2d", yt.Month)
		sep = ":"
		yt.sets += 1
	}
	if yt.Day >= 1 && yt.Day <= 31 {
		yeartime += sep + fmt.Sprintf("%2d", yt.Day)
		sep = ":"
		yt.sets += 1
	}
	return yeartime
}

func ParseYeartime(yeartime string) (*Yeartime, error) {
	yt := &Yeartime{-1, -1, -1, 0}
	err := error(nil)
	parts := strings.Split(yeartime, "-")
	if len(parts) != 3 {
		err = errors.New("wrong elems")
		return yt, err
	}
	for index, part := range parts {
		switch index {
		case 0:
			year, err := strconv.ParseInt(part, 10, 16)
			if err != nil {
				return yt, err
			}
			yt.Year = int16(year)
		case 1:
			month, err := strconv.ParseInt(part, 10, 8)
			if err != nil {
				return yt, err
			}
			yt.Month = int8(month)
		case 2:
			day, err := strconv.ParseInt(part, 10, 8)
			if err != nil {
				return yt, err
			}
			yt.Day = int8(day)
		}
	}
	return yt, nil
}

type Date struct {
	*Yeartime
	*Daytime
}

func (date *Date) String() string {
	yeartime := date.Yeartime.String()
	daytime := date.Daytime.String()
	if date.Yeartime.sets == 3 && date.Daytime.sets == 3 {
		return yeartime + "T" + daytime
	}
	return yeartime
}

func ParseDate(date string) (*Date, error) {
	de := &Date{}
	err := error(nil)
	if len(date) != 19 {
		err = errors.New("wrong len")
		return de, err
	}
	yeartime := date[:10]
	daytime := date[11:]
	yt, err := ParseYeartime(yeartime)
	if err != nil {
		return de, err
	}
	dt, err := ParseDaytime(daytime)
	if err != nil {
		return de, err
	}
	de.Yeartime = yt
	de.Daytime = dt
	return de, nil
}

type Weekday int8

func (weekday Weekday) String() string {
	weekdays := ""
	sep := ""
	for i := 0; i <= 6; i++ {
		if weekday&(1<<i) != 0 {
			weekdays += sep + strconv.Itoa(i+1)
			sep = ","
		}
	}
	return weekdays
}

const (
	Monday Weekday = 1 << iota
	Tuesday
	Wednesday
	Thursday
	Friday
	Saturday
	Sunday
)

var (
	Weekdays = map[string]Weekday{
		"Mon": Monday,
		"Tue": Tuesday,
		"Wed": Wednesday,
		"Thu": Thursday,
		"Fri": Friday,
		"Sat": Saturday,
		"Sun": Sunday,
	}
)

type Monthday int32

func (monthday Monthday) String() string {
	monthdays := ""
	sep := ""
	for i := 0; i <= 30; i++ {
		if monthday&(1<<i) != 0 {
			monthdays += sep + strconv.Itoa(i+1)
			sep = ","
		}
	}
	return monthdays
}

// IP related
type IPType uint8

const (
	IPv4 IPType = 1 << iota
	IPv6
	IPALL = IPv4 | IPv6
)

type IPv6Option struct {
	Type   int
	Length int
}

// IP headers
// see https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/inX.h
type IPHeaderType uint8

func (ipHeaderType IPHeaderType) String() string {
	switch ipHeaderType {
	case IPPROTO_HOPOPTS:
		return "hop"
	case IPPROTO_DSTOPTS:
		return "dst"
	case IPPROTO_ROUTING:
		return "route"
	case IPPROTO_FRAGMENT:
		return "frag"
	case IPPROTO_AH:
		return "auth"
	case IPPROTO_ESP:
		return "esp"
	case IPPROTO_NONE:
		return "none"
	case IPPROTO_RAW:
		return "proto"
	default:
		return ""
	}
}

const (
	IPPROTO_IP       IPHeaderType = 0
	IPPROTO_ICMP     IPHeaderType = 1
	IPPROTO_IGMP     IPHeaderType = 2
	IPPROTO_IPIP     IPHeaderType = 4
	IPPROTO_TCP      IPHeaderType = 6
	IPPROTO_EGP      IPHeaderType = 8
	IPPROTO_PUP      IPHeaderType = 12
	IPPROTO_UDP      IPHeaderType = 17
	IPPROTO_IDP      IPHeaderType = 22
	IPPROTO_TP       IPHeaderType = 29
	IPPROTO_DCCP     IPHeaderType = 33
	IPPROTO_IPV6     IPHeaderType = 41
	IPPROTO_RSVP     IPHeaderType = 46
	IPPROTO_GRE      IPHeaderType = 47
	IPPROTO_ESP      IPHeaderType = 50
	IPPROTO_AH       IPHeaderType = 51
	IPPROTO_MTP      IPHeaderType = 92
	IPPROTO_BEETPH   IPHeaderType = 94
	IPPROTO_ENCAP    IPHeaderType = 98
	IPPROTO_PIM      IPHeaderType = 103
	IPPROTO_COMP     IPHeaderType = 108
	IPPROTO_SCTP     IPHeaderType = 132
	IPPROTO_UDPLITE  IPHeaderType = 136
	IPPROTO_MPLS     IPHeaderType = 137
	IPPROTO_ETHERNET IPHeaderType = 143
	IPPROTO_RAW      IPHeaderType = 255
	// IPPROTO_MPTCP    IPHeaderType = 262
	// IPv6 extension headers
	IPPROTO_HOPOPTS  IPHeaderType = 0
	IPPROTO_ROUTING  IPHeaderType = 43
	IPPROTO_FRAGMENT IPHeaderType = 44
	IPPROTO_ICMPV6   IPHeaderType = 58
	IPPROTO_NONE     IPHeaderType = 59
	IPPROTO_DSTOPTS  IPHeaderType = 60
	IPPROTO_MH       IPHeaderType = 135

	// mask
	MASK_HOPOPTS  IPHeaderType = 128
	MASK_DSTOPTS  IPHeaderType = 64
	MASK_ROUTING  IPHeaderType = 32
	MASK_FRAGMENT IPHeaderType = 16
	MASK_AH       IPHeaderType = 8
	MASK_ESP      IPHeaderType = 4
	MASK_NONE     IPHeaderType = 2
	MASK_PROTO    IPHeaderType = 1
)

var (
	IPHeaderTypeMasks   = [...]IPHeaderType{MASK_HOPOPTS, MASK_DSTOPTS, MASK_ROUTING, MASK_FRAGMENT, MASK_AH, MASK_ESP, MASK_NONE, MASK_PROTO}
	IPHeaderTypeMaskMap = map[IPHeaderType]IPHeaderType{
		MASK_HOPOPTS:  IPPROTO_HOPOPTS,
		MASK_DSTOPTS:  IPPROTO_DSTOPTS,
		MASK_ROUTING:  IPPROTO_ROUTING,
		MASK_FRAGMENT: IPPROTO_FRAGMENT,
		MASK_AH:       IPPROTO_AH,
		MASK_ESP:      IPPROTO_ESP,
		MASK_NONE:     IPPROTO_NONE,
		MASK_PROTO:    IPPROTO_RAW,
	}
)

var (
	IPHeaderTypes = map[string]IPHeaderType{
		"hop":        IPPROTO_HOPOPTS,
		"hop-by-hop": IPPROTO_HOPOPTS,
		"dst":        IPPROTO_DSTOPTS,
		"ipv6-opts":  IPPROTO_DSTOPTS,
		"route":      IPPROTO_ROUTING,
		"ipv6-route": IPPROTO_ROUTING,
		"frag":       IPPROTO_FRAGMENT,
		"ipv6-frag":  IPPROTO_FRAGMENT,
		"auth":       IPPROTO_AH,
		"ah":         IPPROTO_AH,
		"esp":        IPPROTO_ESP,
		"none":       IPPROTO_NONE,
		"ipv6-nonxt": IPPROTO_NONE,
		"prot":       IPPROTO_RAW,
		"protocol":   IPPROTO_RAW,
	}
)

type TOS int8

const (
	_ TOS = 1 << iota
	TOSMinCost
	TOSMaxReliability
	TOSMaxThroughput
	TOSMinDelay
	TOSNormal TOS = 0
)

var (
	TOSMap = map[string]TOS{
		"Minimize-Delay":       TOSMinDelay,
		"Maximize-Throughput":  TOSMaxThroughput,
		"Maximize-Reliability": TOSMaxReliability,
		"Minimize-Cost":        TOSMinCost,
		"Normal-Service":       TOSNormal,
	}
)

// operators
type Operator uint32

const (
	_            Operator = iota
	OperatorEQ            // ==
	OperatorNE            // !=
	OperatorLT            // <
	OperatorGT            // >
	OperatorINC           // +
	OperatorDEC           // -
	OperatorSET           // =
	OperatorXSET          // ^=
	OperatorAND           // &
	OperatorOR            // |
	OperatorXOR           // ^|
)

// ICMP related
type ICMPType int
type ICMPCode int

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

type ICMP6Type ICMPType

const (
	DestinationUnreachable6 ICMP6Type = 1
	PacketTooBig6           ICMP6Type = 2
	TimeExceeded6           ICMP6Type = 3
	ParameterProblem6       ICMP6Type = 4
	EchoRequest6            ICMP6Type = 128
	Ping6                   ICMP6Type = 128
	EchoReply6              ICMP6Type = 129
	Pong6                   ICMP6Type = 129
	RouterSolicitation6     ICMP6Type = 133
	RouterAdvertisement6    ICMP6Type = 134
	NeighbourSolicitation   ICMP6Type = 135
	NeighborSolicitation    ICMP6Type = 135
	NeighbourAdvertisement  ICMP6Type = 136
	NeighborAdvertisement   ICMP6Type = 136
	Redirect6               ICMP6Type = 137
)

var (
	ICMP6Types = map[string]ICMP6Type{
		"destination-unreachable": DestinationUnreachable6,
		"packet-too-big":          PacketTooBig6,
		"time-exceeded":           TimeExceeded6,
		"parameter-problem":       ParameterProblem6,
		"echo-request":            EchoRequest6,
		"ping":                    Ping6,
		"echo-reply":              EchoReply6,
		"poing":                   Pong6,
		"router-solicitation":     RouterSolicitation6,
		"router-advertisement":    RouterAdvertisement6,
		"neighbour-solicitation":  NeighbourSolicitation,
		"neighbor-solicitation":   NeighborSolicitation,
		"neighbour-advertisement": NeighbourAdvertisement,
		"neighbor-advertisement":  NeighborAdvertisement,
		"redirect":                Redirect6,
	}
)

type ICMP6Code ICMPCode

const (
	// destination unreachable IPv6
	NoRoute6                 ICMP6Code = 0
	CommunicationProhibited6 ICMP6Code = 1
	BeyondScope              ICMP6Code = 2
	AddressUnreachable       ICMP6Code = 3
	PortUnreachable6         ICMP6Code = 4
	FailedPolicy             ICMP6Code = 5
	RejectRoute              ICMP6Code = 6
	// time exceeded IPv6
	TTLZeroDuringTransit6    ICMP6Code = 0
	TTLZeroDuringReassembly6 ICMP6Code = 1
	// parameter problem IPv6
	BadHeader         ICMP6Code = 0
	UnknownHeaderType ICMP6Code = 1
	UnknownOption     ICMP6Code = 2
)

var (
	ICMP6Codes = map[string]struct {
		Code ICMP6Code
		Type ICMP6Type
	}{
		"no-route": struct {
			Code ICMP6Code
			Type ICMP6Type
		}{NoRoute6, DestinationUnreachable6},
		"communication-prohibited": struct {
			Code ICMP6Code
			Type ICMP6Type
		}{CommunicationProhibited6, DestinationUnreachable6},
		"beyond-scope": struct {
			Code ICMP6Code
			Type ICMP6Type
		}{BeyondScope, DestinationUnreachable6},
		"address-unreachable": struct {
			Code ICMP6Code
			Type ICMP6Type
		}{AddressUnreachable, DestinationUnreachable6},
		"port-unreachable": struct {
			Code ICMP6Code
			Type ICMP6Type
		}{PortUnreachable6, DestinationUnreachable6},
		"failed-policy": struct {
			Code ICMP6Code
			Type ICMP6Type
		}{FailedPolicy, DestinationUnreachable6},
		"reject-route": struct {
			Code ICMP6Code
			Type ICMP6Type
		}{RejectRoute, DestinationUnreachable6},
		"ttl-zero-during-transit": struct {
			Code ICMP6Code
			Type ICMP6Type
		}{TTLZeroDuringTransit6, TimeExceeded6},
		"ttl-zero-during-reassembly": struct {
			Code ICMP6Code
			Type ICMP6Type
		}{TTLZeroDuringReassembly6, TimeExceeded6},
		"bad-header": struct {
			Code ICMP6Code
			Type ICMP6Type
		}{BadHeader, ParameterProblem6},
		"unknown-header-type": struct {
			Code ICMP6Code
			Type ICMP6Type
		}{UnknownHeaderType, ParameterProblem6},
		"unknown-option": struct {
			Code ICMP6Code
			Type ICMP6Type
		}{UnknownOption, ParameterProblem6},
	}
)
