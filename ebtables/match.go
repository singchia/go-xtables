package ebtables

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/singchia/go-xtables/internal/rate"
	"github.com/singchia/go-xtables/internal/xerror"
	"github.com/singchia/go-xtables/pkg/network"
)

type MatchType int

const (
	MatchType802dot3 MatchType = iota
	MatchTypeAmong
	MatchTypeARP
	MatchTypeDestination // option
	MatchTypeInInterface // option
	MatchTypeIP
	MatchTypeIPv6
	MatchTypeLimit
	MatchTypeLogicalIn  // option
	MatchTypeLogicalOut // option
	MatchTypeMark
	MatchTypeOutInterface // option
	MatchTypePktType
	MatchTypeProtocol   // option
	MatchTypeSetCounter // option
	MatchTypeSource     // option
	MatchTypeSTP
	MatchTypeVLAN
)

func (mt MatchType) Type() string {
	return "MatchType"
}

func (mt MatchType) Value() string {
	return strconv.Itoa(int(mt))
}

func (mt MatchType) String() string {
	switch mt {
	case MatchType802dot3:
		return "802_3"
	case MatchTypeAmong:
		return "among"
	case MatchTypeARP:
		return "arp"
	case MatchTypeIP:
		return "ip"
	case MatchTypeIPv6:
		return "ip6"
	case MatchTypeLimit:
		return "limit"
	case MatchTypeMark:
		return "mark_m"
	case MatchTypeSTP:
		return "stp"
	case MatchTypeVLAN:
		return "vlan"
	default:
		return ""
	}
}

type Match interface {
	Type() MatchType
	Short() string
	ShortArgs() []string
	Long() string
	LongArgs() []string
	Parse([]byte) (int, bool)
	Depends() []MatchType
}

func MatchFactory(matchType MatchType) Match {
	switch matchType {
	case MatchType802dot3:
		match, _ := NewMatch802dot3()
		return match
	case MatchTypeAmong:
		match, _ := NewMatchAmong()
		return match
	case MatchTypeARP:
		match, _ := NewMatchARP()
		return match
	case MatchTypeDestination:
		match, _ := NewMatchDestination(false, nil)
		return match
	case MatchTypeInInterface:
		match, _ := NewMatchInInterface(false, "")
		return match
	case MatchTypeIP:
		match, _ := NewMatchIP()
		return match
	case MatchTypeIPv6:
		match, _ := NewMatchIPv6()
		return match
	case MatchTypeLimit:
		match, _ := NewMatchLimit()
		return match
	case MatchTypeLogicalIn:
		match, _ := NewMatchLogicalIn(false, "")
		return match
	case MatchTypeLogicalOut:
		match, _ := NewMatchLogicalOut(false, "")
		return match
	case MatchTypeMark:
		match, _ := NewMatchMark(false, -1)
		return match
	case MatchTypeOutInterface:
		match, _ := NewMatchOutInterface(false, "")
		return match
	case MatchTypePktType:
		match, _ := NewMatchPktType(false, -1)
		return match
	case MatchTypeProtocol:
		match, _ := NewMatchProtocol(false, network.ProtocolUnknown)
		return match
	case MatchTypeSource:
		match, _ := NewMatchSource(false, nil)
		return match
	case MatchTypeSTP:
		match, _ := NewMatchSTP()
		return match
	case MatchTypeVLAN:
		match, _ := NewMatchVLAN()
		return match
	}
	return nil
}

type baseMatch struct {
	matchType MatchType
	child     Match
}

func (bm baseMatch) setChild(child Match) {
	bm.child = child
}

func (bm baseMatch) Type() MatchType {
	return bm.matchType
}

func (bm baseMatch) Short() string {
	if bm.child != nil {
		return bm.child.Short()
	}
	return ""
}

func (bm baseMatch) ShortArgs() []string {
	if bm.child != nil {
		return bm.child.ShortArgs()
	}
	return nil
}

func (bm baseMatch) Long() string {
	return bm.Short()
}

func (bm baseMatch) LongArgs() []string {
	return bm.LongArgs()
}

func (bm *baseMatch) Parse(params []byte) (int, bool) {
	return 0, false
}

func (bm *baseMatch) Depends() []MatchType {
	return nil
}

type OptionMatch802dot3 func(*Match802dot3)

// DSAP and SSAP are two one byte 802.3 fields.  The bytes are always equal,
// so only one byte(hexadecimal) is needed as an argument.
func WithMatch802dot3SAP(yes bool, sap byte) OptionMatch802dot3 {
	return func(m802dot3 *Match802dot3) {
		m802dot3.SAP = sap
		m802dot3.HasSAP = true
		m802dot3.SAPInvert = !yes
	}
}

// If the 802.3 DSAP and SSAP values are 0xaa then the SNAP type field must
// be consulted to determine the payload protocol. This is a two byte(hexadecimal)
// argument. Only 802.3 frames with DSAP/SSAP 0xaa are checked for type.
func WithMatch802dot3Type(yes bool, typ [2]byte) OptionMatch802dot3 {
	return func(m802dot3 *Match802dot3) {
		m802dot3.Typ = typ
		m802dot3.HasType = true
		m802dot3.TypeInvert = !yes
	}
}

func NewMatch802dot3(opts ...OptionMatch802dot3) (*Match802dot3, error) {
	match := &Match802dot3{
		baseMatch: baseMatch{
			matchType: MatchType802dot3,
		},
	}
	match.setChild(match)
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// Specify 802.3 DSAP/SSAP fields or SNAP type. The protocol must be specified as LENGTH
type Match802dot3 struct {
	baseMatch
	// sap
	SAP       byte
	HasSAP    bool
	SAPInvert bool
	// type
	Typ        [2]byte
	HasType    bool
	TypeInvert bool
}

func (m802dot3 *Match802dot3) Short() string {
	return strings.Join(m802dot3.ShortArgs(), " ")
}

func (m802dot3 *Match802dot3) ShortArgs() []string {
	args := make([]string, 0, 6)
	if m802dot3.HasSAP {
		args = append(args, "--802_3-sap")
		if m802dot3.SAPInvert {
			args = append(args, "!")
		}
		sap := hex.EncodeToString([]byte{m802dot3.SAP})
		args = append(args, sap)
	}
	if m802dot3.HasType {
		args = append(args, "--802_3-type")
		if m802dot3.TypeInvert {
			args = append(args, "!")
		}
		typ := hex.EncodeToString([]byte{m802dot3.Typ[0], m802dot3.Typ[1]})
		args = append(args, typ)
	}
	return args
}

type OptionMatchAmong func(*MatchAmong)

type Among struct {
	MAC net.HardwareAddr
	IP  net.IP
}

// Compare the MAC destination to the given list. If the Ethernet frame
// has type IPv4 or ARP, then comparison with MAC/IP destination address
// pairs from the list is possible.
func WithMatchAmongDst(yes bool, list []*Among) OptionMatchAmong {
	return func(mAmong *MatchAmong) {
		mAmong.DstInvert = !yes
		mAmong.Dst = list
	}
}

// Compare the MAC source to the given list. If the Ethernet frame has
// type IPv4 or ARP, then comparison with MAC/IP srouce address pairs
// from the list is possible.
func WithMatchAmongSrc(yes bool, list []*Among) OptionMatchAmong {
	return func(mAmong *MatchAmong) {
		mAmong.SrcInvert = !yes
		mAmong.Src = list
	}
}

// List is read in from the specified file. A list entry has the following
// format: xx:xx:xx:xx:xx:xx[=ip.ip.ip.ip][,]
// This option conflicts with WithMatchAmongDst, using it will overwirte
// the latter.
func WithMatchAmongDstFile(yes bool, path string) OptionMatchAmong {
	return func(mAmong *MatchAmong) {
		mAmong.DstFileInvert = !yes
		mAmong.DstFile = path
	}
}

// List is read in from the specified file. A list entry has the following
// format: xx:xx:xx:xx:xx:xx[=ip.ip.ip.ip][,]
// the latter.
func WithMatchAmongSrcFile(yes bool, path string) OptionMatchAmong {
	return func(mAmong *MatchAmong) {
		mAmong.SrcFileInvert = !yes
		mAmong.SrcFile = path
	}
}

func NewMatchAmong(opts ...OptionMatchAmong) (*MatchAmong, error) {
	match := &MatchAmong{
		baseMatch: baseMatch{
			matchType: MatchTypeAmong,
		},
	}
	match.setChild(match)
	for _, opt := range opts {
		opt(match)
	}
	if match.DstFile != "" {
		data, err := os.ReadFile(match.DstFile)
		if err != nil {
			return nil, err
		}
		match.DstFile = string(data)
	}
	if match.SrcFile != "" {
		data, err := os.ReadFile(match.SrcFile)
		if err != nil {
			return nil, err
		}
		match.SrcFile = string(data)
	}
	return match, nil
}

// Match a MAC address or MAC/IP address pair versus a list of MAC addresses
// and MAC/IP address pairs. If the MAC address doesn't match any entry from
// the list, the frame doesn't match the rule unless yes=false was used.
type MatchAmong struct {
	baseMatch
	Dst     []*Among
	Src     []*Among
	DstFile string
	SrcFile string

	// invert
	DstInvert     bool
	SrcInvert     bool
	DstFileInvert bool
	SrcFileInvert bool
}

func (mAmong *MatchAmong) Short() string {
	return strings.Join(mAmong.ShortArgs(), " ")
}

func (mAmong *MatchAmong) ShortArgs() []string {
	args := make([]string, 0, 6)
	if mAmong.DstFile != "" {
		args = append(args, "--among-dst-file")
		if mAmong.DstFileInvert {
			args = append(args, "!")
		}
		args = append(args, mAmong.DstFile)
	} else if mAmong.Dst != nil {
		args = append(args, "--among-dst")
		if mAmong.DstInvert {
			args = append(args, "!")
		}
		list, err := amongListToString(mAmong.Dst)
		if err != nil {
			// TODO
			return args
		}
		args = append(args, list)
	}

	if mAmong.SrcFile != "" {
		args = append(args, "--among-src-file")
		if mAmong.SrcFileInvert {
			args = append(args, "!")
		}
		args = append(args, mAmong.SrcFile)
	} else if mAmong.Src != nil {
		args = append(args, "--among-src")
		if mAmong.SrcInvert {
			args = append(args, "!")
		}
		list, err := amongListToString(mAmong.Src)
		if err != nil {
			// TODO
			return args
		}
		args = append(args, list)
	}
	return args
}

func amongListToString(list []*Among) (string, error) {
	sb := strings.Builder{}
	for index, elem := range list {
		if index != 0 {
			_, err := sb.WriteString(",")
			if err != nil {
				return "", err
			}
		}
		if elem != nil {
			if elem.MAC == nil {
				return "", xerror.ErrArgsWithoutMAC
			}
			_, err := sb.WriteString(elem.MAC.String())
			if err != nil {
				return "", err
			}
			if elem.IP != nil {
				_, err = sb.WriteString("=")
				if err != nil {
					return "", err
				}
				_, err = sb.WriteString(elem.IP.String())
				if err != nil {
					return "", err
				}
			}
		}
	}
	return sb.String(), nil
}

type OptionMatchARP func(*MatchARP)

// The (R)ARP opcode.
func WithMatchARPOpCode(yes bool, opcode network.ARPOpCode) OptionMatchARP {
	return func(mARP *MatchARP) {
		mARP.OpCodeInvert = !yes
		mARP.OpCode = opcode
	}
}

// The hardware type, Most (R)ARP packets have Ethernet as hardware type.
func WithMatchARPHWType(yes bool, hwtype network.HardwareType) OptionMatchARP {
	return func(mARP *MatchARP) {
		mARP.HWTypeInvert = !yes
		mARP.HWType = hwtype
	}
}

// The protocol type for which the (R)ARP is used. Most (R)ARP packets have
// protocol type IPv4.
func WithMatchARPProtoType(yes bool, prototype network.EthernetType) OptionMatchARP {
	return func(mARP *MatchARP) {
		mARP.ProtoTypeInvert = !yes
		mARP.HasProtoType = true
		mARP.ProtoType = prototype
	}
}

// The (R)ARP IP source address specification.
// Getting addr by using network.NewIP(net.IP) or network.NewIPNet(*net.IPNet)
func WithMatchARPIPSrc(yes bool, addr network.Address) OptionMatchARP {
	return func(mARP *MatchARP) {
		mARP.IPSrcInvert = !yes
		mARP.IPSrc = addr
	}
}

// The (R)ARP IP destination address specification.
// Getting addr by using network.NewIP(net.IP) or network.NewIPNet(*net.IPNet).
func WithMatchARPIPDst(yes bool, addr network.Address) OptionMatchARP {
	return func(mARP *MatchARP) {
		mARP.IPDstInvert = !yes
		mARP.IPDst = addr
	}
}

// The (R)ARP MAC source address specification.
// Getting addr by using network.NewHardwareAddr(net.HardwareAddr) or
// network.NewHardwareAddrMask(net.HardwareAddr, net.HardwareAddr).
func WithMatchARPMACSrc(yes bool, addr network.Address) OptionMatchARP {
	return func(mARP *MatchARP) {
		mARP.MACSrcInvert = !yes
		mARP.MACSrc = addr
	}
}

// The (R)ARP MAC destination address specification.
// Getting addr by using network.NewHardwareAddr(net.HardwareAddr) or
// network.NewHardwareAddrMask(net.HardwareAddr, net.HardwareAddr).
func WithMatchARPMACDst(yes bool, addr network.Address) OptionMatchARP {
	return func(mARP *MatchARP) {
		mARP.MACDstInvert = !yes
		mARP.MACDst = addr
	}
}

// Checks for ARP gratuitous packets: checks equality of IPv4 source
// address and IPv4 destination address inside the ARP header.
func WithMatchARPGratuitous(yes bool) OptionMatchARP {
	return func(mARP *MatchARP) {
		mARP.GratuitousInvert = !yes
		mARP.HasGratuitous = true
	}
}

func NewMatchARP(opts ...OptionMatchARP) (*MatchARP, error) {
	match := &MatchARP{
		baseMatch: baseMatch{
			matchType: MatchTypeARP,
		},
	}
	match.setChild(match)
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// Specify (R)ARP fields. The protocol must be specified as ARP or RARP.
type MatchARP struct {
	baseMatch
	OpCode        network.ARPOpCode
	HWType        network.HardwareType
	ProtoType     network.EthernetType
	HasProtoType  bool
	IPSrc         network.Address
	IPDst         network.Address
	MACSrc        network.Address
	MACDst        network.Address
	HasGratuitous bool
	// invert
	OpCodeInvert     bool
	HWTypeInvert     bool
	ProtoTypeInvert  bool
	IPSrcInvert      bool
	IPDstInvert      bool
	MACSrcInvert     bool
	MACDstInvert     bool
	GratuitousInvert bool
}

func (mARP *MatchARP) Short() string {
	return strings.Join(mARP.ShortArgs(), " ")
}

func (mARP *MatchARP) ShortArgs() []string {
	args := make([]string, 0, 23)
	if mARP.OpCode != 0 {
		args = append(args, "--arp-opcode")
		if mARP.OpCodeInvert {
			args = append(args, "!")
		}
		args = append(args, mARP.OpCode.String())
	}
	if mARP.HWType != 0 {
		args = append(args, "--arp-htype")
		if mARP.HWTypeInvert {
			args = append(args, "!")
		}
		args = append(args, mARP.HWType.String())
	}
	if mARP.HasProtoType {
		args = append(args, "--arp-ptype")
		if mARP.ProtoTypeInvert {
			args = append(args, "!")
		}
		args = append(args, mARP.ProtoType.String())
	}
	if mARP.IPSrc != nil {
		args = append(args, "--arp-ip-src")
		if mARP.IPSrcInvert {
			args = append(args, "!")
		}
		args = append(args, mARP.IPSrc.String())
	}
	if mARP.IPDst != nil {
		args = append(args, "--arp-ip-dst")
		if mARP.IPDstInvert {
			args = append(args, "!")
		}
		args = append(args, mARP.IPDst.String())
	}
	if mARP.MACSrc != nil {
		args = append(args, "--arp-mac-src")
		if mARP.MACSrcInvert {
			args = append(args, "!")
		}
		args = append(args, mARP.MACSrc.String())
	}
	if mARP.MACDst != nil {
		args = append(args, "--arp-mac-dst")
		if mARP.MACDstInvert {
			args = append(args, "!")
		}
		args = append(args, mARP.MACDst.String())
	}
	if mARP.HasGratuitous {
		if mARP.GratuitousInvert {
			args = append(args, "!")
		}
		args = append(args, "--arp-gratuitous")
	}
	return args
}

// The destination MAC address with or without mask.
func NewMatchDestination(yes bool, addr network.Address) (*MatchDestination, error) {
	match := &MatchDestination{
		baseMatch: baseMatch{
			matchType: MatchTypeDestination,
		},
		DestinationInvert: !yes,
		Destination:       addr,
	}
	match.setChild(match)
	return match, nil
}

type MatchDestination struct {
	baseMatch
	Destination network.Address
	// invert
	DestinationInvert bool
}

func (mDestination *MatchDestination) Short() string {
	return strings.Join(mDestination.ShortArgs(), " ")
}

func (mDestination *MatchDestination) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-d")
	if mDestination.DestinationInvert {
		args = append(args, "!")
	}
	args = append(args, mDestination.Destination.String())
	return args
}

func (mDestination *MatchDestination) Long() string {
	return strings.Join(mDestination.LongArgs(), " ")
}

func (mDestination *MatchDestination) LongArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--destination")
	if mDestination.DestinationInvert {
		args = append(args, "!")
	}
	args = append(args, mDestination.Destination.String())
	return args
}

func NewMatchInInterface(yes bool, name string) (*MatchInInterface, error) {
	match := &MatchInInterface{
		baseMatch: baseMatch{
			matchType: MatchTypeInInterface,
		},
		InInterfaceInvert: !yes,
		InInterface:       name,
	}
	match.setChild(match)
	return match, nil
}

type MatchInInterface struct {
	baseMatch
	InInterface string
	// invert
	InInterfaceInvert bool
}

func (mInInterface *MatchInInterface) Short() string {
	return strings.Join(mInInterface.ShortArgs(), " ")
}

func (mInInterface *MatchInInterface) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-i")
	if mInInterface.InInterfaceInvert {
		args = append(args, "!")
	}
	args = append(args, mInInterface.InInterface)
	return args
}

func (mInInterface *MatchInInterface) Long() string {
	return strings.Join(mInInterface.LongArgs(), " ")
}

func (mInInterface *MatchInInterface) LongArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--in-interface")
	if mInInterface.InInterfaceInvert {
		args = append(args, "!")
	}
	args = append(args, mInInterface.InInterface)
	return args
}

type OptionMatchIP func(*MatchIP)

// The source IP address. Getting addr by using network.NewIP(net.IP) or
// network.NewIPNet(ipNet *IPNet).
func WithMatchIPSource(yes bool, addr network.Address) OptionMatchIP {
	return func(mIP *MatchIP) {
		mIP.SourceInvert = !yes
		mIP.Source = addr
	}
}

// The destination IP address. Getting addr by using network.NewIP(net.IP) or
// network.NewIPNet(ipNet *IPNet).
func WithMatchIPDestination(yes bool, addr network.Address) OptionMatchIP {
	return func(mIP *MatchIP) {
		mIP.DestinationInvert = !yes
		mIP.Destination = addr
	}
}

// The IP type of service.
func WithMatchIPTOS(yes bool, tos network.TOS) OptionMatchIP {
	return func(mIP *MatchIP) {
		mIP.TOSInvert = !yes
		mIP.TOS = tos
	}
}

// The IP protocol.
func WithMatchIPProtocol(yes bool, protocol network.Protocol) OptionMatchIP {
	return func(mIP *MatchIP) {
		mIP.ProtocolInvert = !yes
		mIP.Protocol = protocol
	}
}

// The source port or port range for the IP protocols 6(TCP), 17(UDP),
// 33(DCCP) or 132(SCTP). If min equals -1, 0:max is used; if max equal -1,
// min:65535 is used.
func WithMatchIPSourcePort(yes bool, port ...int) OptionMatchIP {
	return func(mIP *MatchIP) {
		mIP.SourcePortInvert = !yes
		switch len(port) {
		case 1:
			mIP.SourcePortMin = port[0]
			mIP.SourcePortMax = -1
		case 2:
			mIP.SourcePortMin = port[0]
			mIP.SourcePortMax = port[1]
		}
	}
}

// The destination port or port range for the IP protocols 6(TCP), 17(UDP),
// 33(DCCP) or 132(SCTP). If min equals -1, 0:max is used; if max equal -1,
// min:65535 is used.
func WithMatchIPDestinationPort(yes bool, port ...int) OptionMatchIP {
	return func(mIP *MatchIP) {
		mIP.DestinationPortInvert = !yes
		switch len(port) {
		case 1:
			mIP.DestinationPortMin = port[0]
			mIP.DestinationPortMax = -1
		case 2:
			mIP.DestinationPortMin = port[0]
			mIP.DestinationPortMax = port[1]
		}
	}
}

func NewMatchIP(opts ...OptionMatchIP) (*MatchIP, error) {
	match := &MatchIP{
		baseMatch: baseMatch{
			matchType: MatchTypeIP,
		},
	}
	match.setChild(match)
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// Specify IPv4 fields.
type MatchIP struct {
	baseMatch
	Source                                 network.Address
	Destination                            network.Address
	TOS                                    network.TOS
	Protocol                               network.Protocol // default -1
	SourcePortMin, SourcePortMax           int
	DestinationPortMin, DestinationPortMax int
	// invert
	SourceInvert          bool
	DestinationInvert     bool
	TOSInvert             bool
	ProtocolInvert        bool
	SourcePortInvert      bool
	DestinationPortInvert bool
}

func (mIP *MatchIP) Short() string {
	return strings.Join(mIP.ShortArgs(), " ")
}

func (mIP *MatchIP) ShortArgs() []string {
	args := make([]string, 0, 18)
	if mIP.Source != nil {
		args = append(args, "--ip-source")
		if mIP.SourceInvert {
			args = append(args, "!")
		}
		args = append(args, mIP.Source.String())
	}
	if mIP.Destination != nil {
		args = append(args, "--ip-destination")
		if mIP.DestinationInvert {
			args = append(args, "!")
		}
		args = append(args, mIP.Destination.String())
	}
	if mIP.TOS != 0 {
		args = append(args, "--ip-tos")
		if mIP.TOSInvert {
			args = append(args, "!")
		}
		args = append(args, mIP.TOS.String())
	}
	if mIP.Protocol > -1 {
		args = append(args, "--ip-protocol")
		if mIP.ProtocolInvert {
			args = append(args, "!")
		}
		args = append(args, mIP.Protocol.Value())
	}
	if mIP.SourcePortMin > -1 {
		args = append(args, "--ip-source-port")
		if mIP.SourcePortInvert {
			args = append(args, "!")
		}
		if mIP.SourcePortMax > -1 {
			args = append(args, strconv.Itoa(mIP.SourcePortMin)+
				":"+strconv.Itoa(mIP.SourcePortMax))
		} else {
			args = append(args, strconv.Itoa(mIP.SourcePortMin))
		}
	}
	if mIP.DestinationPortMin > -1 {
		args = append(args, "--ip-destination-port")
		if mIP.DestinationPortInvert {
			args = append(args, "!")
		}
		if mIP.DestinationPortMax > -1 {
			args = append(args, strconv.Itoa(mIP.DestinationPortMin)+
				":"+strconv.Itoa(mIP.DestinationPortMax))
		} else {
			args = append(args, strconv.Itoa(mIP.DestinationPortMin))
		}
	}
	return args
}

type OptionMatchIPv6 func(*MatchIPv6)

// The source IPv6 address. Getting addr by using network.NewIP(net.IP) or
// network.NewIPNet(ipNet *IPNet).
func WithMatchIPv6Source(yes bool, addr network.Address) OptionMatchIPv6 {
	return func(mIP *MatchIPv6) {
		mIP.SourceInvert = !yes
		mIP.Source = addr
	}
}

// The destination IPv6 address. Getting addr by using network.NewIP(net.IP) or
// network.NewIPNet(ipNet *IPNet).
func WithMatchIPv6Destination(yes bool, addr network.Address) OptionMatchIPv6 {
	return func(mIP *MatchIPv6) {
		mIP.DestinationInvert = !yes
		mIP.Destination = addr
	}
}

// The IPv6 traffic class, in hexadecimal numbers.
func WithMatchIPv6TrafficClass(yes bool, tclass byte) OptionMatchIPv6 {
	return func(mIP *MatchIPv6) {
		mIP.TrafficClassInvert = !yes
		mIP.TrafficClass = tclass
		mIP.HasTrafficClass = true
	}
}

// The IP protocol.
func WithMatchIPv6Protocol(yes bool, protocol network.Protocol) OptionMatchIPv6 {
	return func(mIP *MatchIPv6) {
		mIP.ProtocolInvert = !yes
		mIP.Protocol = protocol
	}
}

// The source port or port range for the IPv6 protocols 6(TCP), 17(UDP),
// 33(DCCP) or 132(SCTP). If min equals -1, 0:max is used; if max equal -1,
// min:65535 is used.
func WithMatchIPv6SourcePort(yes bool, port ...int) OptionMatchIPv6 {
	return func(mIP *MatchIPv6) {
		mIP.SourcePortInvert = !yes
		switch len(port) {
		case 1:
			mIP.SourcePortMin = port[0]
			mIP.SourcePortMax = -1
		case 2:
			mIP.SourcePortMin = port[0]
			mIP.SourcePortMax = port[1]
		}
	}
}

// The destination port or port range for the IPv6 protocols 6(TCP), 17(UDP),
// 33(DCCP) or 132(SCTP). If min equals -1, 0:max is used; if max equal -1,
// min:65535 is used.
func WithMatchIPv6DestinationPort(yes bool, port ...int) OptionMatchIPv6 {
	return func(mIP *MatchIPv6) {
		mIP.DestinationPortInvert = !yes
		switch len(port) {
		case 1:
			mIP.DestinationPortMin = port[0]
			mIP.DestinationPortMax = -1
		case 2:
			mIP.DestinationPortMin = port[0]
			mIP.DestinationPortMax = port[1]
		}
	}
}

// Specify ipv6-icmp type and code to match. Ranges for both type and supported.
// Valid numbers for type and range are 0 to 255. To match a single type including
// all valid codes. Set network.ICMPv6CodeNull or network.ICMPv6TypeNull if no need.
// eg. WithMatchIPv6ICMPType(false, ICMPv6TypePacketTooBig, ICMPv6TypeTimeExceeded,
// ICMPv6CodeNull, ICMPv6CodeNull) means --ip6-icmp-type 2:3/0:255 to iptables.
func WithMatchIPv6ICMPType(yes bool, typeMin, typeMax network.ICMPv6Type,
	codeMin, codeMax network.ICMPv6Code) OptionMatchIPv6 {
	return func(mIP *MatchIPv6) {
		mIP.ICMPTypeInvert = !yes
		mIP.HasICMPType = true
		mIP.ICMPTypeMin = typeMin
		mIP.ICMPTypeMax = typeMax
		mIP.ICMPCodeMin = codeMin
		mIP.ICMPCodeMax = codeMax
	}
}

func NewMatchIPv6(opts ...OptionMatchIPv6) (*MatchIPv6, error) {
	match := &MatchIPv6{
		baseMatch: baseMatch{
			matchType: MatchTypeIPv6,
		},
		SourcePortMin:      -1,
		SourcePortMax:      -1,
		DestinationPortMin: -1,
		DestinationPortMax: -1,
		ICMPTypeMin:        network.ICMPv6TypeNull,
		ICMPTypeMax:        network.ICMPv6TypeNull,
		ICMPCodeMin:        network.ICMPv6CodeNull,
		ICMPCodeMax:        network.ICMPv6CodeNull,
	}
	match.setChild(match)
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// Specify IPv6 fields. The protocol must be specified as IPv6.
type MatchIPv6 struct {
	baseMatch
	Source                                 network.Address
	Destination                            network.Address
	TrafficClass                           byte
	HasTrafficClass                        bool
	Protocol                               network.Protocol
	SourcePortMin, SourcePortMax           int
	DestinationPortMin, DestinationPortMax int
	HasICMPType                            bool
	ICMPTypeMin, ICMPTypeMax               network.ICMPv6Type
	ICMPCodeMin, ICMPCodeMax               network.ICMPv6Code
	// invert
	SourceInvert          bool
	DestinationInvert     bool
	TrafficClassInvert    bool
	ProtocolInvert        bool
	SourcePortInvert      bool
	DestinationPortInvert bool
	ICMPTypeInvert        bool
}

func (mIP *MatchIPv6) Short() string {
	return strings.Join(mIP.ShortArgs(), " ")
}

func (mIP *MatchIPv6) ShortArgs() []string {
	args := make([]string, 0, 21)
	if mIP.Source != nil {
		args = append(args, "--ip6-source")
		if mIP.SourceInvert {
			args = append(args, "!")
		}
		args = append(args, mIP.Source.String())
	}
	if mIP.Destination != nil {
		args = append(args, "--ip6-destination")
		if mIP.DestinationInvert {
			args = append(args, "!")
		}
		args = append(args, mIP.Destination.String())
	}
	if mIP.HasTrafficClass {
		args = append(args, "--ip6-tclass")
		if mIP.TrafficClassInvert {
			args = append(args, "!")
		}
		args = append(args, fmt.Sprintf("0x%02x", mIP.TrafficClass))
	}
	if mIP.Protocol > -1 {
		args = append(args, "--ip6-protocol")
		if mIP.ProtocolInvert {
			args = append(args, "!")
		}
		args = append(args, mIP.Protocol.Value())
	}
	if mIP.SourcePortMin > -1 {
		args = append(args, "--ip6-source-port")
		if mIP.SourcePortInvert {
			args = append(args, "!")
		}
		if mIP.SourcePortMax > -1 {
			args = append(args, strconv.Itoa(mIP.SourcePortMin)+
				":"+strconv.Itoa(mIP.SourcePortMax))
		} else {
			args = append(args, strconv.Itoa(mIP.SourcePortMin))
		}
	}
	if mIP.DestinationPortMin > -1 {
		args = append(args, "--ip6-destination-port")
		if mIP.DestinationPortInvert {
			args = append(args, "!")
		}
		if mIP.DestinationPortMax > -1 {
			args = append(args, strconv.Itoa(mIP.DestinationPortMin)+
				":"+strconv.Itoa(mIP.DestinationPortMax))
		} else {
			args = append(args, strconv.Itoa(mIP.DestinationPortMin))
		}
	}
	if mIP.HasICMPType {
		args = append(args, "--ip6-icmp-type")
		if mIP.ICMPTypeInvert {
			args = append(args, "!")
		}
		str := ""
		if mIP.ICMPTypeMin != network.ICMPv6TypeNull {
			str += mIP.ICMPTypeMin.String()
		}
		if mIP.ICMPTypeMax != network.ICMPv6TypeNull {
			str += ":" + mIP.ICMPCodeMax.String()
		}
		if mIP.ICMPCodeMin != network.ICMPv6CodeNull {
			str += "/" + mIP.ICMPCodeMin.String()
		}
		if mIP.ICMPCodeMax != network.ICMPv6CodeNull {
			str += mIP.ICMPCodeMax.String()
		}
		args = append(args, str)
	}
	return args
}

type OptionMatchLimit func(*MatchLimit)

// Maximum average matching rate.
func WithMatchLimit(value rate.Rate) OptionMatchLimit {
	return func(mLimit *MatchLimit) {
		mLimit.Limit = value
		mLimit.HasLimit = true
	}
}

// Maximum initial number of packet to match: this number gets recharged
// by one every time the limit specified above is not reached, up to this
// number; the default is 5.
func WithMatchLimitBurst(number int) OptionMatchLimit {
	return func(mLimit *MatchLimit) {
		mLimit.LimitBurst = number
	}
}

func NewMatchLimit(opts ...OptionMatchLimit) (*MatchLimit, error) {
	match := &MatchLimit{
		baseMatch: baseMatch{
			matchType: MatchTypeLimit,
		},
		LimitBurst: -1,
	}
	match.setChild(match)
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// This module matches at a limited rate using a token bucket filter. A rule
// using this extension will match until this limit is reached. It can be used
// with the LOG watcher to give limited logging, for example. It's use is the
// same as the limit match of iptables.
type MatchLimit struct {
	baseMatch
	Limit      rate.Rate
	HasLimit   bool
	LimitBurst int
}

func (mLimit *MatchLimit) Short() string {
	return strings.Join(mLimit.ShortArgs(), " ")
}

func (mLimit *MatchLimit) ShortArgs() []string {
	args := make([]string, 0, 4)
	if mLimit.HasLimit {
		args = append(args, "--limit", mLimit.Limit.String())
	}
	if mLimit.LimitBurst > -1 {
		args = append(args, "--limit-burst", strconv.Itoa(mLimit.LimitBurst))
	}
	return args
}

// The logical bridge interface via which a frame is going to be received
// (this option is useful in the INPUT, FORWARD, PREROUTING and BROUTING
// chains). If the interface name ends with '+', then any interface
// name that begins with this name(disregarding '+') will match.
func NewMatchLogicalIn(yes bool, name string) (*MatchLogicalIn, error) {
	match := &MatchLogicalIn{
		baseMatch: baseMatch{
			matchType: MatchTypeLogicalIn,
		},
		LogicalIn:       name,
		LogicalInInvert: !yes,
	}
	match.setChild(match)
	return match, nil
}

type MatchLogicalIn struct {
	baseMatch
	LogicalIn string
	// invert
	LogicalInInvert bool
}

func (mLogicalIn *MatchLogicalIn) Short() string {
	return strings.Join(mLogicalIn.ShortArgs(), " ")
}

func (mLogicalIn *MatchLogicalIn) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--logical-in")
	if mLogicalIn.LogicalInInvert {
		args = append(args, "!")
	}
	args = append(args, mLogicalIn.LogicalIn)
	return args
}

// The logical bridge interface via which a frame is going to be sent
// (this optio name v string  he INPUT, FORWARD, PREROUTING and BROUTING
// chains). If the interface name ends with '+', then any interface
// name that begins with this name(disregarding '+') will match.
func NewMatchLogicalOut(yes bool, name string) (*MatchLogicalOut, error) {
	match := &MatchLogicalOut{
		baseMatch: baseMatch{
			matchType: MatchTypeLogicalOut,
		},
		LogicalOut:       name,
		LogicalOutInvert: !yes,
	}
	match.setChild(match)
	return match, nil
}

type MatchLogicalOut struct {
	baseMatch
	LogicalOut string
	// invert
	LogicalOutInvert bool
}

func (mLogicalOut *MatchLogicalOut) Short() string {
	return strings.Join(mLogicalOut.ShortArgs(), " ")
}

func (mLogicalOut *MatchLogicalOut) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--logical-in")
	if mLogicalOut.LogicalOutInvert {
		args = append(args, "!")
	}
	args = append(args, mLogicalOut.LogicalOut)
	return args
}

// The argument value takes mostly 2 values, mark or mark/mask.
// Matched frames with the given unsigned mark value. If a value and mask are
// specified, the logical AND of the mark value of the frame and the user-specified
// mask is taken before comparing it with the user-specified mark value. When only
// mark value is specified, the packet only matches when the mark value of the frame
// equals the user-specified mark value. If only a mask is specified, the logical AND
// of the mark value of the frame and the user-specified mask is taken and the frame
// matches when the result of this logical AND is non-zero. Only specifying a mask
// is useful to match multiple mark values.
func NewMatchMark(yes bool, value ...int) (*MatchMark, error) {
	match := &MatchMark{
		baseMatch: baseMatch{
			matchType: MatchTypeMark,
		},
		Value:      -1,
		Mask:       -1,
		MarkInvert: !yes,
	}
	match.setChild(match)
	switch len(value) {
	case 1:
		match.Value = value[0]
		match.Mask = -1
	case 2:
		match.Value = value[0]
		match.Mask = value[1]
	}
	return match, nil
}

type MatchMark struct {
	baseMatch
	Value int
	Mask  int
	// invert
	MarkInvert bool
}

func (mMark *MatchMark) Short() string {
	return strings.Join(mMark.ShortArgs(), " ")
}

func (mMark *MatchMark) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--mark")
	if mMark.Value > -1 {
		if mMark.MarkInvert {
			args = append(args, "!")
		}
		if mMark.Mask > -1 {
			args = append(args,
				strconv.Itoa(mMark.Value)+"/"+strconv.Itoa(mMark.Mask))
		} else {
			args = append(args, strconv.Itoa(mMark.Value))
		}
	}
	return args
}

func NewMatchOutInterface(yes bool, name string) (*MatchOutInterface, error) {
	match := &MatchOutInterface{
		baseMatch: baseMatch{
			matchType: MatchTypeOutInterface,
		},
		OutInterfaceInvert: !yes,
		OutInterface:       name,
	}
	match.setChild(match)
	return match, nil
}

type MatchOutInterface struct {
	baseMatch
	OutInterface string
	// invert
	OutInterfaceInvert bool
}

func (mOutInterface *MatchOutInterface) Short() string {
	return strings.Join(mOutInterface.ShortArgs(), " ")
}

func (mOutInterface *MatchOutInterface) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-i")
	if mOutInterface.OutInterfaceInvert {
		args = append(args, "!")
	}
	args = append(args, mOutInterface.OutInterface)
	return args
}

func (mOutInterface *MatchOutInterface) Long() string {
	return strings.Join(mOutInterface.LongArgs(), " ")
}

func (mOutInterface *MatchOutInterface) LongArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--in-interface")
	if mOutInterface.OutInterfaceInvert {
		args = append(args, "!")
	}
	args = append(args, mOutInterface.OutInterface)
	return args
}

func NewMatchPktType(yes bool, pktType network.PktType) (*MatchPktType, error) {
	match := &MatchPktType{
		baseMatch: baseMatch{
			matchType: MatchTypePktType,
		},
		PktTypeInvert: !yes,
		PktType:       pktType,
	}
	match.setChild(match)
	return match, nil
}

type MatchPktType struct {
	baseMatch
	PktType network.PktType
	// invert
	PktTypeInvert bool
}

func (mPktType *MatchPktType) Short() string {
	return strings.Join(mPktType.ShortArgs(), " ")
}

func (mPktType *MatchPktType) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--pkttype-type")
	if mPktType.PktType > -1 {
		if mPktType.PktTypeInvert {
			args = append(args, "!")
		}
		args = append(args, mPktType.PktType.String())
	}
	return args
}

func NewMatchProtocol(yes bool, protocol network.Protocol) (*MatchProtocol, error) {
	match := &MatchProtocol{
		baseMatch: baseMatch{
			matchType: MatchTypeProtocol,
		},
		ProtocolInvert: !yes,
		Protocol:       protocol,
	}
	match.setChild(match)
	return match, nil
}

// The protocol that was responsible for creating the frame. This can be a
// hexadecimal number, above 0x0600. The protocol field of the Ethernet frame
// can be used to denote the length of the header(802.2/802.3 networks). When
// the value of that field is below or equals 0x0600, the value equals the
// size of the header and shouldn't be used as a protocol number. Instead, all
// frames where the protocol field is used as the length field are assumed to
// be of the same 'protocol', related to 802.3.
type MatchProtocol struct {
	baseMatch
	Protocol network.Protocol
	// invert
	ProtocolInvert bool
}

func (mProtocol *MatchProtocol) Short() string {
	return strings.Join(mProtocol.ShortArgs(), " ")
}

func (mProtocol *MatchProtocol) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-p")
	if mProtocol.ProtocolInvert {
		args = append(args, "!")
	}
	args = append(args, mProtocol.Protocol.Value())
	return args
}

func (mProtocol *MatchProtocol) Long() string {
	return strings.Join(mProtocol.LongArgs(), " ")
}

func (mProtocol *MatchProtocol) LongArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--protocol")
	if mProtocol.ProtocolInvert {
		args = append(args, "!")
	}
	args = append(args, mProtocol.Protocol.Value())
	return args
}

// The source MAC address with or without mask.
func NewMatchSource(yes bool, addr network.Address) (*MatchSource, error) {
	match := &MatchSource{
		baseMatch: baseMatch{
			matchType: MatchTypeSource,
		},
		SourceInvert: !yes,
		Source:       addr,
	}
	match.setChild(match)
	return match, nil
}

type MatchSource struct {
	baseMatch
	Source network.Address
	// invert
	SourceInvert bool
}

func (mSource *MatchSource) Short() string {
	return strings.Join(mSource.ShortArgs(), " ")
}

func (mSource *MatchSource) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-d")
	if mSource.SourceInvert {
		args = append(args, "!")
	}
	args = append(args, mSource.Source.String())
	return args
}

func (mSource *MatchSource) Long() string {
	return strings.Join(mSource.LongArgs(), " ")
}

func (mSource *MatchSource) LongArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--destination")
	if mSource.SourceInvert {
		args = append(args, "!")
	}
	args = append(args, mSource.Source.String())
	return args
}

type OptionMatchSTP func(*MatchSTP)

// The BPDU type(0-255).
func WithMatchSTPType(yes bool, typ uint8) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.TypeInvert = !yes
		mSTP.Typ = typ
		mSTP.HasType = true
	}
}

// The BPDU flags(0-255).
func WithMatchSTPFlags(yes bool, flags uint8) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.FlagInvert = !yes
		mSTP.Flags = flags
		mSTP.HasFlags = true
	}
}

// The argument priority takes mostly 2 values, min or min-max.
// The root priority(0-65535) range.
func WithMatchSTPRootPriority(yes bool, priority ...uint16) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.RootPriorityInvert = !yes
		switch len(priority) {
		case 1:
			mSTP.RootPriorityMin = priority[0]
			mSTP.HasRootPriorityMin = true
		case 2:
			mSTP.RootPriorityMin = priority[0]
			mSTP.RootPriorityMax = priority[1]
			mSTP.HasRootPriorityMin = true
			mSTP.HasRootPriorityMax = true
		}
	}
}

// The root mac address.
func WithMatchSTPRootAddr(yes bool, mac net.HardwareAddr) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.RootAddrInvert = !yes
		mSTP.RootAddr = network.NewHardwareAddr(mac)
	}
}

// The argument cost takes mostly 2 values, min or min-max.
// The root patch cost(0-4294967295) range.
func WithMatchSTPRootCost(yes bool, cost ...uint32) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.RootCostInvert = !yes
		switch len(cost) {
		case 1:
			mSTP.RootCostMin = cost[0]
			mSTP.HasRootCostMin = true
		case 2:
			mSTP.RootCostMin = cost[0]
			mSTP.RootCostMax = cost[1]
			mSTP.HasRootCostMin = true
			mSTP.HasRootCostMax = true
		}
	}
}

// The argument priority takes mostly 2 values, min or min-max.
// The BPDU's sender priority(0-65535) range.
func WithMatchSTPSenderPriority(yes bool, priority ...uint16) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.SenderPriorityInvert = !yes
		switch len(priority) {
		case 1:
			mSTP.SenderPriorityMin = priority[0]
			mSTP.HasSenderPriorityMin = true
		case 2:
			mSTP.SenderPriorityMin = priority[0]
			mSTP.SenderPriorityMax = priority[1]
			mSTP.HasSenderPriorityMin = true
			mSTP.HasSenderPriorityMax = true
		}
	}
}

// The BPDU's sender mac address.
func WithMatchSTPSenderAddr(yes bool, mac net.HardwareAddr) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.SenderAddrInvert = !yes
		mSTP.SenderAddr = network.NewHardwareAddr(mac)
	}
}

// The argument port takes mostly 2 values, min or min-max.
// The port identifier(0-65535) range.
func WithMatchSTPPort(yes bool, port ...uint16) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.PortInvert = !yes
		switch len(port) {
		case 1:
			mSTP.PortMin = port[0]
			mSTP.HasPortMin = true
		case 2:
			mSTP.PortMin = port[0]
			mSTP.PortMax = port[1]
			mSTP.HasPortMin = true
			mSTP.HasPortMax = true
		}
	}
}

// The argument age takes mostly 2 values, min or min-max.
// The message age timer(0-65535) range.
func WithMatchSTPMsgAge(yes bool, age ...uint16) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.MsgAgeInvert = !yes
		switch len(age) {
		case 1:
			mSTP.MsgAgeMin = age[0]
			mSTP.HasMsgAgeMin = true
		case 2:
			mSTP.MsgAgeMin = age[0]
			mSTP.MsgAgeMax = age[1]
			mSTP.HasMsgAgeMin = true
			mSTP.HasMsgAgeMax = true
		}
	}
}

// The argument age takes mostly 2 values, min or min-max.
// The max age timer(0-65535) range.
func WithMatchSTPMaxAge(yes bool, age ...uint16) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.MaxAgeInvert = !yes
		switch len(age) {
		case 1:
			mSTP.MaxAgeMin = age[0]
			mSTP.HasMaxAgeMin = true
		case 2:
			mSTP.MaxAgeMin = age[0]
			mSTP.MaxAgeMax = age[1]
			mSTP.HasMaxAgeMin = true
			mSTP.HasMaxAgeMax = true
		}
	}
}

// The argument time takes mostly 2 values, min or min-max.
// The hello time timer(0-65535) range.
func WithMatchSTPHelloTime(yes bool, time ...uint16) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.HelloTimeInvert = !yes
		switch len(time) {
		case 1:
			mSTP.HelloTimeMin = time[0]
			mSTP.HasHelloTimeMin = true
		case 2:
			mSTP.HelloTimeMin = time[0]
			mSTP.HelloTimeMax = time[1]
			mSTP.HasHelloTimeMin = true
			mSTP.HasHelloTimeMax = true
		}
	}
}

// The delay takes mostly 2 values, min or min-max.
// The forward delay timer(0-65535) range.
func WithMatchSTPForwardDelay(yes bool, delay ...uint16) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.ForwardDelayInvert = !yes
		switch len(delay) {
		case 1:
			mSTP.ForwardDelayMin = delay[0]
			mSTP.HasForwardDelayMin = true
		case 2:
			mSTP.ForwardDelayMin = delay[0]
			mSTP.ForwardDelayMax = delay[1]
			mSTP.HasForwardDelayMin = true
			mSTP.HasForwardDelayMax = true
		}
	}
}

func NewMatchSTP(opts ...OptionMatchSTP) (*MatchSTP, error) {
	match := &MatchSTP{
		baseMatch: baseMatch{
			matchType: MatchTypeSTP,
		},
	}
	match.setChild(match)
	return match, nil
}

// Specify stp BPDU(bridge protocol data unit) fields. The destination
// address must be specified as the bridge group address(BGA). For all
// options for which a range of values can be specified, it holds that
// if the lower bound is omitted, then the lowest possible lower bound
// for that option is used, while if the upper bound is omitted, the
// highest possible upper bound for that option is used.
type MatchSTP struct {
	baseMatch
	Typ     uint8
	HasType bool

	Flags    uint8
	HasFlags bool

	RootPriorityMin, RootPriorityMax       uint16
	HasRootPriorityMin, HasRootPriorityMax bool

	RootAddr network.Address

	RootCostMin, RootCostMax       uint32
	HasRootCostMin, HasRootCostMax bool

	SenderPriorityMin, SenderPriorityMax       uint16
	HasSenderPriorityMin, HasSenderPriorityMax bool

	SenderAddr network.Address

	PortMin, PortMax       uint16
	HasPortMin, HasPortMax bool

	MsgAgeMin, MsgAgeMax       uint16
	HasMsgAgeMin, HasMsgAgeMax bool

	MaxAgeMin, MaxAgeMax       uint16
	HasMaxAgeMin, HasMaxAgeMax bool

	HelloTimeMin, HelloTimeMax       uint16
	HasHelloTimeMin, HasHelloTimeMax bool

	ForwardDelayMin, ForwardDelayMax       uint16
	HasForwardDelayMin, HasForwardDelayMax bool
	// invert
	TypeInvert           bool
	FlagInvert           bool
	RootPriorityInvert   bool
	RootAddrInvert       bool
	RootCostInvert       bool
	SenderPriorityInvert bool
	SenderAddrInvert     bool
	PortInvert           bool
	MsgAgeInvert         bool
	MaxAgeInvert         bool
	HelloTimeInvert      bool
	ForwardDelayInvert   bool
}

func (mSTP *MatchSTP) Short() string {
	return strings.Join(mSTP.ShortArgs(), " ")
}

func (mSTP *MatchSTP) ShortArgs() []string {
	args := make([]string, 0, 36)
	if mSTP.HasType {
		args = append(args, "--stp-type")
		if mSTP.TypeInvert {
			args = append(args, "!")
		}
		args = append(args, strconv.Itoa(int(mSTP.Typ)))
	}
	if mSTP.HasFlags {
		args = append(args, "--stp-flags")
		if mSTP.FlagInvert {
			args = append(args, "!")
		}
		args = append(args, strconv.Itoa(int(mSTP.Flags)))
	}
	if mSTP.HasRootPriorityMin {
		args = append(args, "--stp-root-prio")
		if mSTP.RootPriorityInvert {
			args = append(args, "!")
		}
		if mSTP.HasRootPriorityMax {
			args = append(args, strconv.Itoa(int(mSTP.RootPriorityMax))+
				":"+strconv.Itoa(int(mSTP.RootPriorityMin)))
		} else {
			args = append(args, strconv.Itoa(int(mSTP.RootCostMin)))
		}
	}
	if mSTP.RootAddr != nil {
		args = append(args, "--stp-root-addr")
		if mSTP.RootAddrInvert {
			args = append(args, "!")
		}
		args = append(args, mSTP.RootAddr.String())
	}
	if mSTP.HasRootCostMin {
		args = append(args, "--stp-root-cost")
		if mSTP.RootCostInvert {
			args = append(args, "!")
		}
		if mSTP.HasRootCostMax {
			args = append(args, strconv.Itoa(int(mSTP.RootCostMin))+
				":"+strconv.Itoa(int(mSTP.RootCostMax)))
		} else {
			args = append(args, strconv.Itoa(int(mSTP.RootCostMin)))
		}
	}
	if mSTP.HasSenderPriorityMin {
		args = append(args, "--stp-sender-prio")
		if mSTP.SenderPriorityInvert {
			args = append(args, "!")
		}
		if mSTP.HasSenderPriorityMax {
			args = append(args, strconv.Itoa(int(mSTP.SenderPriorityMin))+
				":"+strconv.Itoa(int(mSTP.SenderPriorityMax)))
		} else {
			args = append(args, strconv.Itoa(int(mSTP.SenderPriorityMin)))
		}
	}
	if mSTP.SenderAddr != nil {
		args = append(args, "--stp-sender-addr")
		if mSTP.SenderAddrInvert {
			args = append(args, "!")
		}
		args = append(args, mSTP.SenderAddr.String())
	}
	if mSTP.HasPortMin {
		args = append(args, "--stp-port")
		if mSTP.PortInvert {
			args = append(args, "!")
		}
		if mSTP.HasPortMax {
			args = append(args, strconv.Itoa(int(mSTP.PortMin))+
				":"+strconv.Itoa(int(mSTP.PortMax)))
		} else {
			args = append(args, strconv.Itoa(int(mSTP.PortMin)))
		}
	}
	if mSTP.HasMsgAgeMin {
		args = append(args, "--stp-msg-age")
		if mSTP.MsgAgeInvert {
			args = append(args, "!")
		}
		if mSTP.HasPortMax {
			args = append(args, strconv.Itoa(int(mSTP.MsgAgeMin))+
				":"+strconv.Itoa(int(mSTP.MsgAgeMax)))
		} else {
			args = append(args, strconv.Itoa(int(mSTP.MsgAgeMin)))
		}
	}
	if mSTP.HasMaxAgeMin {
		args = append(args, "--stp-max-age")
		if mSTP.MaxAgeInvert {
			args = append(args, "!")
		}
		if mSTP.HasMaxAgeMax {
			args = append(args, strconv.Itoa(int(mSTP.MaxAgeMin))+
				":"+strconv.Itoa(int(mSTP.MaxAgeMax)))
		} else {
			args = append(args, strconv.Itoa(int(mSTP.MaxAgeMin)))
		}
	}
	if mSTP.HasHelloTimeMin {
		args = append(args, "--stp-hello-time")
		if mSTP.HelloTimeInvert {
			args = append(args, "!")
		}
		if mSTP.HasHelloTimeMax {
			args = append(args, strconv.Itoa(int(mSTP.HelloTimeMin))+
				":"+strconv.Itoa(int(mSTP.HelloTimeMax)))
		} else {
			args = append(args, strconv.Itoa(int(mSTP.HelloTimeMin)))
		}
	}
	if mSTP.HasForwardDelayMin {
		args = append(args, "--stp-forward-delay")
		if mSTP.ForwardDelayInvert {
			args = append(args, "!")
		}
		if mSTP.HasForwardDelayMax {
			args = append(args, strconv.Itoa(int(mSTP.ForwardDelayMin))+
				":"+strconv.Itoa(int(mSTP.ForwardDelayMax)))
		} else {
			args = append(args, strconv.Itoa(int(mSTP.ForwardDelayMin)))
		}
	}
	return args
}

type OptionMatchVLAN func(*MatchVLAN)

// The VLAN identifier filed(VID). Decimal number from 0 to 4095.
func WithMatchVLANID(yes bool, vlan int) OptionMatchVLAN {
	return func(mVLAN *MatchVLAN) {
		mVLAN.IDInvert = !yes
		mVLAN.ID = vlan
	}
}

// The user priority field, a decimal number from 0 to 7. The VID should
// be set to 0("null VID") or unspecified(in the latter case the VID is
// deliberately set to 0).
func WithMatchVLANPriority(yes bool, priority int) OptionMatchVLAN {
	return func(mVLAN *MatchVLAN) {
		mVLAN.PriorityInvert = !yes
		mVLAN.Priority = priority
	}
}

// The encapsulated Ethernet frame type/length. Specified as a hexadecimal
// number from 0x0000 to 0xFFFF.
func WithMatchVLANEncapsulation(yes bool, encapsulation [2]byte) OptionMatchVLAN {
	return func(mVLAN *MatchVLAN) {
		mVLAN.EncapsulationInvert = !yes
		mVLAN.HasEncapsulation = true
		mVLAN.Encapsulation = encapsulation
	}
}

func NewMatchVLAN(opts ...OptionMatchVLAN) (*MatchVLAN, error) {
	match := &MatchVLAN{
		baseMatch: baseMatch{
			matchType: MatchTypeVLAN,
		},
		ID:       -1,
		Priority: -1,
	}
	match.setChild(match)
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchVLAN struct {
	baseMatch
	ID               int
	Priority         int
	Encapsulation    [2]byte
	HasEncapsulation bool
	// invert
	IDInvert            bool
	PriorityInvert      bool
	EncapsulationInvert bool
}

func (mVLAN *MatchVLAN) Short() string {
	return strings.Join(mVLAN.ShortArgs(), " ")
}

func (mVLAN *MatchVLAN) ShortArgs() []string {
	args := make([]string, 0, 9)
	if mVLAN.ID > -1 {
		args = append(args, "--vlan-id")
		if mVLAN.IDInvert {
			args = append(args, "!")
		}
		args = append(args, strconv.Itoa(mVLAN.ID))
	}
	if mVLAN.Priority > -1 {
		args = append(args, "--vlan-prio")
		if mVLAN.PriorityInvert {
			args = append(args, "!")
		}
		args = append(args, strconv.Itoa(mVLAN.Priority))
	}
	if mVLAN.HasEncapsulation {
		args = append(args, "--vlan-encap")
		if mVLAN.EncapsulationInvert {
			args = append(args, "!")
		}
		encap := hex.EncodeToString([]byte{mVLAN.Encapsulation[0],
			mVLAN.Encapsulation[1]})
		args = append(args, encap)
	}
	return args
}
