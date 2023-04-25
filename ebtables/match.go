package ebtables

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/singchia/go-hammer/tree"
	"github.com/singchia/go-xtables"
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
	Equal(Match) bool
}

func matchFactory(matchType MatchType) Match {
	switch matchType {
	case MatchType802dot3:
		match, _ := newMatch802dot3()
		return match
	case MatchTypeAmong:
		match, _ := newMatchAmong()
		return match
	case MatchTypeARP:
		match, _ := newMatchARP()
		return match
	case MatchTypeDestination:
		match, _ := newMatchDestination(false, nil)
		return match
	case MatchTypeInInterface:
		match, _ := newMatchInInterface(false, "")
		return match
	case MatchTypeIP:
		match, _ := newMatchIP()
		return match
	case MatchTypeIPv6:
		match, _ := newMatchIPv6()
		return match
	case MatchTypeLimit:
		match, _ := newMatchLimit()
		return match
	case MatchTypeLogicalIn:
		match, _ := newMatchLogicalIn(false, "")
		return match
	case MatchTypeLogicalOut:
		match, _ := newMatchLogicalOut(false, "")
		return match
	case MatchTypeMark:
		match, _ := newMatchMark(false, -1, -1)
		return match
	case MatchTypeOutInterface:
		match, _ := newMatchOutInterface(false, "")
		return match
	case MatchTypePktType:
		match, _ := newMatchPktType(false, -1)
		return match
	case MatchTypeProtocol:
		match, _ := newMatchProtocol(false, 0)
		return match
	case MatchTypeSource:
		match, _ := newMatchSource(false, nil)
		return match
	case MatchTypeSTP:
		match, _ := newMatchSTP()
		return match
	case MatchTypeVLAN:
		match, _ := newMatchVLAN()
		return match
	}
	return nil
}

type baseMatch struct {
	matchType MatchType
	child     Match
}

func (bm *baseMatch) setChild(child Match) {
	bm.child = child
}

func (bm *baseMatch) Type() MatchType {
	return bm.matchType
}

func (bm *baseMatch) Short() string {
	if bm.child != nil {
		return bm.child.Short()
	}
	return ""
}

func (bm *baseMatch) ShortArgs() []string {
	if bm.child != nil {
		return bm.child.ShortArgs()
	}
	return nil
}

func (bm *baseMatch) Long() string {
	return bm.Short()
}

func (bm *baseMatch) LongArgs() []string {
	return bm.LongArgs()
}

func (bm *baseMatch) Parse(params []byte) (int, bool) {
	return 0, false
}

func (bm *baseMatch) Equal(mth Match) bool {
	return bm.Short() == mth.Short()
}

func (bm *baseMatch) Depends() []MatchType {
	return nil
}

type OptionMatch802dot3 func(*Match802dot3)

// DSAP and SSAP are two one byte 802.3 fields.  The bytes are always equal,
// so only one byte(hexadecimal) is needed as an argument.
func WithMatch802dot3SAP(invert bool, sap byte) OptionMatch802dot3 {
	return func(m802dot3 *Match802dot3) {
		m802dot3.SAP = sap
		m802dot3.HasSAP = true
		m802dot3.SAPInvert = invert
	}
}

// If the 802.3 DSAP and SSAP values are 0xaa then the SNAP type field must
// be consulted to determine the payload protocol. This is a two byte(hexadecimal)
// argument. Only 802.3 frames with DSAP/SSAP 0xaa are checked for type.
func WithMatch802dot3Type(invert bool, typ [2]byte) OptionMatch802dot3 {
	return func(m802dot3 *Match802dot3) {
		m802dot3.Typ = typ
		m802dot3.HasType = true
		m802dot3.TypeInvert = invert
	}
}

func newMatch802dot3(opts ...OptionMatch802dot3) (*Match802dot3, error) {
	match := &Match802dot3{
		baseMatch: &baseMatch{
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
	*baseMatch
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

func (m802dot3 *Match802dot3) Parse(main []byte) (int, bool) {
	// 1. "--802_3(-sap|-type)( !)? 0x([0-9A-Za-z]+))?" #1 #2 #3
	pattern := `--802_3-(sap|type)( !)? 0x([0-9A-Za-z]+) *`
	reg := regexp.MustCompile(pattern)
	index := 0
	for len(main) > 0 {
		matches := reg.FindSubmatch(main)
		if len(matches) != 4 {
			goto END
		}
		invert := false
		if len(matches[2]) != 0 {
			invert = true
		}
		typ := string(matches[1])
		hex, err := hex.DecodeString(string(matches[3]))
		if err != nil {
			return 0, false
		}
		switch typ {
		case "sap":
			if len(hex) != 1 {
				return 0, false
			}
			m802dot3.SAP = hex[0]
			m802dot3.HasSAP = true
			m802dot3.SAPInvert = invert
		case "type":
			if len(hex) != 2 {
				return 0, false
			}
			m802dot3.Typ = [2]byte{hex[0], hex[1]}
			m802dot3.HasType = true
			m802dot3.TypeInvert = invert
		}
		index += len(matches[0])
		main = main[len(matches[0]):]
	}
END:
	if index != 0 {
		return index, true
	}
	return 0, false
}

type OptionMatchAmong func(*MatchAmong)

type Among struct {
	MAC net.HardwareAddr
	IP  net.IP
}

// Compare the MAC destination to the given list. If the Ethernet frame
// has type IPv4 or ARP, then comparison with MAC/IP destination address
// pairs from the list is possible.
func WithMatchAmongDst(invert bool, list []*Among) OptionMatchAmong {
	return func(mAmong *MatchAmong) {
		mAmong.DstInvert = invert
		mAmong.Dst = list
	}
}

// Compare the MAC source to the given list. If the Ethernet frame has
// type IPv4 or ARP, then comparison with MAC/IP srouce address pairs
// from the list is possible.
func WithMatchAmongSrc(invert bool, list []*Among) OptionMatchAmong {
	return func(mAmong *MatchAmong) {
		mAmong.SrcInvert = invert
		mAmong.Src = list
	}
}

// List is read in from the specified file. A list entry has the following
// format: xx:xx:xx:xx:xx:xx[=ip.ip.ip.ip][,]
// This option conflicts with WithMatchAmongDst, using it will overwirte
// the latter.
func WithMatchAmongDstFile(invert bool, path string) OptionMatchAmong {
	return func(mAmong *MatchAmong) {
		mAmong.DstFileInvert = invert
		mAmong.DstFile = path
	}
}

// List is read in from the specified file. A list entry has the following
// format: xx:xx:xx:xx:xx:xx[=ip.ip.ip.ip][,]
// the latter.
func WithMatchAmongSrcFile(invert bool, path string) OptionMatchAmong {
	return func(mAmong *MatchAmong) {
		mAmong.SrcFileInvert = invert
		mAmong.SrcFile = path
	}
}

func newMatchAmong(opts ...OptionMatchAmong) (*MatchAmong, error) {
	match := &MatchAmong{
		baseMatch: &baseMatch{
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
// the list, the frame doesn't match the rule unless invert=true was used.
type MatchAmong struct {
	*baseMatch
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

func (mAmong *MatchAmong) Parse(main []byte) (int, bool) {
	// 1. "--among-(-src|-dst)( !)? ([[:graph:]]+)) *" #1 #2 #3
	pattern := `--among-(src|dst)( !)? ([[:graph:]]+) *`
	reg := regexp.MustCompile(pattern)
	index := 0
	for len(main) > 0 {
		matches := reg.FindSubmatch(main)
		if len(matches) != 3 {
			goto END
		}
		invert := false
		if len(matches[2]) != 0 {
			invert = true
		}
		amongs := []*Among{}

		list := string(matches[3])
		pairs := strings.Split(list, ",")
		for _, pair := range pairs {
			if len(pair) == 0 {
				continue
			}
			among := &Among{}
			kv := strings.Split(pair, "=")
			if len(kv) >= 1 {
				// mac only
				mac, err := net.ParseMAC(kv[0])
				if err != nil {
					goto END
				}
				among.MAC = mac
			}
			if len(kv) >= 2 {
				among.IP = net.ParseIP(kv[1])
			}
			amongs = append(amongs, among)
		}

		switch string(matches[1]) {
		case "src":
			mAmong.Src = amongs
			mAmong.SrcInvert = invert
		case "dst":
			mAmong.Dst = amongs
			mAmong.DstInvert = invert
		}
		index += len(matches[0])
		main = main[len(matches[0]):]
	}
END:
	if index != 0 {
		return index, true
	}
	return 0, false
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
				return "", xtables.ErrArgsWithoutMAC
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
func WithMatchARPOpCode(invert bool, opcode network.ARPOpCode) OptionMatchARP {
	return func(mARP *MatchARP) {
		mARP.OpCodeInvert = invert
		mARP.OpCode = opcode
	}
}

// The hardware type, Most (R)ARP packets have Ethernet as hardware type.
func WithMatchARPHWType(invert bool, hwtype network.HardwareType) OptionMatchARP {
	return func(mARP *MatchARP) {
		mARP.HWTypeInvert = invert
		mARP.HWType = hwtype
	}
}

// The protocol type for which the (R)ARP is used. Most (R)ARP packets have
// protocol type IPv4.
func WithMatchARPProtoType(invert bool, prototype network.EthernetType) OptionMatchARP {
	return func(mARP *MatchARP) {
		mARP.ProtoTypeInvert = invert
		mARP.HasProtoType = true
		mARP.ProtoType = prototype
	}
}

// The (R)ARP IP source address specification.
// Getting addr by using network.NewIP(net.IP) or network.NewIPNet(*net.IPNet)
func WithMatchARPIPSrc(invert bool, addr network.Address) OptionMatchARP {
	return func(mARP *MatchARP) {
		mARP.IPSrcInvert = invert
		mARP.IPSrc = addr
	}
}

// The (R)ARP IP destination address specification.
// Getting addr by using network.NewIP(net.IP) or network.NewIPNet(*net.IPNet).
func WithMatchARPIPDst(invert bool, addr network.Address) OptionMatchARP {
	return func(mARP *MatchARP) {
		mARP.IPDstInvert = invert
		mARP.IPDst = addr
	}
}

// The (R)ARP MAC source address specification.
// Getting addr by using network.NewHardwareAddr(net.HardwareAddr) or
// network.NewHardwareAddrMask(net.HardwareAddr, net.HardwareAddr).
func WithMatchARPMACSrc(invert bool, addr network.Address) OptionMatchARP {
	return func(mARP *MatchARP) {
		mARP.MACSrcInvert = invert
		mARP.MACSrc = addr
	}
}

// The (R)ARP MAC destination address specification.
// Getting addr by using network.NewHardwareAddr(net.HardwareAddr) or
// network.NewHardwareAddrMask(net.HardwareAddr, net.HardwareAddr).
func WithMatchARPMACDst(invert bool, addr network.Address) OptionMatchARP {
	return func(mARP *MatchARP) {
		mARP.MACDstInvert = invert
		mARP.MACDst = addr
	}
}

// Checks for ARP gratuitous packets: checks equality of IPv4 source
// address and IPv4 destination address inside the ARP header.
func WithMatchARPGratuitous(invert bool) OptionMatchARP {
	return func(mARP *MatchARP) {
		mARP.GratuitousInvert = invert
		mARP.HasGratuitous = true
	}
}

func newMatchARP(opts ...OptionMatchARP) (*MatchARP, error) {
	match := &MatchARP{
		baseMatch: &baseMatch{
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
	*baseMatch
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

func (mARP *MatchARP) Parse(main []byte) (int, bool) {
	// 1. "(! )?--arp-(opcode|htype|ptype|ip-src|ip-dst|mac-src|mac-dst|gratuitous)" #1 #2
	// 2. "(( !)? ([[:graph:]]+))? *" #3 #4 #5
	pattern := `(! )?--arp-(opcode|htype|ptype|ip-src|ip-dst|mac-src|mac-dst|gratuitous)` +
		`(( !)? ([[:graph:]]+))? *`
	reg := regexp.MustCompile(pattern)
	index := 0
	for len(main) > 0 {
		matches := reg.FindSubmatch(main)
		if len(matches) != 5 {
			goto END
		}
		invert := false
		if len(matches[1]) != 0 || len(matches[3]) != 0 {
			invert = true
		}
		value := string(matches[5])
		switch string(matches[2]) {
		case "opcode":
			code, err := network.ParseARPOpCode(value)
			if err != nil {
				goto END
			}
			mARP.OpCode = code
			mARP.OpCodeInvert = invert
		case "htype":
			hwtype, err := network.ParseHardwareType(value)
			if err != nil {
				goto END
			}
			mARP.HWType = hwtype
			mARP.HWTypeInvert = invert
		case "ptype":
			ptype, err := network.ParseEthernetType(value)
			if err != nil {
				goto END
			}
			mARP.ProtoType = ptype
			mARP.HasProtoType = true
			mARP.ProtoTypeInvert = invert
		case "ip-src":
			addr, err := network.ParseAddress(value)
			if err != nil {
				goto END
			}
			mARP.IPSrc = addr
			mARP.IPSrcInvert = invert
		case "ip-dst":
			addr, err := network.ParseAddress(value)
			if err != nil {
				goto END
			}
			mARP.IPDst = addr
			mARP.IPDstInvert = invert
		case "mac-src":
			addr, err := network.ParseAddress(value)
			if err != nil {
				goto END
			}
			mARP.MACSrc = addr
			mARP.MACSrcInvert = invert
		case "mac-dst":
			addr, err := network.ParseAddress(value)
			if err != nil {
				goto END
			}
			mARP.MACDst = addr
			mARP.MACDstInvert = invert
		case "gratuitous":
			mARP.HasGratuitous = true
			mARP.GratuitousInvert = invert
		}
		index += len(matches[0])
		main = main[len(matches[0]):]
	}
END:
	if index != 0 {
		return index, true
	}
	return 0, false
}

// The destination MAC address with or without mask.
func newMatchDestination(invert bool, addr network.Address) (*MatchDestination, error) {
	match := &MatchDestination{
		baseMatch: &baseMatch{
			matchType: MatchTypeDestination,
		},
		DestinationInvert: invert,
		Destination:       addr,
	}
	match.setChild(match)
	return match, nil
}

type MatchDestination struct {
	*baseMatch
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

func (mDestination *MatchDestination) Parse(main []byte) (int, bool) {
	// 1. "-d( !)? (([0-9A-Za-z:]+)(/([0-9A-Za-z:]+))?) *" #1 #2 #3 #4 #5
	pattern := `-d( !)? (([0-9A-Za-z:]+)(/([0-9A-Za-z:]+))?) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 6 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mDestination.DestinationInvert = true
	}
	addr, err := network.ParseAddress(string(matches[2]))
	if err != nil {
		return 0, false
	}
	mDestination.Destination = addr
	return len(matches[0]), true
}

func newMatchInInterface(invert bool, name string) (*MatchInInterface, error) {
	match := &MatchInInterface{
		baseMatch: &baseMatch{
			matchType: MatchTypeInInterface,
		},
		InInterfaceInvert: invert,
		InInterface:       name,
	}
	match.setChild(match)
	return match, nil
}

type MatchInInterface struct {
	*baseMatch
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

func (mInInterface *MatchInInterface) Parse(main []byte) (int, bool) {
	// 1. "-i( !)? ([[:graph:]]+) *" #1 #2
	pattern := `-i( !)? ([[:graph:]]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mInInterface.InInterfaceInvert = true
	}
	mInInterface.InInterface = string(matches[2])
	return len(matches[0]), true
}

type OptionMatchIP func(*MatchIP)

// The source IP address. Getting addr by using network.NewIP(net.IP) or
// network.NewIPNet(ipNet *IPNet).
func WithMatchIPSource(invert bool, addr network.Address) OptionMatchIP {
	return func(mIP *MatchIP) {
		mIP.SourceInvert = invert
		mIP.Source = addr
	}
}

// The destination IP address. Getting addr by using network.NewIP(net.IP) or
// network.NewIPNet(ipNet *IPNet).
func WithMatchIPDestination(invert bool, addr network.Address) OptionMatchIP {
	return func(mIP *MatchIP) {
		mIP.DestinationInvert = invert
		mIP.Destination = addr
	}
}

// The IP type of service.
func WithMatchIPTOS(invert bool, tos network.TOS) OptionMatchIP {
	return func(mIP *MatchIP) {
		mIP.TOSInvert = invert
		mIP.TOS = tos
	}
}

// The IP protocol.
func WithMatchIPProtocol(invert bool, protocol network.Protocol) OptionMatchIP {
	return func(mIP *MatchIP) {
		mIP.ProtocolInvert = invert
		mIP.Protocol = protocol
	}
}

// The source port or port range for the IP protocols 6(TCP), 17(UDP),
// 33(DCCP) or 132(SCTP). If min equals -1, 0:max is used; if max equal -1,
// min:65535 is used.
func WithMatchIPSourcePort(invert bool, port ...int) OptionMatchIP {
	return func(mIP *MatchIP) {
		mIP.SourcePortInvert = invert
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
func WithMatchIPDestinationPort(invert bool, port ...int) OptionMatchIP {
	return func(mIP *MatchIP) {
		mIP.DestinationPortInvert = invert
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

func newMatchIP(opts ...OptionMatchIP) (*MatchIP, error) {
	match := &MatchIP{
		baseMatch: &baseMatch{
			matchType: MatchTypeIP,
		},
		SourcePortMin:      -1,
		SourcePortMax:      -1,
		DestinationPortMin: -1,
		DestinationPortMax: -1,
		Protocol:           -1,
	}
	match.setChild(match)
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// Specify IPv4 fields.
type MatchIP struct {
	*baseMatch
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

func (mIP *MatchIP) Parse(main []byte) (int, bool) {
	// 1. "--ip-(source|destination|tos|protocol|source-port|destination-port)" #1
	// 2. "( !)? ([[:graph:]]+) *" #2 #3
	pattern := `--ip-(src|source|dst|destination|tos|proto|protocol|source-port|destination-port)` +
		`( !)? ([[:graph:]]+) *`
	reg := regexp.MustCompile(pattern)
	index := 0
	for len(main) > 0 {
		matches := reg.FindSubmatch(main)
		if len(matches) != 4 {
			goto END
		}
		invert := false
		if len(matches[2]) != 0 {
			invert = true
		}
		value := string(matches[3])
		switch string(matches[1]) {
		case "source", "src":
			addr, err := network.ParseAddress(value)
			if err != nil {
				goto END
			}
			mIP.Source = addr
			mIP.SourceInvert = invert
		case "destination", "dst":
			addr, err := network.ParseAddress(value)
			if err != nil {
				goto END
			}
			mIP.Destination = addr
			mIP.DestinationInvert = invert
		case "tos":
			tos, err := network.ParseTOS(value)
			if err != nil {
				goto END
			}
			mIP.TOS = tos
			mIP.TOSInvert = invert
		case "protocol", "proto":
			proto, err := network.ParseProtocol(value)
			if err != nil {
				goto END
			}
			mIP.Protocol = proto
			mIP.ProtocolInvert = invert
		case "source-port":
			ports := strings.Split(value, ":")
			if len(ports) == 2 {
				min, err := strconv.Atoi(ports[0])
				if err != nil {
					goto END
				}
				mIP.SourcePortMin = min
				max, err := strconv.Atoi(ports[1])
				if err != nil {
					goto END
				}
				mIP.SourcePortMax = max
				mIP.SourceInvert = invert
			} else if len(ports) == 1 {
				min, err := strconv.Atoi(ports[0])
				if err != nil {
					goto END
				}
				mIP.SourcePortMin = min
			}
		case "destination-port":
			ports := strings.Split(value, ":")
			if len(ports) == 2 {
				min, err := strconv.Atoi(ports[0])
				if err != nil {
					goto END
				}
				mIP.DestinationPortMin = min
				max, err := strconv.Atoi(ports[1])
				if err != nil {
					goto END
				}
				mIP.DestinationPortMax = max
				mIP.DestinationInvert = invert
			} else if len(ports) == 1 {
				min, err := strconv.Atoi(ports[0])
				if err != nil {
					goto END
				}
				mIP.DestinationPortMin = min
			}
		}
		index += len(matches[0])
		main = main[len(matches[0]):]
	}
END:
	if index != 0 {
		return index, true
	}
	return 0, false
}

type OptionMatchIPv6 func(*MatchIPv6)

// The source IPv6 address. Getting addr by using network.NewIP(net.IP) or
// network.NewIPNet(ipNet *IPNet).
func WithMatchIPv6Source(invert bool, addr network.Address) OptionMatchIPv6 {
	return func(mIP *MatchIPv6) {
		mIP.SourceInvert = invert
		mIP.Source = addr
	}
}

// The destination IPv6 address. Getting addr by using network.NewIP(net.IP) or
// network.NewIPNet(ipNet *IPNet).
func WithMatchIPv6Destination(invert bool, addr network.Address) OptionMatchIPv6 {
	return func(mIP *MatchIPv6) {
		mIP.DestinationInvert = invert
		mIP.Destination = addr
	}
}

// The IPv6 traffic class, in hexadecimal numbers.
func WithMatchIPv6TrafficClass(invert bool, tclass byte) OptionMatchIPv6 {
	return func(mIP *MatchIPv6) {
		mIP.TrafficClassInvert = invert
		mIP.TrafficClass = tclass
		mIP.HasTrafficClass = true
	}
}

// The IP protocol.
func WithMatchIPv6Protocol(invert bool, protocol network.Protocol) OptionMatchIPv6 {
	return func(mIP *MatchIPv6) {
		mIP.ProtocolInvert = invert
		mIP.Protocol = protocol
	}
}

// The source port or port range for the IPv6 protocols 6(TCP), 17(UDP),
// 33(DCCP) or 132(SCTP). If min equals -1, 0:max is used; if max equal -1,
// min:65535 is used.
func WithMatchIPv6SourcePort(invert bool, port ...int) OptionMatchIPv6 {
	return func(mIP *MatchIPv6) {
		mIP.SourcePortInvert = invert
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
func WithMatchIPv6DestinationPort(invert bool, port ...int) OptionMatchIPv6 {
	return func(mIP *MatchIPv6) {
		mIP.DestinationPortInvert = invert
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
func WithMatchIPv6ICMPType(invert bool, typeMin, typeMax network.ICMPv6Type,
	codeMin, codeMax network.ICMPv6Code) OptionMatchIPv6 {
	return func(mIP *MatchIPv6) {
		mIP.ICMPTypeInvert = invert
		mIP.HasICMPType = true
		mIP.ICMPTypeMin = typeMin
		mIP.ICMPTypeMax = typeMax
		mIP.ICMPCodeMin = codeMin
		mIP.ICMPCodeMax = codeMax
	}
}

func newMatchIPv6(opts ...OptionMatchIPv6) (*MatchIPv6, error) {
	match := &MatchIPv6{
		baseMatch: &baseMatch{
			matchType: MatchTypeIPv6,
		},
		SourcePortMin:      -1,
		SourcePortMax:      -1,
		DestinationPortMin: -1,
		DestinationPortMax: -1,
		Protocol:           -1,
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
	*baseMatch
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

func (mIP *MatchIPv6) Parse(main []byte) (int, bool) {
	// 1. "--ip6-(source|destination|tclass|protocol|source-port|destination-port|icmp-type)" #1
	// 2. "( !)? ([[:graph:]]+) *" #2 #3
	pattern := `--ip6-(src|source|dst|destination|tos|proto|protocol|source-port|destination-port|icmp-type)` +
		`( !)? ([[:graph:]]+) *`
	reg := regexp.MustCompile(pattern)
	index := 0
	for len(main) > 0 {
		matches := reg.FindSubmatch(main)
		if len(matches) != 4 {
			goto END
		}
		invert := false
		if len(matches[2]) != 0 {
			invert = true
		}
		value := string(matches[3])
		switch string(matches[1]) {
		case "source", "src":
			addr, err := network.ParseAddress(value)
			if err != nil {
				goto END
			}
			mIP.Source = addr
			mIP.SourceInvert = invert
		case "destination", "dst":
			addr, err := network.ParseAddress(value)
			if err != nil {
				goto END
			}
			mIP.Destination = addr
			mIP.DestinationInvert = invert
		case "protocol", "proto":
			proto, err := network.ParseProtocol(value)
			if err != nil {
				goto END
			}
			mIP.Protocol = proto
			mIP.ProtocolInvert = invert
		case "source-port":
			ports := strings.Split(value, ":")
			if len(ports) == 2 {
				min, err := strconv.Atoi(ports[0])
				if err != nil {
					goto END
				}
				mIP.SourcePortMin = min
				max, err := strconv.Atoi(ports[1])
				if err != nil {
					goto END
				}
				mIP.SourcePortMax = max
			} else if len(ports) == 1 {
				min, err := strconv.Atoi(ports[0])
				if err != nil {
					goto END
				}
				mIP.SourcePortMin = min
			}
			mIP.SourceInvert = invert
		case "destination-port":
			ports := strings.Split(value, ":")
			if len(ports) == 2 {
				min, err := strconv.Atoi(ports[0])
				if err != nil {
					goto END
				}
				mIP.DestinationPortMin = min
				max, err := strconv.Atoi(ports[1])
				if err != nil {
					goto END
				}
				mIP.DestinationPortMax = max
			} else if len(ports) == 1 {
				min, err := strconv.Atoi(ports[0])
				if err != nil {
					goto END
				}
				mIP.DestinationPortMin = min
			}
			mIP.DestinationInvert = invert
		case "icmp-type":
			typecode := strings.Split(value, "/")
			if len(typecode) == 1 || len(typecode) == 2 {
				types := strings.Split(typecode[0], ":")
				if len(types) == 2 {
					min, err := network.ParseICMPv6Type(types[0])
					if err != nil {
						goto END
					}
					max, err := network.ParseICMPv6Type(types[1])
					if err != nil {
						goto END
					}
					mIP.ICMPTypeMin = min
					mIP.ICMPTypeMax = max

				} else if len(types) == 1 {
					min, err := network.ParseICMPv6Type(types[0])
					if err != nil {
						goto END
					}
					mIP.ICMPTypeMin = min
				}
			}
			if len(typecode) == 2 {
				codes := strings.Split(typecode[1], ":")
				if len(codes) == 2 {
					min, err := network.ParseICMPv6Code(codes[0])
					if err != nil {
						goto END
					}
					max, err := network.ParseICMPv6Code(codes[1])
					if err != nil {
						goto END
					}
					mIP.ICMPCodeMin = min
					mIP.ICMPCodeMax = max

				} else if len(codes) == 1 {
					min, err := network.ParseICMPv6Code(codes[0])
					if err != nil {
						goto END
					}
					mIP.ICMPCodeMin = min
				}
			}
			mIP.ICMPTypeInvert = invert
		}
		index += len(matches[0])
		main = main[len(matches[0]):]
	}
END:
	if index != 0 {
		return index, true
	}
	return 0, false
}

type OptionMatchLimit func(*MatchLimit)

// Maximum average matching rate.
func WithMatchLimit(value xtables.Rate) OptionMatchLimit {
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

func newMatchLimit(opts ...OptionMatchLimit) (*MatchLimit, error) {
	match := &MatchLimit{
		baseMatch: &baseMatch{
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
	*baseMatch
	Limit      xtables.Rate
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

func (mLimit *MatchLimit) Parse(main []byte) (int, bool) {
	// 1. "--limit(-burst)? " #1
	// 2. "(([0-9]+)/(second|minute|hour|day))?" #2 #3 #4
	// 3. "(([0-9]+))? *" #5 #6
	pattern := `--limit(-burst)? ` +
		`(([0-9]+)/(second|minute|hour|day))?` +
		`(([0-9]+))? *`
	reg := regexp.MustCompile(pattern)
	index := 0
	for len(main) > 0 {
		matches := reg.FindSubmatch(main)
		if len(matches) != 7 {
			goto END
		}
		switch len(matches[1]) {
		case 0:
			// --limit
			number, err := strconv.Atoi(string(matches[3]))
			if err != nil {
				goto END
			}
			unit := xtables.Unit(0)
			switch string(matches[4]) {
			case "second":
				unit = xtables.Second
			case "minute":
				unit = xtables.Minute
			case "hour":
				unit = xtables.Hour
			case "day":
				unit = xtables.Day
			default:
				goto END
			}
			mLimit.Limit = xtables.Rate{
				Rate: number,
				Unit: unit,
			}
			mLimit.HasLimit = true
		default:
			// --limit-burst
			number, err := strconv.Atoi(string(matches[6]))
			if err != nil {
				goto END
			}
			mLimit.LimitBurst = number
		}
		index += len(matches[0])
		main = main[len(matches[0]):]
	}
END:
	if index != 0 {
		return index, true
	}
	return 0, false
}

// The logical bridge interface via which a frame is going to be received
// (this option is useful in the INPUT, FORWARD, PREROUTING and BROUTING
// chains). If the interface name ends with '+', then any interface
// name that begins with this name(disregarding '+') will match.
func newMatchLogicalIn(invert bool, name string) (*MatchLogicalIn, error) {
	match := &MatchLogicalIn{
		baseMatch: &baseMatch{
			matchType: MatchTypeLogicalIn,
		},
		LogicalIn:       name,
		LogicalInInvert: invert,
	}
	match.setChild(match)
	return match, nil
}

type MatchLogicalIn struct {
	*baseMatch
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

func (mLogicalIn *MatchLogicalIn) Parse(main []byte) (int, bool) {
	// 1. "--logical-in( !)? ([[:graph:]]+) *" #1 #2
	pattern := `--logical-in( !)? ([[:graph:]]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mLogicalIn.LogicalInInvert = true
	}
	mLogicalIn.LogicalIn = string(matches[2])
	return len(matches[0]), true
}

// The logical bridge interface via which a frame is going to be sent
// (this optio name v string  he INPUT, FORWARD, PREROUTING and BROUTING
// chains). If the interface name ends with '+', then any interface
// name that begins with this name(disregarding '+') will match.
func newMatchLogicalOut(invert bool, name string) (*MatchLogicalOut, error) {
	match := &MatchLogicalOut{
		baseMatch: &baseMatch{
			matchType: MatchTypeLogicalOut,
		},
		LogicalOut:       name,
		LogicalOutInvert: invert,
	}
	match.setChild(match)
	return match, nil
}

type MatchLogicalOut struct {
	*baseMatch
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

func (mLogicalOut *MatchLogicalOut) Parse(main []byte) (int, bool) {
	// 1. "--logical-in( !)? ([[:graph:]]+) *" #1 #2
	pattern := `--logical-out( !)? ([[:graph:]]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mLogicalOut.LogicalOutInvert = true
	}
	mLogicalOut.LogicalOut = string(matches[2])
	return len(matches[0]), true
}

type OptionMatchMark func(*MatchMark)

// The argument value takes 2 values, mark or mark/mask. specify -1 to omit either one.
// Matches frames with the given unsigned mark value. If a value and mask are
// specified, the logical AND of the mark value of the frame and the user-specified
// mask is taken before comparing it with the user-specified mark value. When only
// mark value is specified, the packet only matches when the mark value of the frame
// equals the user-specified mark value. If only a mask is specified, the logical AND
// of the mark value of the frame and the user-specified mask is taken and the frame
// matches when the result of this logical AND is non-zero. Only specifying a mask
// is useful to match multiple mark values.
func newMatchMark(invert bool, value, mask int) (*MatchMark, error) {
	match := &MatchMark{
		baseMatch: &baseMatch{
			matchType: MatchTypeMark,
		},
		Value:      -1,
		Mask:       -1,
		MarkInvert: invert,
	}
	match.setChild(match)
	match.Value = value
	match.Mask = mask
	return match, nil
}

type MatchMark struct {
	*baseMatch
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

func (mMark *MatchMark) Parse(main []byte) (int, bool) {
	// 1. "--mark( !)? " #1
	// 2. "([0-9]+)?" #2
	// 3. "(/([0-9]+))? *" #3 #4
	pattern := `--mark( !)? ` +
		`([0-9]+)?` +
		`(/([0-9]+))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mMark.MarkInvert = true
	}
	value, err1 := strconv.Atoi(string(matches[2]))
	if err1 == nil {
		mMark.Value = value
	}
	mask, err2 := strconv.Atoi(string(matches[4]))
	if err2 == nil {
		mMark.Mask = mask
	}
	if err1 != nil && err2 != nil {
		return 0, false
	}
	return len(matches[0]), true
}

func newMatchOutInterface(invert bool, name string) (*MatchOutInterface, error) {
	match := &MatchOutInterface{
		baseMatch: &baseMatch{
			matchType: MatchTypeOutInterface,
		},
		OutInterfaceInvert: invert,
		OutInterface:       name,
	}
	match.setChild(match)
	return match, nil
}

type MatchOutInterface struct {
	*baseMatch
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

func (mOutInterface *MatchOutInterface) Parse(main []byte) (int, bool) {
	// 1. "-o( !)? ([[:graph:]]+) *" #1 #2
	pattern := `-o( !)? ([[:graph:]]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mOutInterface.OutInterfaceInvert = true
	}
	mOutInterface.OutInterface = string(matches[2])
	return len(matches[0]), true
}

func newMatchPktType(invert bool, pktType network.PktType) (*MatchPktType, error) {
	match := &MatchPktType{
		baseMatch: &baseMatch{
			matchType: MatchTypePktType,
		},
		PktTypeInvert: invert,
		PktType:       pktType,
	}
	match.setChild(match)
	return match, nil
}

type MatchPktType struct {
	*baseMatch
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

func (mPktType *MatchPktType) Parse(main []byte) (int, bool) {
	// 1. "--pkttype-type( !)? ([[:graph:]]) *" #1 #2
	pattern := `--pkttype-type( !)? ([[:graph:]]) *"`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mPktType.PktTypeInvert = true
	}
	typ, err := network.ParsePktType(string(matches[2]))
	if err != nil {
		return 0, false
	}
	mPktType.PktType = typ
	return len(matches[0]), true
}

func newMatchProtocol(invert bool, protocol network.EthernetType) (*MatchProtocol, error) {
	match := &MatchProtocol{
		baseMatch: &baseMatch{
			matchType: MatchTypeProtocol,
		},
		ProtocolInvert: invert,
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
	*baseMatch
	Protocol network.EthernetType
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
	args = append(args, mProtocol.Protocol.String())
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
	args = append(args, mProtocol.Protocol.String())
	return args
}

func (mProtocol *MatchProtocol) Parse(main []byte) (int, bool) {
	// 1. "-p( !)? ([[:graph:]]+) *"
	pattern := `-p( !)? ([[:graph:]]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mProtocol.ProtocolInvert = true
	}
	typ, err := network.ParseEthernetType(string(matches[2]))
	if err != nil {
		return 0, false
	}
	mProtocol.Protocol = typ
	return len(matches[0]), true
}

// The source MAC address with or without mask.
func newMatchSource(invert bool, addr network.Address) (*MatchSource, error) {
	match := &MatchSource{
		baseMatch: &baseMatch{
			matchType: MatchTypeSource,
		},
		SourceInvert: invert,
		Source:       addr,
	}
	match.setChild(match)
	return match, nil
}

type MatchSource struct {
	*baseMatch
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
func WithMatchSTPType(invert bool, typ uint8) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.TypeInvert = invert
		mSTP.Typ = typ
		mSTP.HasType = true
	}
}

// The BPDU flags(0-255).
func WithMatchSTPFlags(invert bool, flags uint8) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.FlagInvert = invert
		mSTP.Flags = flags
		mSTP.HasFlags = true
	}
}

// The argument priority takes mostly 2 values, min or min-max.
// The root priority(0-65535) range.
func WithMatchSTPRootPriority(invert bool, priority ...uint16) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.RootPriorityInvert = invert
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
func WithMatchSTPRootAddr(invert bool, mac net.HardwareAddr) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.RootAddrInvert = invert
		mSTP.RootAddr = network.NewHardwareAddr(mac)
	}
}

// The argument cost takes mostly 2 values, min or min-max.
// The root patch cost(0-4294967295) range.
func WithMatchSTPRootCost(invert bool, cost ...uint32) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.RootCostInvert = invert
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
func WithMatchSTPSenderPriority(invert bool, priority ...uint16) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.SenderPriorityInvert = invert
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
func WithMatchSTPSenderAddr(invert bool, mac net.HardwareAddr) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.SenderAddrInvert = invert
		mSTP.SenderAddr = network.NewHardwareAddr(mac)
	}
}

// The argument port takes mostly 2 values, min or min-max.
// The port identifier(0-65535) range.
func WithMatchSTPPort(invert bool, port ...uint16) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.PortInvert = invert
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
func WithMatchSTPMsgAge(invert bool, age ...uint16) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.MsgAgeInvert = invert
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
func WithMatchSTPMaxAge(invert bool, age ...uint16) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.MaxAgeInvert = invert
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
func WithMatchSTPHelloTime(invert bool, time ...uint16) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.HelloTimeInvert = invert
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
func WithMatchSTPForwardDelay(invert bool, delay ...uint16) OptionMatchSTP {
	return func(mSTP *MatchSTP) {
		mSTP.ForwardDelayInvert = invert
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

func newMatchSTP(opts ...OptionMatchSTP) (*MatchSTP, error) {
	match := &MatchSTP{
		baseMatch: &baseMatch{
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
	*baseMatch
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

func (mSTP *MatchSTP) Parse(main []byte) (int, bool) {
	// 1. "--stp-(type|flags|root-prio|root-addr|root-cost|sender-prio|sender-addr|port|msg-age|max-age|hello-time|forward-delay)" #1
	// 2. "( !)? ([[:graph:]]) *" #2 #3
	pattern := `--stp-(type|flags|root-prio|root-addr|root-cost|sender-prio|sender-addr|port|msg-age|max-age|hello-time|forward-delay)` +
		`( !)? ([[:graph:]]) *`
	reg := regexp.MustCompile(pattern)
	index := 0
	for len(main) > 0 {
		matches := reg.FindSubmatch(main)
		if len(matches) != 4 {
			goto END
		}
		invert := false
		if len(matches[2]) != 0 {
			invert = true
		}
		value := string(matches[3])
		switch string(matches[1]) {
		case "type":
			typ, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				goto END
			}
			mSTP.Typ = uint8(typ)
			mSTP.HasType = true
			mSTP.TypeInvert = invert
		case "flags":
			flags, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				goto END
			}
			mSTP.Flags = uint8(flags)
			mSTP.HasFlags = true
			mSTP.FlagInvert = invert
		case "root-prio":
			prios := strings.Split(value, ":")
			if len(prios) >= 1 {
				min, err := strconv.ParseUint(prios[0], 10, 16)
				if err != nil {
					goto END
				}
				mSTP.RootPriorityMin = uint16(min)
				mSTP.HasRootPriorityMin = true
			}
			if len(prios) == 2 {
				max, err := strconv.ParseUint(prios[1], 10, 16)
				if err != nil {
					goto END
				}
				mSTP.RootPriorityMax = uint16(max)
				mSTP.HasRootPriorityMax = true
			}
			mSTP.RootPriorityInvert = invert
		case "root-addr":
			addr, err := network.ParseAddress(value)
			if err != nil {
				goto END
			}
			mSTP.RootAddr = addr
			mSTP.RootAddrInvert = invert
		case "root-cost":
			costs := strings.Split(value, ":")
			if len(costs) >= 1 {
				min, err := strconv.ParseUint(costs[0], 10, 32)
				if err != nil {
					goto END
				}
				mSTP.RootCostMin = uint32(min)
				mSTP.HasRootCostMin = true
			}
			if len(costs) == 2 {
				max, err := strconv.ParseUint(costs[1], 10, 32)
				if err != nil {
					goto END
				}
				mSTP.RootCostMax = uint32(max)
				mSTP.HasRootCostMax = true
			}
			mSTP.RootCostInvert = invert
		case "sender-prio":
			prios := strings.Split(value, ":")
			if len(prios) >= 1 {
				min, err := strconv.ParseUint(prios[0], 10, 16)
				if err != nil {
					goto END
				}
				mSTP.SenderPriorityMin = uint16(min)
				mSTP.HasSenderPriorityMin = true
			}
			if len(prios) == 2 {
				max, err := strconv.ParseUint(prios[1], 10, 16)
				if err != nil {
					goto END
				}
				mSTP.SenderPriorityMax = uint16(max)
				mSTP.HasSenderPriorityMax = true
			}
			mSTP.SenderPriorityInvert = invert
		case "sender-addr":
			addr, err := network.ParseAddress(value)
			if err != nil {
				goto END
			}
			mSTP.SenderAddr = addr
			mSTP.SenderAddrInvert = invert
		case "port":
			ports := strings.Split(value, ":")
			if len(ports) >= 1 {
				min, err := strconv.ParseUint(ports[0], 10, 16)
				if err != nil {
					goto END
				}
				mSTP.PortMin = uint16(min)
				mSTP.HasPortMin = true
			}
			if len(ports) == 2 {
				max, err := strconv.ParseUint(ports[1], 10, 16)
				if err != nil {
					goto END
				}
				mSTP.PortMax = uint16(max)
				mSTP.HasPortMax = true
			}
			mSTP.PortInvert = invert
		case "msg-age":
			ages := strings.Split(value, ":")
			if len(ages) >= 1 {
				min, err := strconv.ParseUint(ages[0], 10, 16)
				if err != nil {
					goto END
				}
				mSTP.MsgAgeMin = uint16(min)
				mSTP.HasMsgAgeMin = true
			}
			if len(ages) == 2 {
				max, err := strconv.ParseUint(ages[1], 10, 16)
				if err != nil {
					goto END
				}
				mSTP.MsgAgeMax = uint16(max)
				mSTP.HasMsgAgeMax = true
			}
			mSTP.MsgAgeInvert = invert
		case "max-age":
			ages := strings.Split(value, ":")
			if len(ages) >= 1 {
				min, err := strconv.ParseUint(ages[0], 10, 16)
				if err != nil {
					goto END
				}
				mSTP.MaxAgeMin = uint16(min)
				mSTP.HasMaxAgeMin = true
			}
			if len(ages) == 2 {
				max, err := strconv.ParseUint(ages[1], 10, 16)
				if err != nil {
					goto END
				}
				mSTP.MaxAgeMax = uint16(max)
				mSTP.HasMaxAgeMax = true
			}
			mSTP.MaxAgeInvert = invert
		case "hello-time":
			hellos := strings.Split(value, ":")
			if len(hellos) >= 1 {
				min, err := strconv.ParseUint(hellos[0], 10, 16)
				if err != nil {
					goto END
				}
				mSTP.HelloTimeMin = uint16(min)
				mSTP.HasHelloTimeMin = true
			}
			if len(hellos) == 2 {
				max, err := strconv.ParseUint(hellos[1], 10, 16)
				if err != nil {
					goto END
				}
				mSTP.HelloTimeMax = uint16(max)
				mSTP.HasHelloTimeMax = true
			}
			mSTP.HelloTimeInvert = invert
		case "forward-delay":
			forwards := strings.Split(value, ":")
			if len(forwards) >= 1 {
				min, err := strconv.ParseUint(forwards[0], 10, 16)
				if err != nil {
					goto END
				}
				mSTP.ForwardDelayMin = uint16(min)
				mSTP.HasForwardDelayMin = true
			}
			if len(forwards) == 2 {
				max, err := strconv.ParseUint(forwards[1], 10, 16)
				if err != nil {
					goto END
				}
				mSTP.ForwardDelayMax = uint16(max)
				mSTP.HasForwardDelayMax = true
			}
			mSTP.ForwardDelayInvert = invert
		}
		index += len(matches[0])
		main = main[len(matches[0]):]
	}
END:
	if index != 0 {
		return index, true
	}
	return 0, false
}

type OptionMatchVLAN func(*MatchVLAN)

// The VLAN identifier filed(VID). Decimal number from 0 to 4095.
func WithMatchVLANID(invert bool, vlan int) OptionMatchVLAN {
	return func(mVLAN *MatchVLAN) {
		mVLAN.IDInvert = invert
		mVLAN.ID = vlan
	}
}

// The user priority field, a decimal number from 0 to 7. The VID should
// be set to 0("null VID") or unspecified(in the latter case the VID is
// deliberately set to 0).
func WithMatchVLANPriority(invert bool, priority int) OptionMatchVLAN {
	return func(mVLAN *MatchVLAN) {
		mVLAN.PriorityInvert = invert
		mVLAN.Priority = priority
	}
}

// The encapsulated Ethernet frame type/length. Specified as a hexadecimal
// number from 0x0000 to 0xFFFF.
func WithMatchVLANEncapsulation(invert bool, encapsulation [2]byte) OptionMatchVLAN {
	return func(mVLAN *MatchVLAN) {
		mVLAN.EncapsulationInvert = invert
		mVLAN.HasEncapsulation = true
		mVLAN.Encapsulation = encapsulation
	}
}

func newMatchVLAN(opts ...OptionMatchVLAN) (*MatchVLAN, error) {
	match := &MatchVLAN{
		baseMatch: &baseMatch{
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
	*baseMatch
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

func (mVLAN *MatchVLAN) Parse(main []byte) (int, bool) {
	// 1. "--vlan-(id|prio|encap)" #1
	// 2. "( !)? ([[:graph:]]) *" #2 #3
	pattern := `--vlan-(id|prio|encap)` +
		`( !)? ([[:graph:]]) *`
	reg := regexp.MustCompile(pattern)
	index := 0
	for len(main) > 0 {
		matches := reg.FindSubmatch(main)
		if len(matches) != 4 {
			goto END
		}
		invert := false
		if len(matches[2]) != 0 {
			invert = true
		}
		value := string(matches[1])
		switch value {
		case "id":
			id, err := strconv.Atoi(value)
			if err != nil {
				goto END
			}
			mVLAN.ID = id
			mVLAN.IDInvert = invert
		case "prio":
			prio, err := strconv.Atoi(value)
			if err != nil {
				goto END
			}
			mVLAN.Priority = prio
			mVLAN.PriorityInvert = invert
		case "encap":
			et, err := network.ParseEthernetType(value)
			if err != nil {
				bytes, err := hex.DecodeString(value)
				if err != nil {
					goto END
				}
				mVLAN.Encapsulation = [2]byte{bytes[0], bytes[1]}
				mVLAN.HasEncapsulation = true
			} else {
				bytes := make([]byte, 2)
				binary.BigEndian.PutUint16(bytes, uint16(et))
				mVLAN.Encapsulation = [2]byte{bytes[0], bytes[1]}
				mVLAN.HasEncapsulation = true
			}
			mVLAN.EncapsulationInvert = true
		}
		index += len(matches[0])
		main = main[len(matches[0]):]
	}
END:
	if index != 0 {
		return index, true
	}
	return 0, false
}

var (
	matchPrefixes = map[string]MatchType{
		"-p":                     MatchTypeProtocol,
		"-i":                     MatchTypeInInterface,
		"--in-interface":         MatchTypeInInterface,
		"--logical-in":           MatchTypeLogicalIn,
		"-o":                     MatchTypeOutInterface,
		"--out-interface":        MatchTypeOutInterface,
		"--logical-out":          MatchTypeLogicalOut,
		"-s":                     MatchTypeSource,
		"--source":               MatchTypeSource,
		"-d":                     MatchTypeDestination,
		"--destination":          MatchTypeDestination,
		"--802_3-sap":            MatchType802dot3,
		"--802_3-type":           MatchType802dot3,
		"--arp-opcode":           MatchTypeARP,
		"--arp-htype":            MatchTypeARP,
		"--arp-ptype":            MatchTypeARP,
		"--arp-ip-src":           MatchTypeARP,
		"--arp-ip-dst":           MatchTypeARP,
		"--arp-mac-src":          MatchTypeARP,
		"--arp-mac-dst":          MatchTypeARP,
		"--arp-gratuitous":       MatchTypeARP,
		"! --arp-gratuitous":     MatchTypeARP,
		"--ip-source":            MatchTypeIP,
		"--ip-src":               MatchTypeIP,
		"--ip-destination":       MatchTypeIP,
		"--ip-dst":               MatchTypeIP,
		"--ip-tos":               MatchTypeIP,
		"--ip-protocol":          MatchTypeIP,
		"--ip-proto":             MatchTypeIP,
		"--ip-source-port":       MatchTypeIP,
		"--ip-destination-port":  MatchTypeIP,
		"--ip6-source":           MatchTypeIPv6,
		"--ip6-src":              MatchTypeIPv6,
		"--ip6-destination":      MatchTypeIPv6,
		"--ip6-dst":              MatchTypeIPv6,
		"--ip6-tclass":           MatchTypeIPv6,
		"--ip6-protocol":         MatchTypeIPv6,
		"--ip6-proto":            MatchTypeIPv6,
		"--ip6-source-port":      MatchTypeIPv6,
		"--ip6-destination-port": MatchTypeIPv6,
		"--ip6-icmp-type":        MatchTypeIPv6,
		"--limit":                MatchTypeLimit,
		"--limit-burst":          MatchTypeLimit,
		"--mark":                 MatchTypeMark,
		"--pkttype-type":         MatchTypePktType,
		"--stp-type":             MatchTypeSTP,
		"--stp-flags":            MatchTypeSTP,
		"--stp-root-prio":        MatchTypeSTP,
		"--stp-root-addr":        MatchTypeSTP,
		"--stp-root-cost":        MatchTypeSTP,
		"--stp-sender-cost":      MatchTypeSTP,
		"--stp-sender-addr":      MatchTypeSTP,
		"--stp-port":             MatchTypeSTP,
		"--stp-msg-age":          MatchTypeSTP,
		"--stp-max-age":          MatchTypeSTP,
		"--stp-hello-time":       MatchTypeSTP,
		"--stp-forward-delay":    MatchTypeSTP,
		"--valn-id":              MatchTypeVLAN,
		"--valn-prio":            MatchTypeVLAN,
		"--valn-encap":           MatchTypeVLAN,
	}

	matchTrie tree.Trie
)

func init() {
	matchTrie = tree.NewTrie()
	for prefix, typ := range matchPrefixes {
		matchTrie.Add(prefix, typ)
	}
}

func (ebtables *EBTables) parseMatch(params []byte) ([]Match, int, error) {
	index := 0
	matches := []Match{}
	for len(params) > 0 {
		node, ok := matchTrie.LPM(string(params))
		if !ok {
			ebtables.log.Tracef("longest path mismatched: %s", string(params))
			break
		}
		typ := node.Value().(MatchType)
		// get match by match type
		match := matchFactory(typ)
		if match == nil {
			ebtables.log.Errorf("match: %s unrecognized", typ)
			return matches, index, xtables.ErrMatchParams
		}
		// index meaning the end of this match
		offset, ok := match.Parse(params)
		if !ok {
			ebtables.log.Errorf("match: %s parse: %s failed", match.Type(), string(params))
			return matches, index, xtables.ErrMatchParams
		}
		index += offset
		matches = append(matches, match)
		params = params[offset:]
	}
	return matches, index, nil
}
