package arptables

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/singchia/go-hammer/tree"
	"github.com/singchia/go-xtables"
	"github.com/singchia/go-xtables/pkg/network"
)

type MatchType int

const (
	_ MatchType = iota
	MatchTypeDestinationIP
	MatchTypeDestinationMAC
	MatchTypeHardwareLength
	MatchTypeHardwareType // like Ethernet, etc.
	MatchTypeInInterface
	MatchTypeOpCode
	MatchTypeOutInterface
	MatchTypeProtoType
	MatchTypeSourceIP
	MatchTypeSourceMAC
)

func (mt MatchType) Type() string {
	return "MatchType"
}

func (mt MatchType) Value() string {
	return strconv.Itoa(int(mt))
}

func (mt MatchType) String() string {
	switch mt {
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
	case MatchTypeDestinationIP:
		match, _ := NewMatchDestinationIP(false, nil)
		return match
	case MatchTypeDestinationMAC:
		match, _ := NewMatchDestinationMAC(false, nil)
		return match
	case MatchTypeHardwareLength:
		match, _ := NewMatchHardwareLength(-1)
		return match
	case MatchTypeHardwareType:
		match, _ := NewMatchHardwareType(0)
		return match
	case MatchTypeInInterface:
		match, _ := NewMatchInInterface(false, "")
		return match
	case MatchTypeOpCode:
		match, _ := NewMatchOpCode(0)
		return match
	case MatchTypeOutInterface:
		match, _ := NewMatchOutInterface(false, "")
		return match
	case MatchTypeProtoType:
		match, _ := NewMatchProtoType(-1)
		return match
	case MatchTypeSourceIP:
		match, _ := NewMatchSourceIP(false, nil)
		return match
	case MatchTypeSourceMAC:
		match, _ := NewMatchSourceMAC(false, nil)
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

// The destination IP specification
func NewMatchDestinationIP(invert bool, addr network.Address) (*MatchDestinationIP, error) {
	match := &MatchDestinationIP{
		baseMatch: baseMatch{
			matchType: MatchTypeDestinationIP,
		},
		DestinationInvert: invert,
		Destination:       addr,
	}
	match.setChild(match)
	return match, nil
}

type MatchDestinationIP struct {
	baseMatch
	Destination network.Address
	// invert
	DestinationInvert bool
}

func (match *MatchDestinationIP) Short() string {
	return strings.Join(match.ShortArgs(), " ")
}

func (match *MatchDestinationIP) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-d")
	if match.DestinationInvert {
		args = append(args, "!")
	}
	args = append(args, match.Destination.String())
	return args
}

func (match *MatchDestinationIP) Long() string {
	return strings.Join(match.LongArgs(), " ")
}

func (match *MatchDestinationIP) LongArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--destination-ip")
	if match.DestinationInvert {
		args = append(args, "!")
	}
	args = append(args, match.Destination.String())
	return args
}

func (match *MatchDestinationIP) Parse(main []byte) (int, bool) {
	// 1. "(! )?-d (([[:graph:]]+)(\/([:graph:]+))?) *" #1 #2 #3 #4 #5
	pattern := `(! )?-d (([[:graph:]]+)(\/([[:graph:]]+))?) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 6 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		match.DestinationInvert = true
	}
	addr, err := network.ParseAddress(string(matches[2]))
	if err != nil {
		return 0, false
	}
	match.Destination = addr
	return len(matches[0]), true
}

// The destination mac address.
func NewMatchDestinationMAC(invert bool, addr network.Address) (*MatchDestinationMAC, error) {
	match := &MatchDestinationMAC{
		baseMatch: baseMatch{
			matchType: MatchTypeDestinationMAC,
		},
		DestinationInvert: invert,
		Destination:       addr,
	}
	match.setChild(match)
	return match, nil
}

type MatchDestinationMAC struct {
	baseMatch
	Destination network.Address
	// invert
	DestinationInvert bool
}

func (match *MatchDestinationMAC) Short() string {
	return strings.Join(match.ShortArgs(), " ")
}

func (match *MatchDestinationMAC) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--destination-mac")
	if match.DestinationInvert {
		args = append(args, "!")
	}
	args = append(args, match.Destination.String())
	return args
}

func (match *MatchDestinationMAC) Parse(main []byte) (int, bool) {
	// 1. "(! )?--dst-mac (([0-9A-Za-z:]+)(/([0-9A-Za-z:]+))?) *" #1 #2 #3 #4 #5
	pattern := `(! )?--dst-mac (([0-9A-Za-z:]+)(/([0-9A-Za-z:]+))?) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 6 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		match.DestinationInvert = true
	}
	addr, err := network.ParseAddress(string(matches[2]))
	if err != nil {
		return 0, false
	}
	match.Destination = addr
	return len(matches[0]), true
}

// The source IP specification.
func NewMatchSourceIP(invert bool, addr network.Address) (*MatchSourceIP, error) {
	match := &MatchSourceIP{
		baseMatch: baseMatch{
			matchType: MatchTypeSourceIP,
		},
		SourceInvert: invert,
		Source:       addr,
	}
	match.setChild(match)
	return match, nil
}

type MatchSourceIP struct {
	baseMatch
	Source network.Address
	// invert
	SourceInvert bool
}

func (match *MatchSourceIP) Short() string {
	return strings.Join(match.ShortArgs(), " ")
}

func (match *MatchSourceIP) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-s")
	if match.SourceInvert {
		args = append(args, "!")
	}
	args = append(args, match.Source.String())
	return args
}

func (match *MatchSourceIP) Long() string {
	return strings.Join(match.LongArgs(), " ")
}

func (match *MatchSourceIP) LongArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--source-ip")
	if match.SourceInvert {
		args = append(args, "!")
	}
	args = append(args, match.Source.String())
	return args
}

func (match *MatchSourceIP) Parse(main []byte) (int, bool) {
	// 1. "(! )?-s( !)? (([[:graph:]]+)(/([:graph:]+))?) *" #1 #2 #3 #4 #5
	pattern := `(! )?-s (([[:graph:]]+)(/([:graph:]+))?) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 6 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		match.SourceInvert = true
	}
	addr, err := network.ParseAddress(string(matches[2]))
	if err != nil {
		return 0, false
	}
	match.Source = addr
	return len(matches[0]), true
}

// The source mac address.
func NewMatchSourceMAC(invert bool, addr network.Address) (*MatchSourceMAC, error) {
	match := &MatchSourceMAC{
		baseMatch: baseMatch{
			matchType: MatchTypeSourceMAC,
		},
		SourceInvert: invert,
		Source:       addr,
	}
	match.setChild(match)
	return match, nil
}

type MatchSourceMAC struct {
	baseMatch
	Source network.Address
	// invert
	SourceInvert bool
}

func (match *MatchSourceMAC) Short() string {
	return strings.Join(match.ShortArgs(), " ")
}

func (match *MatchSourceMAC) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--source-mac")
	if match.SourceInvert {
		args = append(args, "!")
	}
	args = append(args, match.Source.String())
	return args
}

func (match *MatchSourceMAC) Parse(main []byte) (int, bool) {
	// 1. "(! )?--src-mac (([0-9A-Za-z:]+)(/([0-9A-Za-z:]+))?) *" #1 #2 #3 #4 #5
	pattern := `(! )?--src-mac (([0-9A-Za-z:]+)(/([0-9A-Za-z:]+))?) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 6 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		match.SourceInvert = true
	}
	addr, err := network.ParseAddress(string(matches[2]))
	if err != nil {
		return 0, false
	}
	match.Source = addr
	return len(matches[0]), true
}

func NewMatchHardwareLengthWithMask(length, mask int) (*MatchHardwareLength, error) {
	match := &MatchHardwareLength{
		baseMatch: baseMatch{
			matchType: MatchTypeHardwareLength,
		},
		Length: length,
		Mask:   mask,
	}
	match.setChild(match)
	return match, nil
}

func NewMatchHardwareLength(length int) (*MatchHardwareLength, error) {
	match := &MatchHardwareLength{
		baseMatch: baseMatch{
			matchType: MatchTypeHardwareLength,
		},
		Length: length,
		Mask:   -1,
	}
	match.setChild(match)
	return match, nil
}

// The hardware length(number of bytes).
type MatchHardwareLength struct {
	baseMatch
	Length int
	Mask   int
}

func (match *MatchHardwareLength) Short() string {
	return strings.Join(match.ShortArgs(), " ")
}

func (match *MatchHardwareLength) ShortArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "-l")
	if match.Length > -1 {
		if match.Mask > -1 {
			args = append(args,
				strconv.Itoa(match.Length)+"/"+strconv.Itoa(match.Mask))
		} else {
			args = append(args, strconv.Itoa(match.Length))
		}
	}
	return args
}

func (match *MatchHardwareLength) Long() string {
	return strings.Join(match.LongArgs(), " ")
}

func (match *MatchHardwareLength) LongArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "--h-length")
	if match.Length > -1 {
		if match.Mask > -1 {
			args = append(args,
				strconv.Itoa(match.Length)+"/"+strconv.Itoa(match.Mask))
		} else {
			args = append(args, strconv.Itoa(match.Length))
		}
	}
	return args
}

func (match *MatchHardwareLength) Parse(main []byte) (int, bool) {
	// 1. "--h-length (([0-9]+)(/([0-9]+))?) *" #1 #2 #3 #4
	pattern := `--h-length (([0-9]+)(/([0-9]+))?) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	elems := strings.Split(string(matches[1]), "/")
	if len(elems) >= 1 {
		value, err := strconv.Atoi(string(matches[2]))
		if err != nil {
			return 0, false
		}
		match.Length = value
	}
	if len(elems) == 2 {
		value, err := strconv.Atoi(string(matches[4]))
		if err != nil {
			return 0, false
		}
		match.Mask = value
	}
	return len(matches[0]), true
}

func NewMatchOpCodeWithMask(opcode network.ARPOpCode, mask uint16) (*MatchOpCode, error) {
	match := &MatchOpCode{
		baseMatch: baseMatch{
			matchType: MatchTypeOpCode,
		},
		OpCode:  opcode,
		Mask:    mask,
		HasMask: true,
	}
	match.setChild(match)
	return match, nil
}

func NewMatchOpCode(opcode network.ARPOpCode) (*MatchOpCode, error) {
	match := &MatchOpCode{
		baseMatch: baseMatch{
			matchType: MatchTypeOpCode,
		},
		OpCode: opcode,
	}
	match.setChild(match)
	return match, nil
}

// The hardware length(number of bytes).
type MatchOpCode struct {
	baseMatch
	OpCode network.ARPOpCode
	//OpCode  [2]byte
	Mask uint16
	//Mask    [2]byte
	HasMask bool
}

func (match *MatchOpCode) Short() string {
	return strings.Join(match.ShortArgs(), " ")
}

func (match *MatchOpCode) ShortArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "--opcode")
	code := match.OpCode.String()
	if match.HasMask {
		mask := strconv.Itoa(int(match.Mask))
		args = append(args, code+"/"+mask)
	} else {
		args = append(args, code)
	}
	return args
}

func (match *MatchOpCode) Parse(main []byte) (int, bool) {
	// 1. "--opcode (([0-9]+)(/([0-9]+))?) *" #1 #2 #3 #4
	pattern := `--opcode (([0-9]+)(/([0-9]+))?) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	elems := strings.Split(string(matches[1]), "/")
	if len(elems) >= 1 {
		value, err := strconv.ParseUint(string(matches[2]), 10, 16)
		if err != nil {
			return 0, false
		}
		match.OpCode = network.ARPOpCode(uint16(value))
	}
	if len(elems) == 2 {
		value, err := strconv.ParseUint(string(matches[4]), 10, 16)
		if err != nil {
			return 0, false
		}
		match.Mask = uint16(value)
		match.HasMask = true
	}
	return len(matches[0]), true
}

func NewMatchProtoTypeWithMask(protoType network.Protocol, mask uint16) (*MatchProtoType, error) {
	match := &MatchProtoType{
		baseMatch: baseMatch{
			matchType: MatchTypeProtoType,
		},
		Typ:     protoType,
		HasMask: true,
		Mask:    mask,
	}
	match.setChild(match)
	return match, nil
}

func NewMatchProtoType(protoType network.Protocol) (*MatchProtoType, error) {
	match := &MatchProtoType{
		baseMatch: baseMatch{
			matchType: MatchTypeProtoType,
		},
		Typ: protoType,
	}
	match.setChild(match)
	return match, nil
}

// The protocol type in 2bytes.
type MatchProtoType struct {
	baseMatch
	Typ network.Protocol

	Mask    uint16
	HasMask bool
}

func (match *MatchProtoType) Short() string {
	return strings.Join(match.ShortArgs(), " ")
}

func (match *MatchProtoType) ShortArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "--proto-type")
	typ := match.Typ.Value()
	if match.HasMask {
		mask := strconv.Itoa(int(match.Mask))
		args = append(args, typ+"/"+mask)
	} else {
		args = append(args, typ)
	}
	return args
}

func (match *MatchProtoType) Parse(main []byte) (int, bool) {
	// 1. "--proto-type (([0-9]+)(/([0-9]+))?) *"
	pattern := `--proto-type (([0-9]+)(/([0-9]+))?) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	elems := strings.Split(string(matches[1]), "/")
	if len(elems) >= 1 {
		value, err := strconv.Atoi(string(matches[2]))
		if err != nil {
			return 0, false
		}
		match.Typ = network.Protocol(value)
	}
	if len(elems) == 2 {
		value, err := strconv.ParseUint(string(matches[4]), 10, 16)
		if err != nil {
			return 0, false
		}
		match.Mask = uint16(value)
	}
	return len(matches[0]), true

}

func NewMatchHardwareTypeWithMask(typ network.HardwareType, mask uint16) (*MatchHardwareType, error) {
	match := &MatchHardwareType{
		baseMatch: baseMatch{
			matchType: MatchTypeHardwareType,
		},
		Typ:     typ,
		HasMask: true,
		Mask:    mask,
	}
	match.setChild(match)
	return match, nil
}

func NewMatchHardwareType(typ network.HardwareType) (*MatchHardwareType, error) {
	match := &MatchHardwareType{
		baseMatch: baseMatch{
			matchType: MatchTypeHardwareType,
		},
		Typ: typ,
	}
	match.setChild(match)
	return match, nil
}

// The protocol type in 2bytes.
type MatchHardwareType struct {
	baseMatch
	Typ network.HardwareType

	Mask    uint16
	HasMask bool
}

func (match *MatchHardwareType) Short() string {
	return strings.Join(match.ShortArgs(), " ")
}

func (match *MatchHardwareType) ShortArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "--h-type")
	typ := match.Typ.String()
	if match.HasMask {
		mask := strconv.Itoa(int(match.Mask))
		args = append(args, typ+"/"+mask)
	} else {
		args = append(args, typ)
	}
	return args
}

func (match *MatchHardwareType) Parse(main []byte) (int, bool) {
	// 1. "--h-type (([0-9]+)(/([0-9]+))?) *" #1 #2 #3 #4
	pattern := `--h-type (([0-9]+)(/([0-9]+))?) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	elems := strings.Split(string(matches[1]), "/")
	if len(elems) >= 1 {
		value, err := strconv.ParseUint(string(matches[2]), 10, 16)
		if err != nil {
			return 0, false
		}
		match.Typ = network.HardwareType(value)
	}
	if len(elems) == 2 {
		value, err := strconv.ParseUint(string(matches[4]), 10, 16)
		if err != nil {
			return 0, false
		}
		match.Mask = uint16(value)
	}
	return len(matches[0]), true
}

func NewMatchInInterface(invert bool, name string) (*MatchInInterface, error) {
	match := &MatchInInterface{
		baseMatch: baseMatch{
			matchType: MatchTypeInInterface,
		},
		InInterfaceInvert: invert,
		InInterface:       name,
	}
	match.setChild(match)
	return match, nil
}

// The interface via which a frame is received(for the INPUT and FORWARD chains).
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

func (mInInterface *MatchInInterface) Parse(main []byte) (int, bool) {
	// 1. "(! )?-i ([[:graph:]]+) *" #1 #2
	pattern := `(! )?-i ([[:graph:]]+) *`
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

// The interface via which a frame is going to be sent (for the OUTPUT and FORWARD chains).
func NewMatchOutInterface(invert bool, name string) (*MatchOutInterface, error) {
	match := &MatchOutInterface{
		baseMatch: baseMatch{
			matchType: MatchTypeOutInterface,
		},
		OutInterfaceInvert: invert,
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

func (mOutInterface *MatchOutInterface) Parse(main []byte) (int, bool) {
	// 1. "(! )?-o ([[:graph:]]+) *" #1 #2
	pattern := `(! )?-o ([[:graph:]]+) *`
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

var (
	matchPrefixes = map[string]MatchType{
		"-d":           MatchTypeDestinationIP,
		"! -d":         MatchTypeDestinationIP,
		"--dst-mac":    MatchTypeDestinationMAC,
		"! --dst-mac":  MatchTypeDestinationMAC,
		"-s":           MatchTypeSourceIP,
		"! -s":         MatchTypeSourceIP,
		"--src-mac":    MatchTypeSourceMAC,
		"! --src-mac":  MatchTypeSourceMAC,
		"--h-length":   MatchTypeHardwareLength,
		"--opcode":     MatchTypeOpCode,
		"--proto-type": MatchTypeProtoType,
		"--h-type":     MatchTypeHardwareType,
		"-i":           MatchTypeInInterface,
		"! -i":         MatchTypeInInterface,
		"-o":           MatchTypeOutInterface,
		"! -o":         MatchTypeOutInterface,
	}

	matchTrie tree.Trie
)

func init() {
	matchTrie = tree.NewTrie()
	for prefix, typ := range matchPrefixes {
		matchTrie.Add(prefix, typ)
	}
}

func ParseMatch(params []byte) ([]Match, int, error) {
	index := 0
	matches := []Match{}
	for len(params) > 0 {
		node, ok := matchTrie.LPM(string(params))
		if !ok {
			break
		}
		typ := node.Value().(MatchType)
		// get match by match type
		match := MatchFactory(typ)
		if match == nil {
			return matches, index, xtables.ErrMatchParams
		}
		// index meaning the end of this match
		offset, ok := match.Parse(params)
		if !ok {
			return matches, index, xtables.ErrMatchParams
		}
		index += offset
		matches = append(matches, match)
		params = params[offset:]
	}
	return matches, index, nil
}
