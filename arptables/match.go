package arptables

import (
	"encoding/hex"
	"strconv"
	"strings"

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
func NewMatchDestinationIP(yes bool, addr network.Address) (*MatchDestinationIP, error) {
	match := &MatchDestinationIP{
		baseMatch: baseMatch{
			matchType: MatchTypeDestinationIP,
		},
		DestinationInvert: !yes,
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

// The destination mac address.
func NewMatchDestinationMAC(yes bool, addr network.Address) (*MatchDestinationMAC, error) {
	match := &MatchDestinationMAC{
		baseMatch: baseMatch{
			matchType: MatchTypeDestinationMAC,
		},
		DestinationInvert: !yes,
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

// The source IP specification.
func NewMatchSourceIP(yes bool, addr network.Address) (*MatchSourceIP, error) {
	match := &MatchSourceIP{
		baseMatch: baseMatch{
			matchType: MatchTypeSourceIP,
		},
		SourceInvert: !yes,
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

// The source mac address.
func NewMatchSourceMAC(yes bool, addr network.Address) (*MatchSourceMAC, error) {
	match := &MatchSourceMAC{
		baseMatch: baseMatch{
			matchType: MatchTypeSourceMAC,
		},
		SourceInvert: !yes,
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

func NewMatchHardwareLength(yes bool, length ...int) (*MatchHardwareLength, error) {
	match := &MatchHardwareLength{
		baseMatch: baseMatch{
			matchType: MatchTypeHardwareLength,
		},
		Length: -1,
		Mask:   -1,
	}
	match.setChild(match)
	switch len(length) {
	case 1:
		match.Length = length[0]
		match.Mask = -1
	case 2:
		match.Length = length[0]
		match.Mask = length[1]
	}
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

func NewMatchOpCodeWithMask(yes bool, opcode, mask [2]byte) (*MatchOpCode, error) {
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

func NewMatchOpCode(yes bool, opcode network.ARPOpCode) (*MatchOpCode, error) {
	match := &MatchOpCode{
		baseMatch: baseMatch{
			matchType: MatchTypeOpCode,
		},
		OpCode: opcode.Hex(),
	}
	match.setChild(match)
	return match, nil
}

// The hardware length(number of bytes).
type MatchOpCode struct {
	baseMatch
	OpCode  [2]byte
	Mask    [2]byte
	HasMask bool
}

func (match *MatchOpCode) Short() string {
	return strings.Join(match.ShortArgs(), " ")
}

func (match *MatchOpCode) ShortArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "--opcode")
	code := hex.EncodeToString([]byte{match.OpCode[0], match.OpCode[1]})
	if match.HasMask {
		mask := hex.EncodeToString([]byte{match.Mask[0], match.Mask[1]})
		args = append(args, code+"/"+mask)
		return args
	}
	args = append(args, code)
	return args
}

func NewMatchProtoTypeWithMask(yes bool, proto, mask [2]byte) (*MatchProtoType, error) {
	match := &MatchProtoType{
		baseMatch: baseMatch{
			matchType: MatchTypeProtoType,
		},
		Typ:     proto,
		HasMask: true,
		Mask:    mask,
	}
	match.setChild(match)
	return match, nil
}

func NewMatchProtoType(yes bool, protoType network.Protocol) (*MatchProtoType, error) {
	match := &MatchProtoType{
		baseMatch: baseMatch{
			matchType: MatchTypeProtoType,
		},
		Typ: protoType.Hex(),
	}
	match.setChild(match)
	return match, nil
}

// The protocol type in 2bytes.
type MatchProtoType struct {
	baseMatch
	Typ [2]byte

	Mask    [2]byte
	HasMask bool
}

func (match *MatchProtoType) Short() string {
	return strings.Join(match.ShortArgs(), " ")
}

func (match *MatchProtoType) ShortArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "--proto-type")
	typ := hex.EncodeToString([]byte{match.Typ[0], match.Typ[1]})
	if match.HasMask {
		mask := hex.EncodeToString([]byte{match.Mask[0], match.Mask[1]})
		args = append(args, typ+"/"+mask)
		return args
	}
	args = append(args, typ)
	return args
}

func NewMatchHardwareTypeWithMask(yes bool, typ, mask [2]byte) (*MatchHardwareType, error) {
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

func NewMatchHardwareType(yes bool, typ network.HardwareType) (*MatchHardwareType, error) {
	match := &MatchHardwareType{
		baseMatch: baseMatch{
			matchType: MatchTypeHardwareType,
		},
		Typ: typ.Hex(),
	}
	match.setChild(match)
	return match, nil
}

// The protocol type in 2bytes.
type MatchHardwareType struct {
	baseMatch
	Typ [2]byte

	Mask    [2]byte
	HasMask bool
}

func (match *MatchHardwareType) Short() string {
	return strings.Join(match.ShortArgs(), " ")
}

func (match *MatchHardwareType) ShortArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "--h-type")
	typ := hex.EncodeToString([]byte{match.Typ[0], match.Typ[1]})
	if match.HasMask {
		mask := hex.EncodeToString([]byte{match.Mask[0], match.Mask[1]})
		args = append(args, typ+"/"+mask)
		return args
	}
	args = append(args, typ)
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

// The interface via which a frame is going to be sent (for the OUTPUT and FORWARD chains).
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
