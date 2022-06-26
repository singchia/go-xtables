/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package iptables

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/singchia/go-hammer/tree"
)

type MatchType int

func (mt MatchType) Type() string {
	return "MatchType"
}

func (mt MatchType) Value() string {
	return strconv.Itoa(int(mt))
}

const (
	MatchTypeAddrType MatchType = iota
	MatchTypeAH                 // Both IPv4 & IPv6 specific
	MatchTypeBPF
	MatchTypeCGroup
	MatchTypeCluster
	MatchTypeComment
	MatchTypeConnBytes
	MatchTypeConnLabel
	MatchTypeConnLimit
	MatchTypeConnMark
	MatchTypeConnTrack
	MatchTypeCPU
	MatchTypeDCCP
	MatchTypeDestination // option
	MatchTypeDevGroup
	MatchTypeDSCP
	MatchTypeDst // IPv6-specific
	MatchTypeECN
	MatchTypeESP
	MatchTypeEUI64 // IPv6-specific
	MatchTypeFrag  // IPv6-specific
	MatchTypeHashLimit
	MatchTypeHBH // IPv6-specific, Hop-by-Hop
	MatchTypeHelper
	MatchTypeHL          // IPv6-specific, Hop Limit
	MatchTypeICMP        // both IPv6 & IPv4-specific
	MatchTypeInInterface // option
	MatchTypeIPRange
	MatchTypeIPv4       // option
	MatchTypeIPv6       // option
	MatchTypeIPv6Header // IPv6-specific
	MatchTypeIPVS
	MatchTypeLength
	MatchTypeLimit
	MatchTypeMAC
	MatchTypeMark
	MatchTypeMH // IPv6-specific
	MatchTypeMultiPort
	MatchTypeNFAcct
	MatchTypeOSF
	MatchTypeOutInterface // option
	MatchTypeOwner
	MatchTypePhysDev
	MatchTypePktType
	MatchTypePolicy
	MatchTypeProtocol // option
	MatchTypeQuota
	MatchTypeRateEst
	MatchTypeRealm // IPv4-specific
	MatchTypeRecent
	MatchTypeRPFilter
	MatchTypeRT // IPv6-specific
	MatchTypeSCTP
	MatchTypeSet
	MatchTypeSocket
	MatchTypeSource // option
	MatchTypeSRH    // unsupport
	MatchTypeState
	MatchTypeStatistic
	MatchTypeString
	MatchTypeTCP
	MatchTypeTCPMSS
	MatchTypeTime
	MatchTypeTOS
	MatchTypeTTL // IPv4-specific
	MatchTypeU32
	MatchTypeUDP
	MatchTypeUnclean // unsupport
)

type Match interface {
	Type() MatchType
	Short() string
	ShortArgs() []string
	Long() string
	LongArgs() []string
	Parse([]byte) (int, bool)
}

func NewMatch(matchType MatchType, args ...interface{}) (Match, error) {
	switch matchType {
	case MatchTypeInInterface:
		if len(args) != 2 {
			goto Err
		}
		yes, ok := args[0].(bool)
		if !ok {
			goto Err
		}
		iface, ok := args[1].(string)
		if !ok {
			goto Err
		}
		return NewMatchInInterface(yes, iface), nil

	case MatchTypeOutInterface:
		if len(args) != 2 {
			goto Err
		}
		yes, ok := args[0].(bool)
		if !ok {
			goto Err
		}
		iface, ok := args[1].(string)
		if !ok {
			goto Err
		}
		return NewMatchOutInterface(yes, iface), nil
	}

Err:
	return nil, ErrArgs
}

func MatchFactory(matchType MatchType) Match {
	switch matchType {
	}
	return nil
}

type baseMatch struct {
	matchType MatchType
	invert    bool
	ipType    IPType
}

func (bm baseMatch) Type() MatchType {
	return bm.matchType
}

func (bm baseMatch) Short() string {
	return ""
}

func (bm baseMatch) ShortArgs() []string {
	return nil
}

func (bm baseMatch) Long() string {
	return ""
}

func (bm baseMatch) LongArgs() []string {
	return nil
}

func (bm *baseMatch) Parse(params []byte) (int, bool) {
	return 0, false
}

func (bm *baseMatch) IPType() IPType {
	return bm.ipType
}

type MatchIPv4 struct {
	baseMatch
}

func (mIPv4 *MatchIPv4) Short() string {
	return "-4"
}

func (mIPv4 *MatchIPv4) ShortArgs() []string {
	return []string{"-4"}
}

func (mIPv4 *MatchIPv4) Long() string {
	return "--ipv4"
}

func (mIPv4 *MatchIPv4) LongArgs() []string {
	return []string{"--ipv4"}
}

type MatchIPv6 struct {
	baseMatch
}

func (mIPv6 *MatchIPv6) Short() string {
	return "-6"
}

func (mIPv6 *MatchIPv6) ShortArgs() []string {
	return []string{"-6"}
}

func (mIPv6 *MatchIPv6) Long() string {
	return "--ipv6"
}

func (mIPv6 *MatchIPv6) LongArgs() []string {
	return []string{"--ipv6"}
}

type MatchProtocol struct {
	baseMatch
	Protocol Protocol
}

func (mProtocol *MatchProtocol) Short() string {
	if mProtocol.invert {
		return fmt.Sprintf("! -p %d", int(mProtocol.Protocol))
	}
	return fmt.Sprintf("-p %d", int(mProtocol.Protocol))
}

func (mProtocol *MatchProtocol) ShortArgs() []string {
	if mProtocol.invert {
		return []string{"!", "-p", strconv.Itoa(int(mProtocol.Protocol))}
	}
	return []string{"-p", strconv.Itoa(int(mProtocol.Protocol))}
}

func (mProtocol *MatchProtocol) Long() string {
	if mProtocol.invert {
		return fmt.Sprintf("! --protocol %d", int(mProtocol.Protocol))
	}
	return fmt.Sprintf("--protocol %d", int(mProtocol.Protocol))
}

func (mProtocol *MatchProtocol) LongArgs() []string {
	if mProtocol.invert {
		return []string{"!", "--protocol", strconv.Itoa(int(mProtocol.Protocol))}
	}
	return []string{"--protocol", strconv.Itoa(int(mProtocol.Protocol))}
}

type MatchSource struct {
	baseMatch
	address *Address
}

func NewMatchSource(yes bool, address *Address) *MatchSource {
	return &MatchSource{
		baseMatch: baseMatch{
			matchType: MatchTypeSource,
		},
		address: address,
	}
}

func (mSrc *MatchSource) Short() string {
	if mSrc.invert {
		return fmt.Sprintf("! -s %s", mSrc.address.String())
	}
	return fmt.Sprintf("-s %s", mSrc.address.String())
}

func (mSrc *MatchSource) ShortArgs() []string {
	if mSrc.invert {
		return []string{"!", "-s", mSrc.address.String()}
	}
	return []string{"-s", mSrc.address.String()}
}

func (mSrc *MatchSource) Long() string {
	if mSrc.invert {
		return fmt.Sprintf("! --source %s", mSrc.address.String())
	}
	return fmt.Sprintf("--source %s", mSrc.address.String())
}

func (mSrc *MatchSource) LongArgs() []string {
	if mSrc.invert {
		return []string{"!", "--source", mSrc.address.String()}
	}
	return []string{"--source", mSrc.address.String()}
}

type MatchDestination struct {
	baseMatch
	address *Address
}

func (mDst *MatchDestination) Short() string {
	if mDst.invert {
		return fmt.Sprintf("! -d %s", mDst.address.String())
	}
	return fmt.Sprintf("-d %s", mDst.address.String())
}

func (mDst *MatchDestination) ShortArgs() []string {
	if mDst.invert {
		return []string{"!", "-d", mDst.address.String()}
	}
	return []string{"-d", mDst.address.String()}
}

func (mDst *MatchDestination) Long() string {
	if mDst.invert {
		return fmt.Sprintf("! --destination %s", mDst.address.String())
	}
	return fmt.Sprintf("--destination %s", mDst.address.String())
}

func (mDst *MatchDestination) LongArgs() []string {
	if mDst.invert {
		return []string{"!", "--destination", mDst.address.String()}
	}
	return []string{"--destination", mDst.address.String()}
}

type MatchInInterface struct {
	baseMatch
	iface string
}

func NewMatchInInterface(yes bool, iface string) *MatchInInterface {
	return &MatchInInterface{
		baseMatch: baseMatch{
			matchType: MatchTypeInInterface,
			invert:    !yes,
		},
		iface: iface,
	}
}

func (mInIface *MatchInInterface) Short() string {
	if mInIface.invert {
		return fmt.Sprintf("! -i %s", mInIface.iface)
	}
	return fmt.Sprintf("-i %s", mInIface.iface)
}

func (mInIface *MatchInInterface) ShortArgs() []string {
	if mInIface.invert {
		return []string{"!", "-i", mInIface.iface}
	}
	return []string{"-i", mInIface.iface}
}

func (mInIface *MatchInInterface) Long() string {
	if mInIface.invert {
		return fmt.Sprintf("! --in-interface %s", mInIface.iface)
	}
	return fmt.Sprintf("--in-interface %s", mInIface.iface)
}

func (mInIface *MatchInInterface) LongArgs() []string {
	if mInIface.invert {
		return []string{"!", "--in-interface", mInIface.iface}
	}
	return []string{"--in-interface", mInIface.iface}
}

type MatchOutInterface struct {
	baseMatch
	iface string
}

func NewMatchOutInterface(yes bool, iface string) *MatchOutInterface {
	return &MatchOutInterface{
		baseMatch: baseMatch{
			matchType: MatchTypeOutInterface,
			invert:    !yes,
		},
		iface: iface,
	}
}

func (mOutIface *MatchOutInterface) Short() string {
	if mOutIface.invert {
		return fmt.Sprintf("! -o %s", mOutIface.iface)
	}
	return fmt.Sprintf("-o %s", mOutIface.iface)
}

func (mOutIface *MatchOutInterface) ShortArgs() []string {
	if mOutIface.invert {
		return []string{"!", "-o", mOutIface.iface}
	}
	return []string{"-o", mOutIface.iface}
}

func (mOutIface *MatchOutInterface) Long() string {
	if mOutIface.invert {
		return fmt.Sprintf("! --out-interface %s", mOutIface.iface)
	}
	return fmt.Sprintf("--out-interface %s", mOutIface.iface)
}

func (mOutIface *MatchOutInterface) LongArgs() []string {
	if mOutIface.invert {
		return []string{"!", "-o", mOutIface.iface}
	}
	return []string{"-o", mOutIface.iface}
}

type AddrType int

func (addrType AddrType) String() string {
	switch addrType {
	case UNSPEC:
		return "UNSPEC"
	case UNICAST:
		return "UNICAST"
	case LOCAL:
		return "LOCAL"
	case BROADCAST:
		return "BROADCAST"
	case ANYCAST:
		return "ANYCAST"
	case MULTICAST:
		return "MULTICAST"
	case BLACKHOLE:
		return "BLACKHOLE"
	case UNREACHABLE:
		return "UNREACHABLE"
	case PROHIBIT:
		return "PROHIBIT"
	case THROW:
		return "THROW"
	case NAT:
		return "NAT"
	case XRESOLVE:
		return "XRESOLVE"
	default:
		return ""
	}
}

const (
	UNSPEC AddrType = 1 << iota // unspecified
	UNICAST
	LOCAL
	BROADCAST
	ANYCAST
	MULTICAST
	BLACKHOLE
	UNREACHABLE
	PROHIBIT
	THROW
	NAT
	XRESOLVE
)

var (
	addrTypes = map[string]AddrType{
		"UNSPEC":      UNSPEC,
		"UNICAST":     UNICAST,
		"LOCAL":       LOCAL,
		"BROADCAST":   BROADCAST,
		"ANYCAST":     ANYCAST,
		"MULTICAST":   MULTICAST,
		"BLACKHOLE":   BLACKHOLE,
		"UNREACHABLE": UNREACHABLE,
		"PROHIBIT":    PROHIBIT,
		"THROW":       THROW,
		"NAT":         NAT,
		"XRESOLVE":    XRESOLVE,
	}
)

type OptionMatchAddrType func(*MatchAddrType)

// Matches if the source address is of given type.
func WithMatchAddrTypeSrcType(yes bool, srcType AddrType) OptionMatchAddrType {
	return func(mAddrType *MatchAddrType) {
		mAddrType.SrcTypeInvert = !yes
		mAddrType.SrcType = srcType
		mAddrType.HasSrcType = true
	}
}

// Matches if the destination address is of given type.
func WithMatchAddrTypeDstType(yes bool, dstType AddrType) OptionMatchAddrType {
	return func(mAddrType *MatchAddrType) {
		mAddrType.DstTypeInvert = !yes
		mAddrType.DstType = dstType
		mAddrType.HasDstType = true
	}
}

// The address type checking can be limited to the interface the packet is coming in.
// This option is only valid in the PREROUTING, INPUT and FORWARD chains.
func WithMatchAddrLimitIfaceIn() OptionMatchAddrType {
	return func(mAddrType *MatchAddrType) {
		mAddrType.LimitIfaceIn = true
	}
}

// The address type checking can be limited to the interface the packet is going out.
// This option is only valid in the POSTROUTING, OUTPUT and FORWARD chains.
func WithMatchAddrLimitIfaceOut() OptionMatchAddrType {
	return func(mAddrType *MatchAddrType) {
		mAddrType.LimitIfaceOut = true
	}
}

func NewMatchAddrType(opts ...OptionMatchAddrType) (*MatchAddrType, error) {
	match := &MatchAddrType{
		baseMatch: baseMatch{
			matchType: MatchTypeAddrType,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	if !match.HasSrcType && !match.HasDstType &&
		!match.LimitIfaceIn && !match.LimitIfaceOut {
		return nil, ErrAtLeastOneOptionRequired
	}
	return match, nil
}

type MatchAddrType struct {
	baseMatch
	// src type
	SrcTypeInvert bool
	SrcType       AddrType
	HasSrcType    bool
	// dst type
	DstTypeInvert bool
	DstType       AddrType
	HasDstType    bool
	// limit face in
	LimitIfaceIn bool
	// limit face out
	LimitIfaceOut bool
}

func (mAddrType *MatchAddrType) Short() string {
	return strings.Join(mAddrType.ShortArgs(), " ")
}

func (mAddrType *MatchAddrType) ShortArgs() []string {
	args := make([]string, 0, 6)
	if mAddrType.HasSrcType {
		if mAddrType.SrcTypeInvert {
			args = append(args, "!")
		}
		args = append(args, "--src-type", mAddrType.SrcType.String())
	}
	if mAddrType.HasDstType {
		if mAddrType.DstTypeInvert {
			args = append(args, "!")
		}
		args = append(args, "--dst-type", mAddrType.DstType.String())
	}
	if mAddrType.LimitIfaceIn {
		args = append(args, "--limit-iface-in")
	}
	if mAddrType.LimitIfaceOut {
		args = append(args, "--limit-iface-out")
	}
	return args
}

func (mAddrType *MatchAddrType) Long() string {
	return mAddrType.Short()
}

func (mAddrType *MatchAddrType) LongArgs() []string {
	return mAddrType.ShortArgs()
}

func (mAddrType *MatchAddrType) Parse(main []byte) (int, bool) {
	// 1. "^ADDRTYPE match"
	// 2. "( src-type !?([A-Za-z,]+))?" #1 #2
	// 3. "( dst-type ?!?([A-Za-z,]+))?" #3 #4
	// 4. "( limit-in)?" #5
	// 5. "( limit-out)?" #6
	pattern := `^ADDRTYPE match` +
		`( src-type (!?[A-Za-z,]+))?` +
		`( dst-type ?(!?[A-Za-z,]+))?` +
		`( limit-in)?` +
		`( limit-out)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 7 {
		return 0, false
	}
	// src type
	srcType := matches[2]
	if len(srcType) != 0 {
		mAddrType.HasSrcType = true
		if srcType[0] == '!' {
			mAddrType.SrcTypeInvert = true
			srcType = srcType[1:]
		}
		srcTypes := bytes.Split(srcType, []byte{','})
		for _, elem := range srcTypes {
			typ, ok := addrTypes[string(elem)]
			if !ok {
				return 0, false
			}
			mAddrType.SrcType |= typ
		}
	}
	// dst type
	dstType := matches[4]
	if len(dstType) != 0 {
		mAddrType.HasDstType = true
		if dstType[0] == '!' {
			mAddrType.DstTypeInvert = true
			dstType = dstType[1:]
		}
		dstTypes := bytes.Split(dstType, []byte{','})
		for _, elem := range dstTypes {
			typ, ok := addrTypes[string(elem)]
			if !ok {
				return 0, false
			}
			mAddrType.DstType |= typ
		}
	}
	// limit in
	if len(matches[5]) != 0 {
		mAddrType.LimitIfaceIn = true
	}
	// limit out
	if len(matches[6]) != 0 {
		mAddrType.LimitIfaceIn = true
	}
	return len(matches[0]), true
}

type OptionMatchAH func(*MatchAH)

// This option takes mostly 2 spis, (min) or (min, max)
// Matches SPI
func WithMatchAHSPI(yes bool, spi ...int) OptionMatchAH {
	return func(mAH *MatchAH) {
		switch len(spi) {
		case 1:
			mAH.SPIMin = spi[0]
			mAH.SPIMax = -1
		case 2:
			mAH.SPIMin = spi[0]
			mAH.SPIMax = spi[1]
		}
		mAH.SPIInvert = !yes
	}
}

// Total length of this header in octets
func WithMatchAHSPILength(yes bool, length int) OptionMatchAH {
	return func(mAH *MatchAH) {
		mAH.LengthInvert = !yes
		mAH.Length = length
	}
}

// Matches if the reserved field is filled with zero
func WithMatchAHReserved() OptionMatchAH {
	return func(mAH *MatchAH) {
		mAH.Reserved = true
	}
}

func NewMatchAH(opts ...OptionMatchAH) (*MatchAH, error) {
	match := &MatchAH{
		baseMatch: baseMatch{
			matchType: MatchTypeAH,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// Both ipv4 and ipv6
// Non-numeric unsupported
type MatchAH struct {
	baseMatch
	// spi
	SPIMin int
	SPIMax int
	// spi length
	Length int
	// reversed
	Reserved bool
	// invert
	SPIInvert    bool
	LengthInvert bool
}

func (mAH *MatchAH) Parse(main []byte) (int, bool) {
	// 1. "^ah "
	// 2. "spi((:!?([0-9]+))?(s:!?([0-9]+):([0-9]+))?)?" #1 #2 #3 #4 #5 #6
	// 3. "(length:(!)?([0-9]+))?" #7 #8 #9
	// 4. "( reserved)?" #10
	// 5. "( Unknown invflags: 0x[0-9A-Za-z]+)?" #11
	pattern := `^ah ` +
		`spi((:(!?[0-9]+))?(s:(!?[0-9]+):([0-9]+))?)?` +
		`(length:(!)?([0-9]+))?` +
		`( reserved)?` +
		`( Unknown invflags: 0x[0-9A-Za-z]+)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 12 {
		return 0, false
	}

	// min == max
	min := matches[3]
	if len(min) != 0 {
		if min[0] == '!' {
			mAH.invert = true
			min = min[1:]
		}
		spiMin, err := strconv.Atoi(string(min))
		if err != nil {
			return 0, false
		}
		mAH.SPIMin, mAH.SPIMax = spiMin, spiMin
		return len(matches[0]), true
	}

	// min < max
	min = matches[5]
	max := matches[6]
	if len(min) != 0 && len(max) != 0 {
		if min[0] == '!' {
			mAH.invert = true
			min = min[1:]
		}
		spiMin, err := strconv.Atoi(string(min))
		if err != nil {
			return 0, false
		}
		spiMax, err := strconv.Atoi(string(max))
		if err != nil {
			return 0, false
		}
		mAH.SPIMin, mAH.SPIMax = spiMin, spiMax
	}
	// length
	if len(matches[9]) != 0 {
		length, err := strconv.Atoi(string(matches[9]))
		if err != nil {
			return 0, false
		}
		mAH.Length = length
		if len(matches[8]) != 0 {
			mAH.LengthInvert = true
		}
	}
	if len(matches[10]) != 0 {
		mAH.Reserved = true
	}
	return len(matches[0]), true
}

// BPF
type BPFSockFilter struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

type OptionMatchBPF func(*MatchBPF)

// Pass the BPF byte code format.
// see iptables manual.
func WithMatchBPFCode(code string) OptionMatchBPF {
	return func(mBPF *MatchBPF) {
		mBPF.BPFRaw = code
	}
}

// Pass a path to a pinned eBPF object.
func WithMatchBPFObjectPinnedPath(path string) OptionMatchBPF {
	return func(mBPF *MatchBPF) {
		mBPF.Path = path
	}
}

func NewMatchBPF(opts ...OptionMatchBPF) (*MatchBPF, error) {
	match := &MatchBPF{
		baseMatch: baseMatch{
			matchType: MatchTypeBPF,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchBPF struct {
	baseMatch
	BPF    []BPFSockFilter
	BPFRaw string
	Path   string
}

func (mBPF *MatchBPF) Parse(main []byte) (int, bool) {
	// 1. "^match bpf "
	// 2. "([0-9, ]+\000)?" #1
	// 3. "(pinned ([ -~]+))?" #2 #3
	// 4. "(unknown)?" #4
	pattern := `^match bpf ([0-9, ]+\000)?(pinned ([ -~]+))?(unknown)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	// bpf
	bpf := matches[1]
	if len(bpf) != 0 {
		// remove last \0
		bpfStr := string(bpf[:len(bpf)-1])
		instructions := strings.Split(bpfStr, ",")
		mBPF.BPF = make([]BPFSockFilter, len(instructions))
		for i, instruction := range instructions {
			elems := strings.Split(instruction, " ")
			if len(elems) != 4 {
				return 0, false
			}
			code, err := strconv.Atoi(elems[0])
			if err != nil {
				return 0, false
			}
			jt, err := strconv.Atoi(elems[1])
			if err != nil {
				return 0, false
			}
			jf, err := strconv.Atoi(elems[2])
			if err != nil {
				return 0, false
			}
			k, err := strconv.Atoi(elems[3])
			if err != nil {
				return 0, false
			}
			sockFilter := BPFSockFilter{
				uint16(code), uint8(jt), uint8(jf), uint32(k),
			}
			mBPF.BPF[i] = sockFilter
		}
		return len(matches[0]), true
	}
	// or path
	path := matches[3]
	if len(path) != 0 {
		mBPF.Path = string(path)
		return len(matches[0]), true
	}
	// or unknown
	if len(matches[4]) != 0 {
		return len(matches[0]), true
	}
	return 0, false
}

type OptionMatchCGroup func(*MatchCGroup)

// Match corresponding cgroup for this packet.
// Can be used to assign particular firewall policies
// for aggregated task/jobs on the system.
// This allows for more fine-grained firewall policies that
// only match for a subset of the system's processes.
// fwid is the maker set through the net_cls cgroup's id.
func WithMatchCGroupClassID(yes bool, classid int) OptionMatchCGroup {
	return func(mCGroup *MatchCGroup) {
		mCGroup.ClassID = classid
		mCGroup.ClassIDInvert = !yes
	}
}

// Match cgroup2 membership.
func WithMatchCGroupPath(yes bool, path string) OptionMatchCGroup {
	return func(mCGroup *MatchCGroup) {
		mCGroup.Path = path
		mCGroup.PathInvert = !yes
	}
}

func NewMatchCGroup(opts ...OptionMatchCGroup) (*MatchCGroup, error) {
	match := &MatchCGroup{
		baseMatch: baseMatch{
			matchType: MatchTypeCGroup,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchCGroup struct {
	baseMatch
	Path    string
	ClassID int
	// invert
	PathInvert    bool
	ClassIDInvert bool
}

func (mCG *MatchCGroup) Parse(main []byte) (int, bool) {
	// 1. "^cgroup"
	// 2. "( (! )?([ -~]+))?" #1 #2 #3
	// 3. "( (! )?([0-9]+))?" #4 #5 #6
	pattern := `^cgroup( (! )?([ -~]+))?( (! )?([0-9]+))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 7 {
		return 0, false
	}
	// path
	if len(matches[3]) != 0 {
		mCG.Path = string(matches[3])
		if len(matches[2]) != 0 {
			mCG.PathInvert = true
		}
		return len(matches[0]), true
	}
	// net_cls class id
	classID := matches[6]
	if len(classID) != 0 {
		id, err := strconv.Atoi(string(classID))
		if err != nil {
			return 0, false
		}
		mCG.ClassID = id
		if len(matches[5]) != 0 {
			mCG.ClassIDInvert = true
		}
		return len(matches[0]), true
	}
	return 0, false
}

type OptionMatchCluster func(*MatchCluster)

// Set number of total nodes in cluster.
func WithMatchClusterTotalNodes(total int) OptionMatchCluster {
	return func(mCluster *MatchCluster) {
		mCluster.TotalNodes = total
	}
}

// Set the local node number ID.
func WithMatchClusterLocalNode(localNode uint64) OptionMatchCluster {
	return func(mCluster *MatchCluster) {
		mCluster.LocalNodeMask = localNode
	}
}

// Set the local node number ID mask.
func WithMatchClusterLocalNodeMask(mask uint64) OptionMatchCluster {
	return func(mCluster *MatchCluster) {
		mCluster.LocalNodeMask = mask
	}
}

// Set seed value of the Jenkins hash.
func WithMatchClusterHashSeed(seed uint64) OptionMatchCluster {
	return func(mCluster *MatchCluster) {
		mCluster.HashSeed = seed
	}
}

func NewMatchCluster(opts ...OptionMatchCluster) (*MatchCluster, error) {
	match := &MatchCluster{
		baseMatch: baseMatch{
			matchType: MatchTypeCluster,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchCluster struct {
	baseMatch
	TotalNodes    int
	LocalNodeMask uint64
	HashSeed      uint64
}

func (mCluster *MatchCluster) Parse(main []byte) (int, bool) {
	// 1. "^cluster "
	// 2. "(!)?node_mask=0x([A-Za-z]+)" #1 #2
	// 3. " total_nodes=([0-9]+) hash_seed=0x([A-Za-z]+)" #3 #4
	pattern := `^cluster ` +
		`(!)?node_mask=0x([0-9A-Za-z]+)` +
		` total_nodes=([0-9]+) hash_seed=0x([0-9A-Za-z]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	// node mask
	if len(matches[2]) != 0 {
		mask, err := strconv.ParseUint(string(matches[2]), 16, 64)
		if err != nil {
			return 0, false
		}
		mCluster.LocalNodeMask = mask
		if len(matches[1]) != 0 {
			mCluster.invert = true
		}
	}
	// total nodes
	if len(matches[3]) != 0 {
		total, err := strconv.Atoi(string(matches[3]))
		if err != nil {
			return 0, false
		}
		mCluster.TotalNodes = total
	}
	// hash seed
	if len(matches[4]) != 0 {
		seed, err := strconv.ParseUint(string(matches[4]), 16, 54)
		if err != nil {
			return 0, false
		}
		mCluster.HashSeed = seed
	}
	return len(matches[0]), true
}

func NewMatchComment(comment string) (*MatchComment, error) {
	match := &MatchComment{
		baseMatch: baseMatch{
			matchType: MatchTypeComment,
		},
		Comment: comment,
	}
	return match, nil
}

type MatchComment struct {
	baseMatch
	Comment string
}

func (mComment *MatchComment) Parse(main []byte) (int, bool) {
	// 1. "^/\* ([ -~]*) \*/" #1
	pattern := `^/\* ([ -~]*) \*/ *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 2 {
		return 0, false
	}
	// comment
	if len(matches[1]) != 0 {
		mComment.Comment = string(matches[1])
	}
	return len(matches[0]), true
}

type ConnBytesMode string

const (
	// mode
	ConnBytesModePackets ConnBytesMode = "packets"
	ConnBytesModeBytes   ConnBytesMode = "bytes"
	ConnBytesModeAvgpkt  ConnBytesMode = "avgpkt"
	ConnBytesModeUnknown ConnBytesMode = "unknown"
)

type OptionMatchConnBytes func(*MatchConnBytes)

// Match packets from a connection whose packets/bytes/average packet size
// is more than FROM and less than TO bytes/packets.
// if TO is omitted only FROM check is done.
func WithMatchConnBytes(yes bool, bytes ...int64) OptionMatchConnBytes {
	return func(mConnBytes *MatchConnBytes) {
		switch len(bytes) {
		case 1:
			mConnBytes.From = bytes[0]
			mConnBytes.To = -1
		case 2:
			mConnBytes.From = bytes[0]
			mConnBytes.To = bytes[1]
		}
		mConnBytes.invert = !yes
	}
}

// Which packets to consider
func WithMatchConnBytesDirection(dir ConnTrackDir) OptionMatchConnBytes {
	return func(mConnBytes *MatchConnBytes) {
		mConnBytes.Direction = dir
	}
}

// Whether to check the amount of packets, number of bytes transferred
// or the average size (in bytes) of all packets received so far.
// Note that when "both" is used together with "avgpkt",
// and data is going (mainly) only in one direction (for example HTTP),
// the average packet size will be about half of the actual data packets.
func WithMatchConnBytesMode(mode ConnBytesMode) OptionMatchConnBytes {
	return func(mConnBytes *MatchConnBytes) {
		mConnBytes.Mode = mode
	}
}

func NewMatchConnBytes(opts ...OptionMatchConnBytes) (*MatchConnBytes, error) {
	match := &MatchConnBytes{
		baseMatch: baseMatch{
			matchType: MatchTypeConnBytes,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchConnBytes struct {
	baseMatch
	From      int64
	To        int64
	Mode      ConnBytesMode
	Direction ConnTrackDir
}

func (mConnBytes *MatchConnBytes) Parse(main []byte) (int, bool) {
	// 1. "^(!)? connbytes ([0-9]+)(:([0-9]+))?" #1 #2 #3 #4
	// 2. " connbytes mode ([A-Za-z]+)" #5
	// 3. " connbytes direction ([A-Za-z]+)" #6
	pattern := `^(! )?connbytes ([0-9]+)(:([0-9]+))? connbytes mode ([A-Za-z]+) connbytes direction ([A-Za-z]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 7 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mConnBytes.invert = true
	}
	// connbytes
	if len(matches[2]) != 0 {
		from, err := strconv.ParseInt(string(matches[2]), 10, 64)
		if err != nil {
			return 0, false
		}
		mConnBytes.From = from
	}
	if len(matches[4]) != 0 {
		to, err := strconv.ParseInt(string(matches[4]), 10, 64)
		if err != nil {
			return 0, false
		}
		mConnBytes.To = to
	}
	// connbytes mode
	if len(matches[5]) != 0 {
		mConnBytes.Mode = ConnBytesMode(string(matches[5]))
	}
	// connbytes direction
	if len(matches[6]) != 0 {
		switch string(matches[6]) {
		case CTDirReply:
			mConnBytes.Direction = REPLY
		case CTDirOriginal:
			mConnBytes.Direction = ORIGINAL
		case CTDirBoth:
			mConnBytes.Direction = BOTH
		default:
			return 0, false
		}
	}
	return len(matches[0]), true
}

type OptionMatchConnLabel func(*MatchConnLabel)

// Matches if label number has been set on a connection.
// Check /etc/xtables/connlabel.conf
func WithMatchConnLabel(yes bool, label int) OptionMatchConnLabel {
	return func(mConnLabel *MatchConnLabel) {
		mConnLabel.Label = label
		mConnLabel.invert = !yes
	}
}

// Matches if label name has been set on a connection.
func WithMatchConnLabelName(yes bool, name string) OptionMatchConnLabel {
	return func(mConnLabel *MatchConnLabel) {
		mConnLabel.LabelName = name
		mConnLabel.invert = !yes
	}
}

// If the label has not been set on the connection, set it.
func WithMatchConnLabelSet() OptionMatchConnLabel {
	return func(mConnLabel *MatchConnLabel) {
		mConnLabel.Set = true
	}
}

func NewMatchConnLabel(opts ...OptionMatchConnLabel) (*MatchConnLabel, error) {
	match := &MatchConnLabel{
		baseMatch: baseMatch{
			matchType: MatchTypeConnLabel,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchConnLabel struct {
	baseMatch
	Label     int
	LabelName string
	Set       bool
}

func (mConnLabel *MatchConnLabel) Parse(main []byte) (int, bool) {
	// 1. "^connlabel"
	// 2. "( !)?" #1
	// 3. "( ([0-9]+))?" #2 #3
	// 4. "( '([ -~]+)')?" #4 #5
	// 5. "( set)?" #6
	pattern := `^connlabel( !)?( ([0-9]+))?( '([ -~]+)')?( set)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 7 {
		return 0, false
	}
	// invert
	if len(matches[1]) != 0 {
		mConnLabel.invert = true
	}
	// label
	if len(matches[3]) != 0 {
		label, err := strconv.Atoi(string(matches[3]))
		if err != nil {
			return 0, false
		}
		mConnLabel.Label = label
	}
	// label name
	if len(matches[5]) != 0 {
		mConnLabel.LabelName = string(matches[5])
	}
	// set
	if len(matches[6]) != 0 {
		mConnLabel.Set = true
	}
	return len(matches[0]), true
}

type MatchConnLimit struct {
	baseMatch
	Upto  int
	Above int
	Mask  int
	Src   bool
	Dst   bool
}

type OptionMatchConnLimit func(*MatchConnLimit)

// Match if the number of existing connections is below or equal n.
func WithMatchConnLimitUpto(upto int) OptionMatchConnLimit {
	return func(mConnLimit *MatchConnLimit) {
		mConnLimit.Upto = upto
	}
}

// Match if the number of existing connections is above n.
func WithMatchConnLimitAbove(above int) OptionMatchConnLimit {
	return func(mConnLimit *MatchConnLimit) {
		mConnLimit.Above = above
	}
}

// Group hosts using the prefix length.
// For IPv4, this must be a number between (including) 0 and 32.
// For IPv6, between 0 and 128. If not specified, the maximum prefix
// length for the applicable protocol is used.
func WithMatchConnLimitMask(mask int) OptionMatchConnLimit {
	return func(mConnLimit *MatchConnLimit) {
		mConnLimit.Mask = mask
	}
}

// Apply the limit onto the source group.
func WithMatchConnLimitSrcAddr() OptionMatchConnLimit {
	return func(mConnLimit *MatchConnLimit) {
		mConnLimit.Src = true
	}
}

// Apply the limit onto the destination group.
func WithMatchConnLimitDstAddr() OptionMatchConnLimit {
	return func(mConnLimit *MatchConnLimit) {
		mConnLimit.Dst = true
	}
}

func NewMatchConnLimit(opts ...OptionMatchConnLimit) (*MatchConnLimit, error) {
	match := &MatchConnLimit{
		baseMatch: baseMatch{
			matchType: MatchTypeConnLimit,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

func (mConnLimit *MatchConnLimit) Parse(main []byte) (int, bool) {
	// 1. "^#conn (src|dst)/([0-9]+) ([<=>]+) ([0-9]+)" #1 #2 #3 #4
	pattern := `^#conn (src|dst)/([0-9]+) ([<=>]+) ([0-9]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	if bytes.Compare(matches[1], []byte("src")) == 0 {
		mConnLimit.Src = true
	}
	if bytes.Compare(matches[1], []byte("dst")) == 0 {
		mConnLimit.Dst = true
	}
	if len(matches[2]) != 0 {
		mask, err := strconv.Atoi(string(matches[2]))
		if err != nil {
			return 0, false
		}
		mConnLimit.Mask = mask
	}
	limit := -1
	err := error(nil)
	if len(matches[4]) != 0 {
		limit, err = strconv.Atoi(string(matches[4]))
		if err != nil {
			return 0, false
		}
	}
	if bytes.Compare(matches[3], []byte("<=")) == 0 {
		mConnLimit.Upto = limit
	}
	if bytes.Compare(matches[3], []byte(">")) == 0 {
		mConnLimit.Above = limit
	}
	return len(matches[0]), true
}

// Takes mostly 2 value, (mark) or (mark, mask)
// Matches packets in connections with the given mark value.
// If a mask is specified, this is logically ANDed with the mark before the comparison.
func NewMatchConnMark(yes bool, value ...int) (*MatchConnMark, error) {
	mConnMark := &MatchConnMark{
		baseMatch: baseMatch{
			matchType: MatchTypeConnMark,
		},
	}
	switch len(value) {
	case 1:
		mConnMark.Value = value[0]
		mConnMark.Mask = -1
	case 2:
		mConnMark.Value = value[0]
		mConnMark.Mask = value[1]
	}
	mConnMark.invert = !yes
	return mConnMark, nil
}

type MatchConnMark struct {
	baseMatch
	Value int
	Mask  int
}

func (mConnMark *MatchConnMark) Parse(main []byte) (int, bool) {
	// 1. "^CONNMARK|connmark match "
	// 2. "(!)?" #1
	// 3. " 0x([0-9A-Za-z]+)(/0x([0-9A-Za-z]+))?" #2 #4
	pattern := `^CONNMARK|connmark match (!)? 0x([0-9A-Za-z]+)(/0x([0-9A-Za-z]+))?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mConnMark.invert = true
	}
	if len(matches[2]) != 0 {
		value, err := strconv.Atoi(string(matches[2]))
		if err != nil {
			return 0, false
		}
		mConnMark.Value = value
	}
	if len(matches[4]) != 0 {
		mask, err := strconv.Atoi(string(matches[4]))
		if err != nil {
			return 0, false
		}
		mConnMark.Mask = mask
	}
	return len(matches[0]), true
}

type ConnTrackState int

const (
	INVALID ConnTrackState = 1 << iota
	NEW
	ESTABLISHED
	RELATED
	UNTRACKED
	SNAT
	DNAT
)

const (
	CTStateINVALID     = "INVALID"
	CTStateNEW         = "NEW"
	CTStateESTABLISHED = "ESTABLISHED"
	CTStateRELATED     = "RELATED"
	CTStateUNTRACKED   = "UNTRACKED"
	CTStateSNAT        = "SNAT"
	CTStateDNAT        = "DNAT"
)

type ConnTrackStatus int

const (
	NONE ConnTrackStatus = 1 << iota
	EXPECTED
	SEEN_REPLY
	ASSURED
	CONFIRMED
)

const (
	CTStatusNONE       = "NONE"
	CTStatusEXPECTED   = "EXPECTED"
	CTStatusSEEN_REPLY = "SEEN_REPLY"
	CTStatusASSURED    = "ASSURED"
	CTStatusCONFIRMED  = "CONFIRMED"
)

type ConnTrackDir int

const (
	ORIGINAL ConnTrackDir = 1 << iota
	REPLY
	BOTH
)

const (
	CTDirREPLY    = "REPLY"
	CTDirORIGINAL = "ORIGINAL"
	CTDirBOTH     = "BOTH"
	CTDirReply    = "reply"
	CTDirOriginal = "original"
	CTDirBoth     = "both"
)

const (
	CTStateAlias  = "state"
	CTState       = "ctstate"
	CTProto       = "ctproto"
	CTStatus      = "ctstatus"
	CTExpire      = "ctexpire"
	CTDir         = "ctdir"
	CTOrigSrc     = "ctorigsrc"
	CTOrigDst     = "ctorigdrc"
	CTReplSrc     = "ctreplsrc"
	CTReplDst     = "ctrepldst"
	CTOrigSrcPort = "ctorigsrcport"
	CTOrigDstPort = "ctorigdstport"
	CTReplSrcPort = "ctreplsrcport"
	CTReplDstPort = "ctrepldstport"
)

type OptionMatchConnTrack func(*MatchConnTrack)

func WithMatchConnTrackState(states ...ConnTrackState) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		for _, state := range states {
			mConnTrack.State |= state
		}
	}
}

func WithMatchConnTrackStatus(statuses ...ConnTrackStatus) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		for _, status := range statuses {
			mConnTrack.Status |= status
		}
	}
}

// Layer-4 protocol to match
func WithMatchConnTrackProtocol(proto Protocol) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		mConnTrack.Proto = proto
	}
}

func WithMatchConnTrackOriginSrc(yes bool, addr *net.IPNet) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		addr, _ := ParseAddress(addr)
		mConnTrack.OrigSrc = addr
		mConnTrack.OrigSrcInvert = !yes
	}
}

func WithMatchConnTrackOriginDst(yes bool, addr *net.IPNet) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		addr, _ := ParseAddress(addr)
		mConnTrack.OrigDst = addr
		mConnTrack.OrigDstInvert = !yes
	}
}

func WithMatchConnTrackReplySrc(yes bool, addr *net.IPNet) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		addr, _ := ParseAddress(addr)
		mConnTrack.ReplSrc = addr
		mConnTrack.ReplSrcInvert = !yes
	}
}

func WithMatchConnTrackReplyDst(yes bool, addr *net.IPNet) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		addr, _ := ParseAddress(addr)
		mConnTrack.ReplDst = addr
		mConnTrack.ReplDstInvert = !yes
	}
}

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchConnTrackOriginSrcPort(yes bool, port ...int) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		switch len(port) {
		case 1:
			mConnTrack.OrigSrcPortMin = port[0]
			mConnTrack.OrigSrcPortMax = -1
		case 2:
			mConnTrack.OrigSrcPortMin = port[0]
			mConnTrack.OrigSrcPortMax = port[1]
		}
		mConnTrack.OrigSrcPortInvert = !yes
	}
}

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchConnTrackOriginDstPort(yes bool, port ...int) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		switch len(port) {
		case 1:
			mConnTrack.OrigDstPortMin = port[0]
			mConnTrack.OrigDstPortMax = -1
		case 2:
			mConnTrack.OrigDstPortMin = port[0]
			mConnTrack.OrigDstPortMax = port[1]
		}
		mConnTrack.OrigDstPortInvert = !yes
	}
}

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchConnTrackReplySrcPort(yes bool, port ...int) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		switch len(port) {
		case 1:
			mConnTrack.ReplSrcPortMin = port[0]
			mConnTrack.ReplSrcPortMax = -1
		case 2:
			mConnTrack.ReplSrcPortMin = port[0]
			mConnTrack.ReplSrcPortMax = port[1]
		}
		mConnTrack.ReplSrcPortInvert = !yes
	}
}

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchConnTrackReplyDstPort(yes bool, port ...int) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		switch len(port) {
		case 1:
			mConnTrack.ReplDstPortMin = port[0]
			mConnTrack.ReplDstPortMax = -1
		case 2:
			mConnTrack.ReplDstPortMin = port[0]
			mConnTrack.ReplDstPortMax = port[1]
		}
		mConnTrack.ReplDstPortInvert = !yes
	}
}

func WithMatchConnTrackDirection(dir ConnTrackDir) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		mConnTrack.Direction = dir
	}
}

// This option takes mostly 2 time, (min) or (min, max)
func WithMatchConnTrackExpire(yes bool, time ...int) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		switch len(time) {
		case 1:
			mConnTrack.ExpireMin = time[0]
			mConnTrack.ExpireMax = -1
		case 2:
			mConnTrack.ExpireMin = time[0]
			mConnTrack.ExpireMax = time[1]
		}
		mConnTrack.ExpireInvert = !yes

	}
}

func NewMatchConnTrack(opts ...OptionMatchConnTrack) (*MatchConnTrack, error) {
	match := &MatchConnTrack{
		baseMatch: baseMatch{
			matchType: MatchTypeConnTrack,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchConnTrack struct {
	baseMatch
	State          ConnTrackState
	Status         ConnTrackStatus
	Direction      ConnTrackDir
	Proto          Protocol
	OrigSrc        *Address
	OrigDst        *Address
	ReplSrc        *Address
	ReplDst        *Address
	OrigSrcPortMin int
	OrigSrcPortMax int
	OrigDstPortMin int
	OrigDstPortMax int
	ReplSrcPortMin int
	ReplSrcPortMax int
	ReplDstPortMin int
	ReplDstPortMax int
	ExpireMin      int
	ExpireMax      int
	// invert
	StateInvert       bool
	StatusInvert      bool
	ProtoInvert       bool
	OrigSrcInvert     bool
	OrigDstInvert     bool
	ReplSrcInvert     bool
	ReplDstInvert     bool
	OrigSrcPortInvert bool
	OrigDstPortInvert bool
	ReplSrcPortInvert bool
	ReplDstPortInvert bool
	ExpireInvert      bool
	DirectionInvert   bool
}

func (mConnTrack *MatchConnTrack) Parse(main []byte) (int, bool) {
	pattern :=
		`^(! )?(state|ctstate|ctproto|ctstatus|ctexpire|ctdir|` +
			`ctorigsrc|ctorigdst|ctreplsrc|ctrepldst|` +
			`ctorigsrcport|ctorigdstport|ctreplsrcport|ctrepldstport)` +
			` +` +
			`((([0-9]{1,3}\.){3}[0-9]{1,3}(\/([1-2][0-9]|3[0-2]|[0-9]))?)|` +
			`(anywhere)|` +
			`(REPLY|ORIGINAL)|` +
			`([0-9]+)(:([0-9]+))?|` +
			`([A-Za-z/,]+)) *`
	reg := regexp.MustCompile(pattern)
	index := 0
	for len(main) > 0 {
		matches := reg.FindSubmatch(main)
		if len(matches) != 14 {
			goto END
		}
		if len(matches[2]) == 0 {
			goto END
		}
		invert := false
		if len(matches[1]) != 0 {
			invert = true
		}
		opt := string(matches[2])
		switch opt {
		case CTStateAlias, CTState:
			states := strings.Split(string(matches[13]), ",")
			for _, state := range states {
				switch state {
				case CTStateINVALID:
					mConnTrack.State |= INVALID
				case CTStateNEW:
					mConnTrack.State |= NEW
				case CTStateESTABLISHED:
					mConnTrack.State |= ESTABLISHED
				case CTStateRELATED:
					mConnTrack.State |= RELATED
				case CTStateUNTRACKED:
					mConnTrack.State |= UNTRACKED
				case CTStateSNAT:
					mConnTrack.State |= SNAT
				case CTStateDNAT:
					mConnTrack.State |= DNAT
				default:
					goto END
				}
			}
			mConnTrack.StateInvert = invert
		case CTProto:
			proto, err := strconv.Atoi(string(matches[10]))
			if err != nil {
				goto END
			}
			mConnTrack.Proto = Protocol(proto)
			mConnTrack.ProtoInvert = invert
		case CTStatus:
			statuses := strings.Split(string(matches[13]), ",")
			for _, status := range statuses {
				switch status {
				case CTStatusNONE:
					mConnTrack.Status |= NONE
				case CTStatusEXPECTED:
					mConnTrack.Status |= EXPECTED
				case CTStatusSEEN_REPLY:
					mConnTrack.Status |= SEEN_REPLY
				case CTStatusASSURED:
					mConnTrack.Status |= ASSURED
				case CTStatusCONFIRMED:
					mConnTrack.Status |= CONFIRMED
				default:
					goto END
				}
			}
			mConnTrack.StatusInvert = invert
		case CTExpire:
			min, err := strconv.Atoi(string(matches[10]))
			if err != nil {
				goto END
			}
			max, err := strconv.Atoi(string(matches[12]))
			if err != nil {
				goto END
			}
			mConnTrack.ExpireMin = min
			mConnTrack.ExpireMax = max
			mConnTrack.ExpireInvert = invert

		case CTDir:
			dir := string(matches[9])
			if dir == CTDirREPLY {
				mConnTrack.Direction = REPLY
			} else if dir == CTDirORIGINAL {
				mConnTrack.Direction = ORIGINAL
			} else {
				goto END
			}
			mConnTrack.DirectionInvert = invert
		case CTOrigSrc:
			src := string(matches[4])
			addr, err := ParseAddress(src)
			if err != nil {
				goto END
			}
			mConnTrack.OrigSrc = addr
			mConnTrack.OrigSrcInvert = invert
		case CTOrigDst:
			dst := string(matches[4])
			addr, err := ParseAddress(dst)
			if err != nil {
				goto END
			}
			mConnTrack.OrigDst = addr
			mConnTrack.OrigDstInvert = invert
		case CTReplSrc:
			src := string(matches[4])
			addr, err := ParseAddress(src)
			if err != nil {
				goto END
			}
			mConnTrack.ReplSrc = addr
			mConnTrack.ReplSrcInvert = invert
		case CTReplDst:
			dst := string(matches[4])
			addr, err := ParseAddress(dst)
			if err != nil {
				goto END
			}
			mConnTrack.ReplDst = addr
			mConnTrack.ReplDstInvert = invert
		case CTOrigSrcPort:
			min, err := strconv.Atoi(string(matches[10]))
			if err != nil {
				goto END
			}
			max, err := strconv.Atoi(string(matches[12]))
			if err != nil {
				goto END
			}
			mConnTrack.OrigSrcPortMin = min
			mConnTrack.OrigSrcPortMax = max
			mConnTrack.OrigSrcPortInvert = invert
		case CTOrigDstPort:
			min, err := strconv.Atoi(string(matches[10]))
			if err != nil {
				goto END
			}
			max, err := strconv.Atoi(string(matches[12]))
			if err != nil {
				goto END
			}
			mConnTrack.OrigDstPortMin = min
			mConnTrack.OrigDstPortMax = max
			mConnTrack.OrigDstPortInvert = invert
		case CTReplSrcPort:
			min, err := strconv.Atoi(string(matches[10]))
			if err != nil {
				goto END
			}
			max, err := strconv.Atoi(string(matches[12]))
			if err != nil {
				goto END
			}
			mConnTrack.ReplSrcPortMin = min
			mConnTrack.ReplSrcPortMax = max
			mConnTrack.ReplSrcPortInvert = invert
		case CTReplDstPort:
			min, err := strconv.Atoi(string(matches[10]))
			if err != nil {
				goto END
			}
			max, err := strconv.Atoi(string(matches[12]))
			if err != nil {
				goto END
			}
			mConnTrack.ReplDstPortMin = min
			mConnTrack.ReplDstPortMax = max
			mConnTrack.ReplDstPortInvert = invert
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

// Match cpu handling this packet. cpus are numbered from 0 to NR_CPUS-1
// Can be used in combination with RPS (Remote Packet Steering) or
// multiqueue NICs to spread network traffic on different queues.
func NewMatchCPU(yes bool, cpu int) (*MatchCPU, error) {
	mCPU := &MatchCPU{
		baseMatch: baseMatch{
			matchType: MatchTypeCPU,
			invert:    !yes,
		},
		CPU: cpu,
	}
	return mCPU, nil
}

type MatchCPU struct {
	baseMatch
	CPU int
}

func (mCPU *MatchCPU) Parse(main []byte) (int, bool) {
	// 1. "^cpu (!)?([0-9]+)"
	pattern := `^cpu (!)?([0-9]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mCPU.invert = true
	}
	cpu, err := strconv.Atoi(string(matches[2]))
	if err != nil {
		return 0, false
	}
	mCPU.CPU = cpu
	return len(matches[0]), true
}

type DCCPType int

const (
	DCCPTypeREQUEST DCCPType = 1 << iota
	DCCPTypeRESPONSE
	DCCPTypeDATA
	DCCPTypeACK
	DCCPTypeDATAACK
	DCCPTypeCLOSEREQ
	DCCPTypeCLOSE
	DCCPTypeRESET
	DCCPTypeSYNC
	DCCPTypeSYNCACK
	DCCPTypeINVALID
)

var (
	DCCPTypes = map[string]DCCPType{
		"REQUEST":  DCCPTypeREQUEST,
		"RESPONSE": DCCPTypeRESPONSE,
		"DATA":     DCCPTypeDATA,
		"ACK":      DCCPTypeACK,
		"DATAACK":  DCCPTypeDATAACK,
		"CLOSEREQ": DCCPTypeCLOSEREQ,
		"CLOSE":    DCCPTypeCLOSE,
		"RESET":    DCCPTypeRESET,
		"SYNC":     DCCPTypeSYNC,
		"SYNCACK":  DCCPTypeSYNCACK,
		"INVALID":  DCCPTypeINVALID,
	}
)

type OptionMatchDCCP func(*MatchDCCP)

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchDCCPSrcPort(yes bool, port ...int) OptionMatchDCCP {
	return func(mDCCP *MatchDCCP) {
		switch len(port) {
		case 1:
			mDCCP.SrcPortMin = port[0]
			mDCCP.SrcPortMax = -1
		case 2:
			mDCCP.SrcPortMin = port[0]
			mDCCP.SrcPortMax = port[1]
		}
		mDCCP.SrcPortInvert = !yes
	}
}

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchDCCPDstPort(yes bool, port ...int) OptionMatchDCCP {
	return func(mDCCP *MatchDCCP) {
		switch len(port) {
		case 1:
			mDCCP.DstPortMin = port[0]
			mDCCP.DstPortMax = -1
		case 2:
			mDCCP.DstPortMin = port[0]
			mDCCP.DstPortMax = port[1]
		}
		mDCCP.DstPortInvert = !yes
	}
}

// Match when the DCCP packet type in types.
func WithMatchDCCPMask(yes bool, types ...DCCPType) OptionMatchDCCP {
	return func(mDCCP *MatchDCCP) {
		for _, typ := range types {
			mDCCP.Type |= typ
		}
		mDCCP.TypeInvert = !yes
	}
}

// Match if DCCP option set.
func WithMatchDCCOption(yes bool, option int) OptionMatchDCCP {
	return func(mDCCP *MatchDCCP) {
		mDCCP.Option = option
		mDCCP.OptionInvert = !yes
	}
}

func NewMatchDCCP(opts ...OptionMatchDCCP) (*MatchDCCP, error) {
	match := &MatchDCCP{
		baseMatch: baseMatch{
			matchType: MatchTypeDCCP,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchDCCP struct {
	baseMatch
	SrcPortMin int
	SrcPortMax int
	DstPortMin int
	DstPortMax int
	Type       DCCPType
	Option     int
	// invert
	SrcPortInvert bool
	DstPortInvert bool
	TypeInvert    bool
	OptionInvert  bool
}

func (mDCCP *MatchDCCP) Parse(main []byte) (int, bool) {
	// 1. "^dccp"
	// 2. "( spt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?" #1 #2 #3 #4 #5 #6 #7 #8
	// 3. "( dpt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?" #9 #10 #11 #12 #13 #14 #15 #16
	// 4. "(( !)? ([0-9,]+))?" #17 #18 #19
	// 5. "( option=(!)?([0-9]+))?" #20 #21 #22
	pattern := `^dccp` +
		`( spt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?` +
		`( dpt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?` +
		`(( !)? ([0-9,]+))?` +
		`( option=(!)?([0-9]+))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 23 {
		return 0, false
	}
	if len(matches[4]) != 0 {
		spt, err := strconv.Atoi(string(matches[4]))
		if err != nil {
			return 0, false
		}
		mDCCP.SrcPortMin = spt
		if len(matches[3]) != 0 {
			mDCCP.SrcPortInvert = true
		}
	}
	if len(matches[7]) != 0 {
		min, err := strconv.Atoi(string(matches[7]))
		if err != nil {
			return 0, false
		}
		max, err := strconv.Atoi(string(matches[8]))
		if err != nil {
			return 0, false
		}
		if len(matches[6]) != 0 {
			mDCCP.SrcPortInvert = true
		}
		mDCCP.SrcPortMin = min
		mDCCP.SrcPortMax = max
	}
	if len(matches[12]) != 0 {
		dpt, err := strconv.Atoi(string(matches[12]))
		if err != nil {
			return 0, false
		}
		mDCCP.DstPortMin = dpt
		if len(matches[11]) != 0 {
			mDCCP.DstPortInvert = true
		}
	}
	if len(matches[15]) != 0 {
		min, err := strconv.Atoi(string(matches[15]))
		if err != nil {
			return 0, false
		}
		max, err := strconv.Atoi(string(matches[16]))
		if err != nil {
			return 0, false
		}
		if len(matches[14]) != 0 {
			mDCCP.DstPortInvert = true
		}
		mDCCP.DstPortMin = min
		mDCCP.DstPortMax = max
	}
	if len(matches[19]) != 0 {
		elems := strings.Split(string(matches[19]), ",")
		for _, elem := range elems {
			typ, err := strconv.Atoi(elem)
			if err != nil {
				return 0, false
			}
			mDCCP.Type |= 1 << typ
		}
		if len(matches[18]) != 0 {
			mDCCP.TypeInvert = true
		}
	}
	if len(matches[22]) != 0 {
		opt, err := strconv.Atoi(string(matches[22]))
		if err != nil {
			return 0, false
		}
		mDCCP.Option = opt
		if len(matches[21]) != 0 {
			mDCCP.OptionInvert = true
		}
	}
	return len(matches[0]), true
}

type OptionMatchDevGroup func(*MatchDevGroup)

// Match device group of incoming device.
func WithMatchDevGroupSrc(yes bool, src uint64) OptionMatchDevGroup {
	return func(mDevGroup *MatchDevGroup) {
		mDevGroup.SrcGroup = src
		mDevGroup.SrcGroupInvert = !yes
	}
}

// Match device group of outgoing device.
func WithMatchDevGroupDst(yes bool, dst uint64) OptionMatchDevGroup {
	return func(mDevGroup *MatchDevGroup) {
		mDevGroup.DstGroup = dst
		mDevGroup.DstGroupInvert = !yes
	}
}

func NewMatchDevGroup(opts ...OptionMatchDevGroup) (*MatchDevGroup, error) {
	match := &MatchDevGroup{
		baseMatch: baseMatch{
			matchType: MatchTypeDevGroup,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchDevGroup struct {
	baseMatch
	SrcGroup uint64
	DstGroup uint64
	// invert
	SrcGroupInvert bool
	DstGroupInvert bool
}

func (mDevGroup *MatchDevGroup) Parse(main []byte) (int, bool) {
	pattern := `^(! )?(src-group|dst-group) 0x([0-9A-Za-z]+) *`
	reg := regexp.MustCompile(pattern)
	index := 0
	for len(main) > 0 {
		matches := reg.FindSubmatch(main)
		if len(matches) != 4 {
			goto END
		}
		invert := false
		if len(matches[1]) != 0 {
			invert = true
		}

		opt := string(matches[2])
		switch opt {
		case "src-group":
			group, err := strconv.ParseUint(string(matches[3]), 16, 64)
			if err != nil {
				goto END
			}
			mDevGroup.SrcGroup = group
			mDevGroup.SrcGroupInvert = invert
		case "dst-group":
			group, err := strconv.ParseUint(string(matches[3]), 16, 64)
			if err != nil {
				return 0, false
			}
			mDevGroup.DstGroup = group
			mDevGroup.DstGroupInvert = invert
		default:
			goto END
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

// see https://git.netfilter.org/iptables/tree/extensions/dscp_helper.c
type DSCPClass int

const (
	ClassCS0  DSCPClass = 0x00
	ClassCS1  DSCPClass = 0x08
	ClassCS2  DSCPClass = 0x10
	ClassCS3  DSCPClass = 0x18
	ClassCS4  DSCPClass = 0x20
	ClassCS5  DSCPClass = 0x28
	ClassCS6  DSCPClass = 0x30
	ClassCS7  DSCPClass = 0x38
	ClassBE   DSCPClass = 0x00
	ClassAF11 DSCPClass = 0x0a
	ClassAF12 DSCPClass = 0x0c
	ClassAF13 DSCPClass = 0x0e
	ClassAF21 DSCPClass = 0x12
	ClassAF22 DSCPClass = 0x14
	ClassAF23 DSCPClass = 0x16
	ClassAF31 DSCPClass = 0x1a
	ClassAF32 DSCPClass = 0x1c
	ClassAF33 DSCPClass = 0x1e
	ClassAF41 DSCPClass = 0x22
	ClassAF42 DSCPClass = 0x24
	ClassAF43 DSCPClass = 0x26
	ClassEF   DSCPClass = 0x2e
)

type OptionMatchDSCP func(*MatchDSCP)

// Match against a numeric value [0-63].
func WithMatchDSCPValue(yes bool, value int) OptionMatchDSCP {
	return func(mDSCP *MatchDSCP) {
		mDSCP.Value = value
		mDSCP.invert = !yes
	}
}

func WithMatchDSCPClass(yes bool, class DSCPClass) OptionMatchDSCP {
	return func(mDSCP *MatchDSCP) {
		mDSCP.Value = int(class)
		mDSCP.invert = !yes
	}
}

func NewMatchDSCP(opts ...OptionMatchDSCP) (*MatchDSCP, error) {
	match := &MatchDSCP{
		baseMatch: baseMatch{
			matchType: MatchTypeDSCP,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchDSCP struct {
	baseMatch
	Value int
}

func (mDSCP *MatchDSCP) Parse(main []byte) (int, bool) {
	pattern := `^DSCP match (!)?0x([0-9A-Za-z]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		value, err := strconv.ParseUint(string(matches[2]), 16, 64)
		if err != nil {
			return 0, false
		}
		mDSCP.Value = int(value)
		if len(matches[1]) != 0 {
			mDSCP.invert = true
		}
	}
	return len(matches[0]), true
}

type OptionMatchDst func(*MatchDst)

// Total length of this header in octets.
func WithMatchDstLen(yes bool, length int) OptionMatchDst {
	return func(mDst *MatchDst) {
		mDst.Length = length
		mDst.invert = !yes
	}
}

// Numeric type of option and the length of the option data in octets.
func WithMatchDstOpts(opts ...IPv6Option) OptionMatchDst {
	return func(mDst *MatchDst) {
		mDst.Options = opts
	}
}

func NewMatchDst(opts ...OptionMatchDst) (*MatchDst, error) {
	match := &MatchDst{
		baseMatch: baseMatch{
			matchType: MatchTypeDst,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// IPv6 specific
// Non-numeric unsupport
type MatchDst struct {
	baseMatch
	Length  int
	Options []IPv6Option
}

func (mDst *MatchDst) Parse(main []byte) (int, bool) {
	// 1. "^dst"
	// 2. "( length:(!)?([0-9]+))?" #1 #2 #3
	// 3. "( opts (([0-9]+(:[0-9]+)?[, ])*))?" #4 #5 #6 #7
	// 4. "( Unknown invflags: 0x[0-9A-Za-z]+)?" #8
	pattern := `^dst` +
		`( length:(!)?([0-9]+))?` +
		`( opts ((,?[0-9]+(:[0-9]+)?)*))?` +
		`( Unknown invflags: 0x[0-9A-Za-z]+)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 9 {
		return 0, false
	}
	if len(matches[3]) != 0 {
		length, err := strconv.Atoi(string(matches[3]))
		if err != nil {
			return 0, false
		}
		mDst.Length = length
		if len(matches[2]) != 0 {
			mDst.invert = true
		}
	}
	mDst.Options = []IPv6Option{}
	if len(matches[5]) != 0 {
		elems := strings.Split(string(matches[5]), ",")
		for _, elem := range elems {
			opt := IPv6Option{}
			typelength := strings.Split(string(elem), ":")
			if len(typelength) >= 1 {
				typ, err := strconv.Atoi(typelength[0])
				if err != nil {
					return 0, false
				}
				opt.Type = typ
			}
			if len(typelength) >= 2 {
				length, err := strconv.Atoi(typelength[1])
				if err != nil {
					return 0, false
				}
				opt.Length = length
			}
			mDst.Options = append(mDst.Options, opt)
		}
	}
	return len(matches[0]), true
}

type OptionMatchECN func(*MatchECN)

// This matches if the TCP ECN ECE (ECN Echo) bit is set.
func WithMatchECNECE(yes bool) OptionMatchECN {
	return func(mECN *MatchECN) {
		mECN.ECE = true
		mECN.ECEInvert = !yes
	}
}

// This matches if the TCP ECN CWR (Congestion Window Received) bit is set.
func WithMatchECNCWR(yes bool) OptionMatchECN {
	return func(mECN *MatchECN) {
		mECN.CWR = true
		mECN.CWRInvert = !yes
	}
}

// This matches a particular IPv4/IPv6 ECT (ECN-Capable Transport).
// You have to specify a number between `0' and `3'.
func WithMatchECNECT(yes bool, ect int) OptionMatchECN {
	return func(mECN *MatchECN) {
		mECN.ECT = ect
		mECN.ECTInvert = !yes
	}
}

func NewMatchECN(opts ...OptionMatchECN) (*MatchECN, error) {
	match := &MatchECN{
		baseMatch: baseMatch{
			matchType: MatchTypeECN,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchECN struct {
	baseMatch
	ECE       bool
	CWR       bool
	ECT       int
	ECEInvert bool
	CWRInvert bool
	ECTInvert bool
}

func (mECN *MatchECN) Parse(main []byte) (int, bool) {
	// 1. "^ECN match"
	// 2. "( (!)?ECE)?" #1 #2
	// 3. "( (!)?CWR)?" #3 #4
	// 4. "( (!)?ECT=([0-3]))?" #5 #6 #7
	pattern := `^ECN match( (!)?ECE)?( (!)?CWR)?( (!)?ECT=([0-3]))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 8 {
		return 0, false
	}
	// ECE
	if len(matches[1]) != 0 {
		mECN.ECE = true
		if len(matches[2]) != 0 {
			mECN.ECEInvert = true
		}
	}
	// CWR
	if len(matches[3]) != 0 {
		mECN.CWR = true
		if len(matches[4]) != 0 {
			mECN.CWRInvert = true
		}
	}
	// ECT
	if len(matches[7]) != 0 {
		ect, err := strconv.Atoi(string(matches[7]))
		if err != nil {
			return 0, false
		}
		mECN.ECT = ect
		if len(matches[6]) != 0 {
			mECN.ECTInvert = true
		}
	}
	return len(matches[0]), true
}

// This option takes mostly 2 spis, (min) or (min, max)
// Matches SPI
func NewMatchESP(yes bool, spi ...int) (*MatchESP, error) {
	match := &MatchESP{
		baseMatch: baseMatch{
			matchType: MatchTypeESP,
		},
	}
	switch len(spi) {
	case 1:
		match.SPIMin = spi[0]
		match.SPIMax = -1
	case 2:
		match.SPIMin = spi[0]
		match.SPIMax = spi[1]
	}
	match.invert = !yes
	return match, nil
}

type MatchESP struct {
	baseMatch
	SPIMin int
	SPIMax int
}

func (mESP *MatchESP) Parse(main []byte) (int, bool) {
	// 1. "^esp"
	// 2. " spi((:!?([0-9]+))?(s:!?([0-9]+):([0-9]+))?)?" #1 #2 #3 #4 #5 #6
	// 3. "( Unknown invflags: 0x[0-9A-Za-z]+)?" #7
	pattern := `^esp spi((:(!?[0-9]+))?(s:(!?[0-9]+):([0-9]+))?)?( Unknown invflags: 0x[0-9A-Za-z]+)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 8 {
		return 0, false
	}
	// min == max
	min := matches[3]
	if len(min) != 0 {
		if min[0] == '!' {
			mESP.invert = true
			min = min[1:]
		}
		spiMin, err := strconv.Atoi(string(min))
		if err != nil {
			return 0, false
		}
		mESP.SPIMin, mESP.SPIMax = spiMin, spiMin
		return len(matches[0]), true
	}

	// min < max
	min = matches[5]
	max := matches[6]
	if len(min) != 0 && len(max) != 0 {
		if min[0] == '!' {
			mESP.invert = true
			min = min[1:]
		}
		spiMin, err := strconv.Atoi(string(min))
		if err != nil {
			return 0, false
		}
		spiMax, err := strconv.Atoi(string(max))
		if err != nil {
			return 0, false
		}
		mESP.SPIMin, mESP.SPIMax = spiMin, spiMax
	}
	return len(matches[0]), true
}

// This module matches the EUI-64 part of a stateless autoconfigured IPv6 address.
// It compares the EUI-64 derived from the source MAC address in Ethernet frame
// with the lower 64 bits of the IPv6 source address.
// But "Universal/Local" bit is not compared.
// This module doesn't match other link layer frame,
// and is only valid in the PREROUTING, INPUT and FORWARD chains.
func NewMatchEUI64() (*MatchEUI64, error) {
	return &MatchEUI64{
		baseMatch: baseMatch{
			matchType: MatchTypeEUI64,
		},
	}, nil
}

// IPv6 specific
// Non-numeric unsupport
type MatchEUI64 struct {
	baseMatch
}

func (mEUI64 *MatchEUI64) Parse(main []byte) (int, bool) {
	pattern := "^eui64 *"
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 1 {
		return 0, false
	}
	return len(matches[0]), true
}

type OptionMatchFrag func(*MatchFrag)

// This option takes mostly 2 ids, (min) or (min, max)
// Matches the given Identification or range of it.
func WithMatchFragID(yes bool, id ...int) OptionMatchFrag {
	return func(mFrag *MatchFrag) {
		switch len(id) {
		case 1:
			mFrag.IDMin = id[0]
			mFrag.IDMax = -1
		case 2:
			mFrag.IDMin = id[0]
			mFrag.IDMax = id[1]
		}
		mFrag.IDInvert = !yes
	}
}

// This option cannot be used with kernel version 2.6.10 or later.
// The length of Fragment header is static and this option doesn't make sense.
func WithMatchFragLen(yes bool, length int) OptionMatchFrag {
	return func(mFrag *MatchFrag) {
		mFrag.Length = length
		mFrag.LengthInvert = !yes
	}
}

// Matches if the reserved fields are filled with zero.
func WithMatchFragReserved() OptionMatchFrag {
	return func(mFrag *MatchFrag) {
		mFrag.Reserved = true
	}
}

// Matches on the first fragment.
func WithMatchFragFirst() OptionMatchFrag {
	return func(mFrag *MatchFrag) {
		mFrag.First = true
	}
}

// Matches if this is the last fragment.
func WithMatchFragLast() OptionMatchFrag {
	return func(mFrag *MatchFrag) {
		mFrag.Last = true
	}
}

// Matches if there are more fragments.
func WithMatchFragMore() OptionMatchFrag {
	return func(mFrag *MatchFrag) {
		mFrag.More = true
	}
}

func NewMatchFrag(opts ...OptionMatchFrag) (*MatchFrag, error) {
	match := &MatchFrag{
		baseMatch: baseMatch{
			matchType: MatchTypeFrag,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// IPv6 specific
// Non-numeric unsupport
type MatchFrag struct {
	baseMatch
	IDMin    int
	IDMax    int
	Length   int
	Reserved bool
	First    bool
	Last     bool
	More     bool
	// invert
	IDInvert     bool
	LengthInvert bool
}

func (mFrag *MatchFrag) Parse(main []byte) (int, bool) {
	// 1. "^frag "
	// 2. "id((:!?([0-9]+))?(s:!?([0-9]+):([0-9]+))?)?" #1 #2 #3 #4 #5 #6
	// 3. "( length:(!)?([0-9]+))?" #7 #8 #9
	// 4. "( reserved)?" #10
	// 5. "( first)?" #11
	// 6. "( more)?" #12
	// 7. "( last)?" #13
	// 8. "( Unknown invflags: 0x[0-9A-Za-z]+)?" #14
	pattern := `^frag ` +
		`id((:!?([0-9]+))?(s:!?([0-9]+):([0-9]+))?)?` +
		`( length:(!)?([0-9]+))?` +
		`( reserved)?` +
		`( first)?` +
		`( more)?` +
		`( last)?` +
		`( Unknown invflags: 0x[0-9A-Za-z]+)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 15 {
		return 0, false
	}
	// min == max
	min := matches[3]
	if len(min) != 0 {
		if min[0] == '!' {
			mFrag.invert = true
			min = min[1:]
		}
		idMin, err := strconv.Atoi(string(min))
		if err != nil {
			return 0, false
		}
		mFrag.IDMin, mFrag.IDMax = idMin, idMin
		return len(matches[0]), true
	}

	// min < max
	min = matches[5]
	max := matches[6]
	if len(min) != 0 && len(max) != 0 {
		if min[0] == '!' {
			mFrag.invert = true
			min = min[1:]
		}
		idMin, err := strconv.Atoi(string(min))
		if err != nil {
			return 0, false
		}
		idMax, err := strconv.Atoi(string(max))
		if err != nil {
			return 0, false
		}
		mFrag.IDMin, mFrag.IDMax = idMin, idMax
	}
	// length
	if len(matches[9]) != 0 {
		length, err := strconv.Atoi(string(matches[9]))
		if err != nil {
			return 0, false
		}
		mFrag.Length = length
		if len(matches[8]) != 0 {
			mFrag.LengthInvert = true
		}
	}
	// reserved
	if len(matches[10]) != 0 {
		mFrag.Reserved = true
	}
	// first
	if len(matches[11]) != 0 {
		mFrag.First = true
	}
	// more
	if len(matches[12]) != 0 {
		mFrag.More = true
	}
	// last
	if len(matches[13]) != 0 {
		mFrag.Last = true
	}
	return len(matches[0]), true
}

type OptionMatchHashLimit func(*MatchHashLimit)

// Match if the rate is below or equal to amount/quantum.
func WithMatchHashLimitUpto(rate Rate) OptionMatchHashLimit {
	return func(mHashLimit *MatchHashLimit) {
		mHashLimit.Avg = rate
	}
}

// Match if the rate is above amount/quantum.
func WithMatchHashLimitAbove(rate Rate) OptionMatchHashLimit {
	return func(mHashLimit *MatchHashLimit) {
		mHashLimit.Avg = rate
		mHashLimit.AvgInvert = true
	}
}

// Maximum initial number of packets to match:
// this number gets recharged by one every time the limit specified above is not reached,
// up to this number; the default is 5.
func WithMatchHashLimitBurst(rate Rate) OptionMatchHashLimit {
	return func(mHashLimit *MatchHashLimit) {
		mHashLimit.Burst = rate
	}
}

// A comma-separated list of objects to take into consideration.
func WithMatchHashLimitMode(mode HashLimitMode) OptionMatchHashLimit {
	return func(mHashLimit *MatchHashLimit) {
		mHashLimit.Mode = mode
	}
}

// All source addresses encountered will be grouped according
// to the given prefix length and the so-created subnet will be subject to hashlimit.
func WithMatchHashLimitSrcMask(mask int) OptionMatchHashLimit {
	return func(mHashLimit *MatchHashLimit) {
		mHashLimit.SrcMask = mask
	}
}

// All destination addresses encountered will be grouped according
// to the given prefix length and the so-created subnet will be subject to hashlimit.
func WithMatchHashLimitDstMask(mask int) OptionMatchHashLimit {
	return func(mHashLimit *MatchHashLimit) {
		mHashLimit.DstMask = mask
	}
}

// The name for the /proc/net/ipt_hashlimit/xxx entry
func WithMatchHashLimitName(name string) OptionMatchHashLimit {
	return func(mHashLimit *MatchHashLimit) {
		mHashLimit.Name = name
	}
}

// The number of buckets of the hash table.
func WithMatchHashLimitHashtableSize(size int) OptionMatchHashLimit {
	return func(mHashLimit *MatchHashLimit) {
		mHashLimit.HashtableSize = size
	}
}

// The number of buckets of the hash table.
func WithMatchHashLimitHashtableMax(max int) OptionMatchHashLimit {
	return func(mHashLimit *MatchHashLimit) {
		mHashLimit.HashtableMax = max
	}
}

// After how many milliseconds do hash entries expire
func WithMatchHashLimitHashtableExpire(expire int) OptionMatchHashLimit {
	return func(mHashLimit *MatchHashLimit) {
		mHashLimit.HashtableExpire = expire
	}
}

// How many milliseconds between garbage collection intervals.
func WithMatchHashLimitHashtableGCInterval(interval int) OptionMatchHashLimit {
	return func(mHashLimit *MatchHashLimit) {
		mHashLimit.HashtableGCInterval = interval
	}
}

func WithMatchHashLimitRateMatch() OptionMatchHashLimit {
	return func(mHashLimit *MatchHashLimit) {
		mHashLimit.RateMatch = true
	}
}

func WithMatchHashLimitRateInterval(interval int) OptionMatchHashLimit {
	return func(mHashLimit *MatchHashLimit) {
		mHashLimit.RateInterval = interval
	}
}

func NewHashLimit(opts ...OptionMatchHashLimit) (*MatchHashLimit, error) {
	match := &MatchHashLimit{
		baseMatch: baseMatch{
			matchType: MatchTypeHashLimit,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type HashLimitMode uint8

const (
	HashLimitModeSrcIP HashLimitMode = 1 << iota
	HashLimitModeSrcPort
	HashLimitModeDstIP
	HashLimitModeDstPort
)

type MatchHashLimit struct {
	baseMatch
	Avg                 Rate // <= avg
	Burst               Rate
	Mode                HashLimitMode
	SrcMask             int
	DstMask             int
	Name                string
	HashtableSize       int
	HashtableMax        int
	HashtableGCInterval int
	HashtableExpire     int
	RateMatch           bool
	RateInterval        int
	// invert
	AvgInvert bool // > avg
}

func (mHashLimit *MatchHashLimit) Parse(main []byte) (int, bool) {
	// 1. "^limit: (above|up to) " #1
	// 2. "([0-9]+)/?(sec|min|hour|day|b/s|kb/s|mb/s)( burst ([0-9]+))?" #2 #3 #4 #5
	// 3. "( mode ((srcip|srcport|dstip|dstport|-)+))?" #6 #7 #8
	// 4. "( htable-size ([0-9]+))?" #9 #10
	// 5. "( htable-max ([0-9]+))?" #11 #12
	// 6. "( htable-gcinterval ([0-9]+))?" #13 #14
	// 7. "( htable-expire ([0-9]+))?" #15 #16
	// 8. "( srcmask ([0-9]+))?" #17 #18
	// 9. "( dstmask ([0-9]+))?" #19 #20
	// 10. "( rate-match)?" #21
	// 11. "( rate-interval ([0-9]+))?" #22 #23
	pattern := `^limit: (above|up to) ` +
		`([0-9]+)/?(sec|min|hour|day|b/s|kb/s|mb/s)( burst ([0-9]+))?` +
		`( mode ((srcip|srcport|dstip|dstport|-)+))?` +
		`( htable-size ([0-9]+))?` +
		`( htable-max ([0-9]+))?` +
		`( htable-gcinterval ([0-9]+))?` +
		`( htable-expire ([0-9]+))?` +
		`( srcmask ([0-9]+))?` +
		`( dstmask ([0-9]+))?` +
		`( rate-match)?` +
		`( rate-interval ([0-9]+))?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 24 {
		return 0, false
	}
	if string(matches[1]) == "above" {
		mHashLimit.AvgInvert = true
	}
	avg, err := strconv.Atoi(string(matches[2]))
	if err != nil {
		return 0, false
	}
	unit := Unit(0)
	switch string(matches[3]) {
	case "sec":
		unit = Second
	case "min":
		unit = Minute
	case "hour":
		unit = Hour
	case "day":
		unit = Day
	case "bs":
		unit = BPS
	case "kb/s":
		unit = KBPS
	case "mb/s":
		unit = MBPS
	}
	mHashLimit.Avg = Rate{avg, unit}
	if len(matches[5]) != 0 {
		burst, err := strconv.Atoi(string(matches[5]))
		if err != nil {
			return 0, false
		}
		mHashLimit.Burst = Rate{burst, unit}
	}
	if len(matches[7]) != 0 {
		modes := strings.Split(string(matches[7]), "-")
		for _, mode := range modes {
			switch mode {
			case "srcip":
				mHashLimit.Mode |= HashLimitModeSrcIP
			case "srcport":
				mHashLimit.Mode |= HashLimitModeSrcPort
			case "dstip":
				mHashLimit.Mode |= HashLimitModeDstIP
			case "dstport":
				mHashLimit.Mode |= HashLimitModeDstPort
			}
		}
	}
	if len(matches[10]) != 0 {
		size, err := strconv.Atoi(string(matches[10]))
		if err != nil {
			return 0, false
		}
		mHashLimit.HashtableSize = size
	}
	if len(matches[12]) != 0 {
		max, err := strconv.Atoi(string(matches[12]))
		if err != nil {
			return 0, false
		}
		mHashLimit.HashtableMax = max
	}
	if len(matches[14]) != 0 {
		gcInterval, err := strconv.Atoi(string(matches[14]))
		if err != nil {
			return 0, false
		}
		mHashLimit.HashtableGCInterval = gcInterval
	}
	if len(matches[16]) != 0 {
		expire, err := strconv.Atoi(string(matches[16]))
		if err != nil {
			return 0, false
		}
		mHashLimit.HashtableExpire = expire
	}
	if len(matches[18]) != 0 {
		srcmask, err := strconv.Atoi(string(matches[18]))
		if err != nil {
			return 0, false
		}
		mHashLimit.SrcMask = srcmask
	}
	if len(matches[20]) != 0 {
		dstmask, err := strconv.Atoi(string(matches[20]))
		if err != nil {
			return 0, false
		}
		mHashLimit.DstMask = dstmask
	}
	if len(matches[21]) != 0 {
		mHashLimit.RateMatch = true
	}
	if len(matches[23]) != 0 {
		interval, err := strconv.Atoi(string(matches[23]))
		if err != nil {
			return 0, false
		}
		mHashLimit.RateInterval = interval
	}
	return len(matches[0]), true
}

type OptionMatchHBH func(*MatchHBH)

// Total length of this header in octets.
func WithMatchHBHLength(yes bool, length int) OptionMatchHBH {
	return func(mHBH *MatchHBH) {
		mHBH.Length = length
		mHBH.invert = !yes
	}
}

// Numeric type of option and the length of the option data in octets.
func WithMatchHBHOpts(opts ...IPv6Option) OptionMatchHBH {
	return func(mHBH *MatchHBH) {
		mHBH.Options = opts
	}
}

func NewMatchHBH(opts ...OptionMatchHBH) (*MatchHBH, error) {
	match := &MatchHBH{
		baseMatch: baseMatch{
			matchType: MatchTypeHBH,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// IPv6 specific
// Non-numeric unsupport
type MatchHBH struct {
	baseMatch
	Length  int
	Options []IPv6Option
}

func (mHBH *MatchHBH) Parse(main []byte) (int, bool) {
	// 1. "^hbh"
	// 2. "( length:(!)?([0-9]+))?" #1 #2 #3
	// 3. "( opts (([0-9]+(:[0-9]+)?[, ])*))?" #4 #5 #6 #7
	// 4. "( Unknown invflags: 0x[0-9A-Za-z]+)?" #8
	pattern := `^hbh` +
		`( length:(!)?([0-9]+))?` +
		`( opts ((,?[0-9]+(:[0-9]+)?)*))?` +
		`( Unknown invflags: 0x[0-9A-Za-z]+)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 9 {
		return 0, false
	}
	if len(matches[3]) != 0 {
		length, err := strconv.Atoi(string(matches[3]))
		if err != nil {
			return 0, false
		}
		mHBH.Length = length
		if len(matches[2]) != 0 {
			mHBH.invert = true
		}
	}
	mHBH.Options = []IPv6Option{}
	if len(matches[5]) != 0 {
		elems := strings.Split(string(matches[5]), ",")
		for _, elem := range elems {
			opt := IPv6Option{}
			typelength := strings.Split(string(elem), ":")
			if len(typelength) >= 1 {
				typ, err := strconv.Atoi(typelength[0])
				if err != nil {
					return 0, false
				}
				opt.Type = typ
			}
			if len(typelength) >= 2 {
				length, err := strconv.Atoi(typelength[1])
				if err != nil {
					return 0, false
				}
				opt.Length = length
			}
			mHBH.Options = append(mHBH.Options, opt)
		}
	}
	return len(matches[0]), true
}

// Matches packets related to the specified conntrack-helper.
func NewMatchHelper(name string) (*MatchHelper, error) {
	mHelper := &MatchHelper{
		baseMatch: baseMatch{
			matchType: MatchTypeHelper,
		},
		Name: name,
	}
	return mHelper, nil
}

type MatchHelper struct {
	baseMatch
	Name string
}

func (mHelper *MatchHelper) Parse(main []byte) (int, bool) {
	pattern := `^helper match (!)?"([A-Za-z0-9()+-._]+)"`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	// invert
	if len(matches[1]) != 0 {
		mHelper.invert = true
	}
	if len(matches[2]) != 0 {
		mHelper.Name = string(matches[2])
	}
	return len(matches[0]), true
}

// This module matches the Hop Limit field in the IPv6 header.
func NewMatchHL(operator Operator, value int) (*MatchHL, error) {
	mHL := &MatchHL{
		baseMatch: baseMatch{
			matchType: MatchTypeHL,
		},
		Operator: operator,
		Value:    value,
	}
	return mHL, nil
}

type MatchHL struct {
	baseMatch
	Operator Operator
	Value    int
}

func (mHL *MatchHL) Parse(main []byte) (int, bool) {
	pattern := `^HL match HL (==|!=|<|>) ([0-9]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	switch string(matches[1]) {
	case "==":
		mHL.Operator = OperatorEQ
	case "!=":
		mHL.Operator = OperatorNE
	case "<":
		mHL.Operator = OperatorLT
	case ">":
		mHL.Operator = OperatorGT
	default:
		return 0, false
	}
	value, err := strconv.Atoi(string(matches[2]))
	if err != nil {
		return 0, false
	}
	mHL.Value = value
	return len(matches[0]), true
}

type OptionMatchICMP func(*MatchICMP)

func WithMatchICMPCode(code ICMPCode) OptionMatchICMP {
	return func(mICMP *MatchICMP) {
		mICMP.CodeMin = code
	}
}

func NewMatchICMP(yes bool, typ ICMPType, opts ...OptionMatchICMP) (*MatchICMP, error) {
	match := &MatchICMP{
		Type: typ,
		baseMatch: baseMatch{
			matchType: MatchTypeICMP,
			invert:    !yes,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// IPv6 specific
// Non-numeric support
type MatchICMP struct {
	baseMatch
	Type    ICMPType
	CodeMin ICMPCode
	CodeMax ICMPCode
}

func (mICMP *MatchICMP) Parse(main []byte) (int, bool) {
	// 1. "^(ipv6-icmp|icmp)" #1
	// 3. "(( !)?type ([0-9]+))?" #2 #3 #4
	// 4. "(( code ([0-9]+))|( codes ([0-9]+)-([0-9]+)))?" #5 #6 #7 #8 #9 #10
	// 2. "( (!)?([0-9A-Za-z.-_]+))?" #11 #12 #13
	// 5. "( Unknown invflags: 0x[0-9]+)?" #14
	pattern := `^(ipv6-icmp|icmp)` +
		`(( !)?type ([0-9]+))?` +
		`(( code ([0-9]+))|( codes ([0-9]+)-([0-9]+)))?` +
		`( (!)?([0-9A-Za-z-_.]+))?` +
		`( Unknown invflags: 0x[0-9]+)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 15 {
		return 0, false
	}
	switch string(matches[1]) {
	case "ipv6-icmp":
		mICMP.ipType = IPv6
	case "icmp":
		mICMP.ipType = IPv4
	}
	if len(matches[4]) != 0 {
		typ, err := strconv.Atoi(string(matches[4]))
		if err != nil {
			return 0, false
		}
		mICMP.Type = ICMPType(typ)
		if len(matches[3]) != 0 {
			mICMP.invert = true
		}
	}
	if len(matches[7]) != 0 {
		code, err := strconv.Atoi(string(matches[7]))
		if err != nil {
			return 0, false
		}
		mICMP.CodeMin = ICMPCode(code)
	}
	if len(matches[9]) != 0 {
		codeMin, err := strconv.Atoi(string(matches[9]))
		if err != nil {
			return 0, false
		}
		codeMax, err := strconv.Atoi(string(matches[10]))
		if err != nil {
			return 0, false
		}
		mICMP.CodeMin = ICMPCode(codeMin)
		mICMP.CodeMax = ICMPCode(codeMax)
	}
	if len(matches[13]) != 0 {
		str := string(matches[13])
		switch mICMP.ipType {
		case IPv4:
			typ, ok := ICMP4Types[str]
			if !ok {
				code, ok := ICMP4Codes[str]
				if !ok {
					return 0, false
				} else {
					mICMP.CodeMin = ICMPCode(code.Code)
					mICMP.Type = ICMPType(code.Type)
				}
			} else {
				mICMP.Type = ICMPType(typ)
			}
		case IPv6:
			typ, ok := ICMP6Types[str]
			if !ok {
				code, ok := ICMP6Codes[str]
				if !ok {
					return 0, false
				} else {
					mICMP.CodeMin = ICMPCode(code.Code)
					mICMP.Type = ICMPType(code.Type)
				}
			} else {
				mICMP.Type = ICMPType(typ)
			}
		}
	}
	return len(matches[0]), true
}

type OptionMatchIPRange func(*MatchIPRange)

// This option takes mostly 2 ips, (min) or (min, max)
// Match source IP in the specified range.
func WithMatchIPRangeSrc(yes bool, ip ...net.IP) OptionMatchIPRange {
	return func(mIPRange *MatchIPRange) {
		switch len(ip) {
		case 1:
			mIPRange.SrcIPMin = ip[0]
		case 2:
			mIPRange.SrcIPMin = ip[0]
			mIPRange.SrcIPMax = ip[1]
		}
		mIPRange.SrcIPInvert = !yes
	}
}

// This option takes mostly 2 ips, (min) or (min, max)
// Match destination IP in the specified range.
func WithMatchIPRangeDst(yes bool, ip ...net.IP) OptionMatchIPRange {
	return func(mIPRange *MatchIPRange) {
		switch len(ip) {
		case 1:
			mIPRange.DstIPMin = ip[0]
		case 2:
			mIPRange.DstIPMin = ip[0]
			mIPRange.DstIPMax = ip[1]
		}
		mIPRange.DstIPInvert = !yes
	}
}

func NewMatchIPRange(opts ...OptionMatchIPRange) (*MatchIPRange, error) {
	match := &MatchIPRange{
		baseMatch: baseMatch{
			matchType: MatchTypeIPRange,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchIPRange struct {
	baseMatch
	SrcIPMin    net.IP
	SrcIPMax    net.IP
	DstIPMin    net.IP
	DstIPMax    net.IP
	SrcIPInvert bool
	DstIPInvert bool
}

func (mIPRange *MatchIPRange) Parse(main []byte) (int, bool) {
	// 1. "^ source|destination IP range (([0-9]{1,3}\.){3}[0-9]{1,3})?-(([0-9]{1,3}\.){3}[0-9]{1,3})?"
	pattern := `^(source|destination) IP range ` +
		`( !)?` +
		`(([0-9]{1,3}\.){3}[0-9]{1,3})-(([0-9]{1,3}\.){3}[0-9]{1,3}) *`
	reg := regexp.MustCompile(pattern)
	index := 0
	for len(main) > 0 {
		matches := reg.FindSubmatch(main)
		if len(matches) != 7 {
			goto END
		}
		invert := false
		if len(matches[2]) != 0 {
			invert = true
		}
		switch string(matches[1]) {
		case "source":
			if len(matches[3]) != 0 {
				min := net.ParseIP(string(matches[3]))
				if min == nil {
					goto END
				}
				mIPRange.SrcIPMin = min
			}
			if len(matches[5]) != 0 {
				max := net.ParseIP(string(matches[5]))
				if max == nil {
					goto END
				}
				mIPRange.SrcIPMax = max
			}
			mIPRange.SrcIPInvert = invert
		case "destination":
			if len(matches[3]) != 0 {
				min := net.ParseIP(string(matches[3]))
				if min == nil {
					goto END
				}
				mIPRange.DstIPMin = min
			}
			if len(matches[5]) != 0 {
				max := net.ParseIP(string(matches[5]))
				if max == nil {
					goto END
				}
				mIPRange.DstIPMax = max
			}
			mIPRange.DstIPInvert = invert
		default:
			goto END
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

type OptionMatchIPv6Header func(*MatchIPv6Header)

// Matches the packet which EXACTLY includes all specified headers.
func WithMatchIPv6Header(headers ...IPHeaderType) OptionMatchIPv6Header {
	return func(mIPv6Header *MatchIPv6Header) {
		mIPv6Header.IPHeaderTypes = headers
	}
}

// Matches if the packet includes any of the headers specified with WithMatchIPv6Header
func WithMatchIPv6HeaderSoft() OptionMatchIPv6Header {
	return func(mIPv6Header *MatchIPv6Header) {
		mIPv6Header.Soft = true
	}
}

func NewMatchIPv6Header(opts ...OptionMatchIPv6Header) (*MatchIPv6Header, error) {
	match := &MatchIPv6Header{
		baseMatch: baseMatch{
			matchType: MatchTypeIPv6Header,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// IPv6 specific
// Non-numeric support
type MatchIPv6Header struct {
	baseMatch
	Soft          bool
	IPHeaderTypes []IPHeaderType
}

func (mIPv6 *MatchIPv6Header) Parse(main []byte) (int, bool) {
	// 1. "^ipv6header"
	// 2. "(flag:(!)?(0x([0-9]+)|([0-9A-Za-z-,]+)))?" #1 #2 #3 #4 #5
	// 3. "( soft)?" #6
	pattern := `^ipv6header` +
		`( flags:(!)?(0x([0-9]+)|([0-9A-Za-z-,]+)))?` +
		`( soft)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 7 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		mIPv6.invert = true
	}
	mIPv6.IPHeaderTypes = []IPHeaderType{}
	// 0x02X
	if len(matches[4]) != 0 {
		hex, err := strconv.ParseUint(string(matches[4]), 16, 8)
		if err != nil {
			return 0, false
		}
		hex8 := uint8(hex)
		for hex8 != 0 {
			for _, mask := range IPHeaderTypeMasks {
				v, _ := IPHeaderTypeMaskMap[mask]
				if hex8&uint8(mask) != 0 {
					mIPv6.IPHeaderTypes = append(mIPv6.IPHeaderTypes, v)
					hex8 &= ^uint8(mask)
					break
				}
			}
		}
	}
	if len(matches[5]) != 0 {
		elems := strings.Split(string(matches[5]), ",")
		for _, elem := range elems {
			typ, ok := IPHeaderTypes[elem]
			if !ok {
				return 0, false
			}
			mIPv6.IPHeaderTypes = append(mIPv6.IPHeaderTypes, typ)
		}
	}
	if len(matches[6]) != 0 {
		mIPv6.Soft = true
	}
	return len(matches[0]), true
}

type IPVSMethod int

const (
	GATE = 1 << iota
	IPIP
	MASQ
	UNKNOWN
)

const (
	IPVSGATE    = "GATE"
	IPVSIPIP    = "IPIP"
	IPVSMASQ    = "MASQ"
	IPVSUNKNOWN = "UNKNOWN"
)

const (
	IPVSIPVS     = "ipvs"
	IPVSVProto   = "vproto"
	IPVSVAddr    = "vaddr"
	IPVSVPort    = "vport"
	IPVSVDir     = "vdir"
	IPVSVMethod  = "vmethod"
	IPVSVPortCtl = "vportctl"
)

type OptionMatchIPVS func(*MatchIPVS)

// Packet belongs to an IPVS connection.
func WithMatchIPVS(yes bool) OptionMatchIPVS {
	return func(mIPVS *MatchIPVS) {
		mIPVS.IPVS = yes
	}
}

// VIP protocol to match.
func WithMatchVProto(yes bool, proto Protocol) OptionMatchIPVS {
	return func(mIPVS *MatchIPVS) {
		mIPVS.VProto = proto
		mIPVS.VProtoInvert = !yes
	}
}

// VIP address to match.
func WithMatchVAddr(yes bool, addr *Address) OptionMatchIPVS {
	return func(mIPVS *MatchIPVS) {
		mIPVS.VAddr = addr
		mIPVS.VAddrInvert = !yes
	}
}

//  VIP port to match.
func WithMatchVPort(yes bool, port int) OptionMatchIPVS {
	return func(mIPVS *MatchIPVS) {
		mIPVS.VPort = port
		mIPVS.VPortInvert = !yes
	}
}

// Flow direction of packet
func WithMatchVDir(dir ConnTrackDir) OptionMatchIPVS {
	return func(mIPVS *MatchIPVS) {
		mIPVS.VDir = dir
	}
}

// IPVS forwarding method used.
func WithMatchVMethod(yes bool, method IPVSMethod) OptionMatchIPVS {
	return func(mIPVS *MatchIPVS) {
		mIPVS.VMethod = method
		mIPVS.VMethodInvert = !yes
	}
}

// VIP port of the controlling connection to match.
func WithMatchVPortCtl(yes bool, portCtl int) OptionMatchIPVS {
	return func(mIPVS *MatchIPVS) {
		mIPVS.VPortCtl = portCtl
		mIPVS.VPortCtlInvert = !yes
	}
}

func NewMatchIPVS(opts ...OptionMatchIPVS) (*MatchIPVS, error) {
	match := &MatchIPVS{
		baseMatch: baseMatch{
			matchType: MatchTypeIPVS,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchIPVS struct {
	baseMatch
	IPVS     bool
	VProto   Protocol
	VAddr    *Address
	VPort    int
	VDir     ConnTrackDir
	VMethod  IPVSMethod
	VPortCtl int
	// invert
	IPVSInvert   bool
	VProtoInvert bool
	VAddrInvert  bool
	VPortInvert  bool
	//VDirInvert     bool
	VMethodInvert  bool
	VPortCtlInvert bool
}

func (mIPVS *MatchIPVS) Parse(main []byte) (int, bool) {
	pattern :=
		`^(! )?(ipvs|vproto|vaddr|vport|vdir|vmethod|vportctl)` +
			` *` +
			`((([0-9]{1,3}\.){3}[0-9]{1,3}(\/([1-2][0-9]|3[0-2]|[0-9]))?)|` +
			`([0-9]+)|` +
			`(anywhere)|` +
			`(GATE|IPIP|MASQ)|` +
			`(REPLY|ORIGINAL))? *`
	reg := regexp.MustCompile(pattern)
	index := 0
	for len(main) > 0 {
		matches := reg.FindSubmatch(main)
		if len(matches) != 12 {
			goto END
		}
		if len(matches[2]) == 0 {
			goto END
		}
		invert := false
		if len(matches[1]) != 0 {
			invert = true
		}
		opt := string(matches[2])
		switch opt {
		case IPVSIPVS:
			mIPVS.IPVS = true
			mIPVS.IPVSInvert = invert
		case IPVSVProto:
			proto, err := strconv.Atoi(string(matches[8]))
			if err != nil {
				goto END
			}
			mIPVS.VProto = Protocol(proto)
			mIPVS.VProtoInvert = invert
		case IPVSVAddr:
			vaddr := string(matches[4])
			addr, err := ParseAddress(vaddr)
			if err != nil {
				goto END
			}
			mIPVS.VAddr = addr
		case IPVSVPort:
			port, err := strconv.Atoi(string(matches[8]))
			if err != nil {
				goto END
			}
			mIPVS.VPort = port
			mIPVS.VPortInvert = invert
		case IPVSVDir:
			dir := string(matches[11])
			if dir == CTDirREPLY {
				mIPVS.VDir = REPLY
			} else if dir == CTDirORIGINAL {
				mIPVS.VDir = ORIGINAL
			} else {
				goto END
			}
			//mIPVS.VDirInvert = invert
		case IPVSVMethod:
			method := string(matches[11])
			switch method {
			case IPVSGATE:
				mIPVS.VMethod = GATE
			case IPVSIPIP:
				mIPVS.VMethod = IPIP
			case IPVSMASQ:
				mIPVS.VMethod = MASQ
			default:
				goto END
			}
			mIPVS.VMethodInvert = invert
		case IPVSVPortCtl:
			port, err := strconv.Atoi(string(matches[8]))
			if err != nil {
				goto END
			}
			mIPVS.VPortCtl = port
			mIPVS.VPortCtlInvert = invert
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

// This option takes mostly 2 length, (min) or (min, max)
func NewMatchLength(yes bool, length ...int) (*MatchLength, error) {
	match := &MatchLength{
		baseMatch: baseMatch{
			matchType: MatchTypeLength,
		},
	}
	switch len(length) {
	case 1:
		match.LengthMin = length[0]
		match.LengthMax = -1
	case 2:
		match.LengthMin = length[0]
		match.LengthMax = length[1]
	}
	match.invert = !yes
	return match, nil
}

type MatchLength struct {
	baseMatch
	LengthMin int
	LengthMax int
}

func (mLength *MatchLength) Parse(main []byte) (int, bool) {
	pattern := `length (!)?([0-9]+)(:([0-9]+))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mLength.invert = true
	}
	// min
	if len(matches[2]) != 0 {
		min, err := strconv.Atoi(string(matches[2]))
		if err != nil {
			return 0, false
		}
		mLength.LengthMin = min
	}
	// max
	if len(matches[4]) != 0 {
		max, err := strconv.Atoi(string(matches[4]))
		if err != nil {
			return 0, false
		}
		mLength.LengthMax = max
	}
	return len(matches[0]), true
}

type OptionMatchLimit func(*MatchLimit)

// Maximum average matching rate.
func WithMatchLimit(rate Rate) OptionMatchLimit {
	return func(mLimit *MatchLimit) {
		mLimit.Avg = rate
	}
}

// Maximum initial number of packets to match.
func WithMatchLimitBurst(burst Rate) OptionMatchLimit {
	return func(mLimit *MatchLimit) {
		mLimit.Burst = burst
	}
}

func NewMatchLimit(opts ...OptionMatchLimit) (*MatchLimit, error) {
	match := &MatchLimit{
		baseMatch: baseMatch{
			matchType: MatchTypeLimit,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchLimit struct {
	baseMatch
	Avg   Rate
	Burst Rate
}

func (mLimit *MatchLimit) Parse(main []byte) (int, bool) {
	pattern := `^limit: avg (([0-9]+)/(second|minute|hour|day)) burst ([0-9]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	// avg
	avg, err := strconv.Atoi(string(matches[2]))
	if err != nil {
		return 0, false
	}
	// burst
	burst, err := strconv.Atoi(string(matches[4]))
	if err != nil {
		return 0, false
	}
	unit := Unit(0)
	switch string(matches[3]) {
	case "second":
		unit = Second
	case "minute":
		unit = Minute
	case "hour":
		unit = Hour
	case "day":
		unit = Day
	default:
		return 0, false
	}
	mLimit.Avg = Rate{
		avg, unit,
	}
	mLimit.Burst = Rate{
		burst, unit,
	}
	return len(matches[0]), true
}

// Match source MAC address.
func NewMatchMAC(yes bool, mac net.HardwareAddr) (*MatchMAC, error) {
	match := &MatchMAC{
		baseMatch: baseMatch{
			matchType: MatchTypeMAC,
			invert:    !yes,
		},
		SrcMac: mac,
	}
	return match, nil
}

type MatchMAC struct {
	baseMatch
	SrcMac net.HardwareAddr
}

func (mMAC *MatchMAC) Parse(main []byte) (int, bool) {
	pattern := `^MAC( !)?([0-9A-Za-z:]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mMAC.invert = true
	}
	mac, err := net.ParseMAC(string(matches[2]))
	if err != nil {
		return 0, false
	}
	mMAC.SrcMac = mac
	return len(matches[0]), true
}

// Takes mostly 2 value, (mark) or (mark/mask)
// Matches packets with the given unsigned mark value
func NewMatchMark(yes bool, value ...int) (*MatchMark, error) {
	mMark := &MatchMark{
		baseMatch: baseMatch{
			matchType: MatchTypeMark,
		},
	}
	switch len(value) {
	case 1:
		mMark.Value = value[0]
		mMark.Mask = -1
	case 2:
		mMark.Value = value[0]
		mMark.Mask = value[1]
	}
	mMark.invert = !yes
	return mMark, nil
}

type MatchMark struct {
	baseMatch
	Value int
	Mask  int
}

func (mMark *MatchMark) Parse(main []byte) (int, bool) {
	// 1. "^MARK|mark match"
	// 2. "( !)?" #1
	// 3. " 0x([0-9A-Za-z]+)(/0x([0-9A-Za-z]+))?" #2 #3 #4
	pattern := `^MARK|mark match( !)? 0x([0-9A-Za-z]+)(/0x([0-9A-Za-z]+))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mMark.invert = true
	}
	if len(matches[2]) != 0 {
		value, err := strconv.ParseInt(string(matches[2]), 16, 64)
		if err != nil {
			// TODO string format mask support
			mMark.Value = -2
		} else {
			mMark.Value = int(value)
		}
	}
	if len(matches[4]) != 0 {
		mask, err := strconv.ParseInt(string(matches[4]), 16, 64)
		if err != nil {
			// TODO string format mask support
			mMark.Mask = -2
		} else {
			mMark.Mask = int(mask)
		}
	}
	return len(matches[0]), true
}

type MHType uint8

const (
	BindingRefreshRequest  MHType = 0
	BRR                    MHType = 0
	HomeTestInit           MHType = 1
	HOTI                   MHType = 1
	CareofTestInit         MHType = 2
	COTI                   MHType = 2
	HomeTest               MHType = 3
	HOT                    MHType = 3
	CareofTest             MHType = 4
	COT                    MHType = 4
	BindingUpdate          MHType = 5
	BU                     MHType = 5
	BindingAcknowledgement MHType = 6
	BA                     MHType = 6
	BindingError           MHType = 7
	BE                     MHType = 7
)

var (
	MHTypes = map[string]MHType{
		"binding-refresh-request": BindingRefreshRequest,
		"brr":                     BindingRefreshRequest,
		"home-test-init":          HomeTestInit,
		"hoti":                    HomeTestInit,
		"careof-test-init":        CareofTestInit,
		"coti":                    CareofTestInit,
		"home-test":               HomeTest,
		"hot":                     HomeTest,
		"careof-test":             CareofTest,
		"cot":                     CareofTest,
		"binding-update":          BindingUpdate,
		"bu":                      BindingUpdate,
		"binding-acknowledgement": BindingAcknowledgement,
		"ba":                      BindingAcknowledgement,
		"binding-error":           BindingError,
		"be":                      BindingError,
	}
)

// This option takes mostly 2 types, (min) or (min, max)
func NewMatchMH(yes bool, types ...MHType) (*MatchMH, error) {
	match := &MatchMH{
		baseMatch: baseMatch{
			matchType: MatchTypeMH,
			invert:    !yes,
		},
	}
	switch len(types) {
	case 1:
		match.TypeMin = types[0]
	case 2:
		match.TypeMin = types[0]
		match.TypeMax = types[1]
	}
	return match, nil
}

// IPv6 specific
// Non-numeric support
type MatchMH struct {
	baseMatch
	TypeMin MHType
	TypeMax MHType
}

func (mMH *MatchMH) Parse(main []byte) (int, bool) {
	// 1. "^mh"
	// 2. "( (!)?(([0-9]+)|([0-9A-Za-z-]+))(:(([0-9]+)|([0-9A-Za-z-]+)))?)?" #1 #2 #3 #4 #5 #6 #7 #8 #9
	// 3. "( Unknown invflags: 0x[0-9]+)?" #10
	pattern := `^mh` +
		`( (!)?(([0-9]+)|([0-9A-Za-z-]+))(:(([0-9]+)|([0-9A-Za-z-]+)))?)?` +
		`( Unknown invflags: 0x[0-9]+)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 11 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		mMH.invert = true
	}
	if len(matches[4]) != 0 {
		min, err := strconv.Atoi(string(matches[4]))
		if err != nil {
			return 0, false
		}
		mMH.TypeMin = MHType(min)
	}
	if len(matches[5]) != 0 {
		typ, ok := MHTypes[string(matches[5])]
		if !ok {
			return 0, false
		}
		mMH.TypeMin = typ
	}
	if len(matches[8]) != 0 {
		max, err := strconv.Atoi(string(matches[8]))
		if err != nil {
			return 0, false
		}
		mMH.TypeMax = MHType(max)
	}
	if len(matches[9]) != 0 {
		typ, ok := MHTypes[string(matches[9])]
		if !ok {
			return 0, false
		}
		mMH.TypeMax = typ
	}
	return len(matches[0]), true
}

type OptionMatchMultiPort func(*MatchMultiPort)

// Match if the source port is one of the given ports.
func WithMatchMultiPortSrc(yes bool, ports ...PortRange) OptionMatchMultiPort {
	return func(mMultiPort *MatchMultiPort) {
		mMultiPort.SrcPorts = ports
		mMultiPort.invert = !yes
	}
}

//  Match if the destination port is one of the given ports.
func WithMatchMultiPortDst(yes bool, ports ...PortRange) OptionMatchMultiPort {
	return func(mMultiPort *MatchMultiPort) {
		mMultiPort.DstPorts = ports
		mMultiPort.invert = !yes
	}
}

// Match if either the source or destination ports are equal to one of the given ports.
func WithMatchMultiPort(yes bool, ports ...PortRange) OptionMatchMultiPort {
	return func(mMultiPort *MatchMultiPort) {
		mMultiPort.Ports = ports
		mMultiPort.invert = !yes
	}
}

func NewMatchMultiPort(opts ...OptionMatchMultiPort) (*MatchMultiPort, error) {
	match := &MatchMultiPort{
		baseMatch: baseMatch{
			matchType: MatchTypeMultiPort,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchMultiPort struct {
	baseMatch
	SrcPorts []PortRange
	DstPorts []PortRange
	Ports    []PortRange
}

func (mMultiPort *MatchMultiPort) Parse(main []byte) (int, bool) {
	// 1. "^multiport "
	// 2. "(sports|dports|ports|ERROR)" #1
	// 3. "( !)?" #2
	// 4. "([0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*)" #3 ...
	pattern := `^multiport (sports|dports|ports|ERROR) ( !)?([0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 7 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		mMultiPort.invert = true
	}
	ports := []PortRange{}
	ranges := strings.Split(string(matches[3]), ",")
	for _, rge := range ranges {
		pair := strings.Split(rge, ":")
		switch len(pair) {
		case 1:
			start, err := strconv.Atoi(pair[0])
			if err != nil {
				return 0, false
			}
			portRange := PortRange{
				Start: start,
				End:   -1,
			}
			ports = append(ports, portRange)
		case 2:
			start, err := strconv.Atoi(pair[0])
			if err != nil {
				return 0, false
			}
			end, err := strconv.Atoi(pair[1])
			if err != nil {
				return 0, false
			}
			portRange := PortRange{
				Start: start,
				End:   end,
			}
			ports = append(ports, portRange)
		default:
			return 0, false
		}
	}
	switch string(matches[1]) {
	case "sports":
		mMultiPort.SrcPorts = ports
	case "dports":
		mMultiPort.DstPorts = ports
	case "ports":
		mMultiPort.Ports = ports
	case "ERROR":
		return 0, false
	}
	return len(matches[0]), true
}

func NewMatchNFAcct(name string) (*MatchNFAcct, error) {
	match := &MatchNFAcct{
		baseMatch: baseMatch{
			matchType: MatchTypeNFAcct,
		},
		AccountingName: name,
	}
	return match, nil
}

type MatchNFAcct struct {
	baseMatch
	AccountingName string
}

func (mNFAcct *MatchNFAcct) Parse(main []byte) (int, bool) {
	// 1. "^nfacct-name "
	// 2. " ([0-9A-Za-z-_]+)"
	pattern := `^nfacct-name  ([0-9A-Za-z-_]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 2 {
		return 0, false
	}
	mNFAcct.AccountingName = string(matches[1])
	return len(matches[0]), true
}

type OptionMatchOSF func(*MatchOSF)

// Match an operating system genre by using a passive fingerprinting.
func WithMatchOSFGenre(yes bool, genre string) OptionMatchOSF {
	return func(mOSF *MatchOSF) {
		mOSF.Genre = genre
		mOSF.invert = !yes
	}
}

// Do additional TTL checks on the packet to determine the operating system.
func WithMatchOSFTTL(level int) OptionMatchOSF {
	return func(mOSF *MatchOSF) {
		mOSF.TTLLevel = level
	}
}

// Log determined genres into dmesg even if they do not match the desired one.
func WithMatchOSFLog(log int) OptionMatchOSF {
	return func(mOSF *MatchOSF) {
		mOSF.LogLevel = log
	}
}

func NewMatchOSF(opts ...OptionMatchOSF) (*MatchOSF, error) {
	match := &MatchOSF{
		baseMatch: baseMatch{
			matchType: MatchTypeOSF,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchOSF struct {
	baseMatch
	Genre    string
	TTLLevel int
	LogLevel int
}

func (mOSF *MatchOSF) Parse(main []byte) (int, bool) {
	// 1. "^OS fingerprint match (!)?[A-Za-z]+"
	pattern := `^OS fingerprint match (!)?([A-Za-z-_]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mOSF.invert = true
	}
	mOSF.Genre = string(matches[2])
	return len(matches[0]), true
}

type OptionMatchOwner func(*MatchOwner)

// Matches if the packet socket's file structure (if it has one) is owned by the given user.
func WithMatchOwnerUid(yes bool, uid int) OptionMatchOwner {
	return func(mOwner *MatchOwner) {
		mOwner.UidOwner = uid
		mOwner.UidOwnerInvert = !yes
	}
}

// Matches if the packet socket's file structure (if it has one) is owned by the given user.
func WithMatchOwnerUser(yes bool, name string) OptionMatchOwner {
	return func(mOwner *MatchOwner) {
		mOwner.User = name
		mOwner.UidOwnerInvert = !yes
	}
}

// Matches if the packet socket's file structure is owned by the given group.
func WithMatchOwnerGid(yes bool, gid int) OptionMatchOwner {
	return func(mOwner *MatchOwner) {
		mOwner.GidOwner = gid
		mOwner.GidOwnerInvert = !yes
	}
}

// Matches if the packet socket's file structure is owned by the given group.
func WithMatchOwnerGroup(yes bool, group string) OptionMatchOwner {
	return func(mOwner *MatchOwner) {
		mOwner.Group = group
		mOwner.GidOwnerInvert = !yes
	}
}

// Group to be also checked in the supplementary groups of a process.
func WithMatchOwnerSupplGroups() OptionMatchOwner {
	return func(mOwner *MatchOwner) {
		mOwner.SupplGroups = true
	}
}

// Matches if the packet is associated with a socket.
func WithMatchOwnerSocketExists(yes bool) OptionMatchOwner {
	return func(mOwner *MatchOwner) {
		mOwner.HasSocketExists = true
		mOwner.SocketExistsInvert = !yes
	}
}

func NewMatchOwner(opts ...OptionMatchOwner) (*MatchOwner, error) {
	match := &MatchOwner{
		baseMatch: baseMatch{
			matchType: MatchTypeOwner,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchOwner struct {
	baseMatch
	UidOwner        int
	User            string
	GidOwner        int
	Group           string
	SupplGroups     bool
	HasSocketExists bool
	// invert
	UidOwnerInvert     bool
	GidOwnerInvert     bool
	SocketExistsInvert bool
}

func (mOwner *MatchOwner) Parse(main []byte) (int, bool) {
	// 1. "^(! )?(owner socket exists|owner UID match|owner GID match|incl. suppl. groups)"
	// 2. "( ([0-9A-Za-z]+))?"
	pattern := `^(! )?(owner socket|owner UID match|owner GID match|incl. suppl.)` +
		` +` +
		`(exists|groups|([0-9A-Za-z]+))? *`
	reg := regexp.MustCompile(pattern)
	index := 0
	for len(main) > 0 {
		matches := reg.FindSubmatch(main)
		if len(matches) != 5 {
			goto END
		}
		invert := false
		if len(matches[1]) != 0 {
			invert = true
		}
		switch string(matches[2]) {
		case "owner socket":
			mOwner.HasSocketExists = true
			mOwner.SocketExistsInvert = invert
		case "owner UID match":
			uidRaw := string(matches[4])
			uid, err := strconv.Atoi(uidRaw)
			if err != nil {
				mOwner.User = uidRaw
			} else {
				mOwner.UidOwner = uid
			}
			mOwner.UidOwnerInvert = invert
		case "owner GID match":
			gidRaw := string(matches[4])
			gid, err := strconv.Atoi(gidRaw)
			if err != nil {
				mOwner.Group = gidRaw
			} else {
				mOwner.GidOwner = gid
			}
			mOwner.GidOwnerInvert = invert
		case "incl. suppl.":
			mOwner.SupplGroups = true
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

type OptionMatchPhysDev func(*MatchPhysDev)

// Name of a bridge port via which a packet is received.
func WithMatchPhysDevIn(yes bool, in string) OptionMatchPhysDev {
	return func(mPhysDev *MatchPhysDev) {
		mPhysDev.PhysdevIn = in
		mPhysDev.PhysdevInInvert = !yes
	}
}

// Name of a bridge port via which a packet is going to be sent.
func WithMatchPhysDevOut(yes bool, out string) OptionMatchPhysDev {
	return func(mPhysDev *MatchPhysDev) {
		mPhysDev.PhysdevOut = out
		mPhysDev.PhysdevOutInvert = !yes
	}
}

// Matches if the packet has entered through a bridge interface.
func WithMatchPhysDevIsIn(yes bool) OptionMatchPhysDev {
	return func(mPhysDev *MatchPhysDev) {
		mPhysDev.PhysdevIsIn = true
		mPhysDev.PhysdevIsInInvert = true
	}
}

// Matches if the packet will leave through a bridge interface.
func WithMatchPhysDevIsOut(yes bool) OptionMatchPhysDev {
	return func(mPhysDev *MatchPhysDev) {
		mPhysDev.PhysdevIsOut = true
		mPhysDev.PhysdevIsOutInvert = true
	}
}

func WithMatchPhysDevIsBridged(yes bool) OptionMatchPhysDev {
	return func(mPhysDev *MatchPhysDev) {
		mPhysDev.PhysdevIsBridged = true
		mPhysDev.PhysdevIsBridgedInvert = true
	}
}

func NewMatchPhysDev(opts ...OptionMatchPhysDev) (*MatchPhysDev, error) {
	match := &MatchPhysDev{
		baseMatch: baseMatch{
			matchType: MatchTypePhysDev,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchPhysDev struct {
	baseMatch
	PhysdevIn        string
	PhysdevOut       string
	PhysdevIsIn      bool
	PhysdevIsOut     bool
	PhysdevIsBridged bool
	// invert
	PhysdevInInvert        bool
	PhysdevOutInvert       bool
	PhysdevIsInInvert      bool
	PhysdevIsOutInvert     bool
	PhysdevIsBridgedInvert bool
}

func (mPhysDev *MatchPhysDev) Parse(main []byte) (int, bool) {
	// 1. "^PHYSDEV match"
	// 2. "(( !)? --physdev-is-in)?" #1 #2
	// 5. "(( !)? --physdev-in ([0-9A-Za-z]+))?" #3 #4 #5
	// 3. "(( !)? --physdev-is-out)?" #6 #7
	// 6. "(( !)? --physdev-out ([0-9A-Za-z]+))?" #8 #9 #10
	// 4. "(( !)? --physdev-is-bridged)?" #11 #12
	pattern := `^PHYSDEV match` +
		`(( !)? --physdev-is-in)?` +
		`(( !)? --physdev-in ([0-9A-Za-z]+))?` +
		`(( !)? --physdev-is-out)?` +
		`(( !)? --physdev-out ([0-9A-Za-z]+))?` +
		`(( !)? --physdev-is-bridged)?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 13 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mPhysDev.PhysdevIsIn = true
		if len(matches[2]) != 0 {
			mPhysDev.PhysdevIsInInvert = true
		}
	}
	if len(matches[5]) != 0 {
		mPhysDev.PhysdevIn = string(matches[5])
		if len(matches[3]) != 0 {
			mPhysDev.PhysdevInInvert = true
		}
	}
	if len(matches[6]) != 0 {
		mPhysDev.PhysdevIsOut = true
		if len(matches[7]) != 0 {
			mPhysDev.PhysdevIsOutInvert = true
		}
	}
	if len(matches[10]) != 0 {
		mPhysDev.PhysdevOut = string(matches[10])
		if len(matches[8]) != 0 {
			mPhysDev.PhysdevOutInvert = true
		}
	}
	if len(matches[11]) != 0 {
		mPhysDev.PhysdevIsBridged = true
		if len(matches[12]) != 0 {
			mPhysDev.PhysdevIsBridgedInvert = true
		}
	}
	return len(matches[0]), true
}

type PktType int

const (
	Unicast PktType = 1 << iota
	Broadcast
	Multicast
)

const (
	PktTypeUnicast   = "unicast"
	PktTypeBroadcast = "broadcast"
	PktTypeMulticast = "multicast"
)

func NewMatchPktType(yes bool, pktType PktType) (*MatchPktType, error) {
	match := &MatchPktType{
		baseMatch: baseMatch{
			matchType: MatchTypePktType,
			invert:    !yes,
		},
		PktType: pktType,
	}
	return match, nil
}

type MatchPktType struct {
	baseMatch
	PktType PktType
}

func (mPktType *MatchPktType) Parse(main []byte) (int, bool) {
	// 1. "^PKTTYPE (!)?=([0-9A-Za-z]+)"
	pattern := `^PKTTYPE (!)?= ([0-9A-Za-z]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mPktType.invert = true
	}
	switch string(matches[2]) {
	case PktTypeUnicast:
		mPktType.PktType = Unicast
	case PktTypeBroadcast:
		mPktType.PktType = Broadcast
	case PktTypeMulticast:
		mPktType.PktType = Multicast
	default:
		return 0, false
	}
	return len(matches[0]), true
}

const (
	AH     = "ah"
	ESP    = "esp"
	IPComp = "ipcomp"
)

type PolicyMode int

const (
	_ PolicyMode = iota
	Tunnel
	Transport
	Unknown
)

type PolicyPol int

const (
	_ PolicyPol = iota
	None
	IPSec
)

type MatchPolicyElement struct {
	ReqID     int
	SPI       int
	Proto     Protocol
	Mode      PolicyMode
	TunnelSrc *Address
	TunnelDst *Address
	// invert
	ReqIDInvert     bool
	SPIInvert       bool
	ProtoInvert     bool
	ModeInvert      bool
	TunnelSrcInvert bool
	TunnelDstInvert bool
}

type OptionMatchPolicy func(*MatchPolicy)

//  Used to select whether to match the policy used for decapsulation or
// the policy that will be used for encapsulation.
func WithMatchPolicyDir(dir Dir) OptionMatchPolicy {
	return func(mPolicy *MatchPolicy) {
		mPolicy.Dir = dir
	}
}

// Matches if the packet is subject to IPsec processing.
func WithMatchPolicy(pol PolicyPol) OptionMatchPolicy {
	return func(mPolicy *MatchPolicy) {
		mPolicy.Pol = pol
	}
}

// Selects whether to match the exact policy or match
// if any rule of the policy matches the given policy.
func WithMatchPolicyStrict() OptionMatchPolicy {
	return func(mPolicy *MatchPolicy) {
		mPolicy.Strict = true
	}
}

func WithMatchPolicyElements(elems ...*MatchPolicyElement) OptionMatchPolicy {
	return func(mPolicy *MatchPolicy) {
		mPolicy.Elements = elems
	}
}

func NewMatchPolicy(opts ...OptionMatchPolicy) (*MatchPolicy, error) {
	match := &MatchPolicy{
		baseMatch: baseMatch{
			matchType: MatchTypePolicy,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchPolicy struct {
	baseMatch
	Dir      Dir
	Pol      PolicyPol
	Strict   bool
	Elements []*MatchPolicyElement
}

func (mPolicy *MatchPolicy) Parse(main []byte) (int, bool) {
	// 1. "^policy match"
	// 2. " (dir in|dir out)" #1
	// 3. " (pol none|pol ipsec)" #2
	// 4. "( strict)?" #3
	pattern := `^policy match` +
		` (dir in|dir out)` +
		` (pol none|pol ipsec)` +
		`( strict)? *`

	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 4 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mPolicy.Dir = In
		if matches[1][4] == 'o' {
			mPolicy.Dir = Out
		}
	}
	if len(matches[2]) != 0 {
		mPolicy.Pol = None
		if matches[2][4] == 'i' {
			mPolicy.Pol = IPSec
		}
	}
	if len(matches[3]) != 0 {
		mPolicy.Strict = true
	}
	mPolicy.Elements = []*MatchPolicyElement{}
	index := len(matches[0])
	main = main[index:]
	// elements
	// 1. "^(\[[0-9]+\])?" #1
	// 2. "(( !)? reqid ([0-9]+))?" #2 #3 #4
	// 3. "(( !)? spi 0x([0-9A-Za-z]+))?" #5 #6 #7
	// 4. "(( !)? proto ([0-9A-Za-z]+))?" #8 #9 #10
	// 5. "(( !)? mode (transport|tunnel|\?\?\?))?" #11 #12 #13
	// 6. "(( !)? tunnel-dst ([0-9A-Za-z:./]+))?" #14 #15 #16
	// 7. "(( !)? tunnel-src ([0-9A-Za-z:./]+))?" #17 #18 #19
	pattern = `^(\[[0-9]+\])?` +
		`(( !)? reqid ([0-9]+))?` +
		`(( !)? spi 0x([0-9A-Za-z]+))?` +
		`(( !)? proto ([0-9A-Za-z]+))?` +
		`(( !)? mode (transport|tunnel|\?\?\?))?` +
		`(( !)? tunnel-dst ([0-9A-Za-z:./]+))?` +
		`(( !)? tunnel-src ([0-9A-Za-z:./]+))? *`
	reg = regexp.MustCompile(pattern)
	for len(main) > 0 {
		matched := false
		matches = reg.FindSubmatch(main)
		if len(matches) != 20 {
			goto END
		}
		elem := &MatchPolicyElement{}
		if len(matches[4]) != 0 {
			reqID, err := strconv.Atoi(string(matches[4]))
			if err != nil {
				goto END
			}
			elem.ReqID = reqID
			if len(matches[3]) != 0 {
				elem.ReqIDInvert = true
			}
			matched = true
		}
		if len(matches[7]) != 0 {
			spi, err := strconv.Atoi(string(matches[7]))
			if err != nil {
				goto END
			}
			elem.SPI = spi
			if len(matches[6]) != 0 {
				elem.SPIInvert = true
			}
			matched = true
		}
		if len(matches[10]) != 0 {
			protocol := string(matches[10])
			switch protocol {
			case AH:
				elem.Proto = ProtocolAH
			case ESP:
				elem.Proto = ProtocolESP
			case IPComp:
				elem.Proto = ProtocolIPComp
			default:
				proto, err := strconv.Atoi(protocol)
				if err != nil {
					goto END
				}
				elem.Proto = Protocol(proto)
			}
			if len(matches[9]) != 0 {
				elem.ProtoInvert = true
			}
			matched = true
		}
		if len(matches[13]) != 0 {
			mode := string(matches[13])
			switch mode {
			case "transport":
				elem.Mode = Transport
			case "tunnel":
				elem.Mode = Tunnel
			case "???":
				elem.Mode = Unknown
			}
			if len(matches[12]) != 0 {
				elem.ModeInvert = true
			}
			matched = true
		}
		if len(matches[16]) != 0 {
			addr, err := ParseAddress(string(matches[16]))
			if err != nil {
				goto END
			}
			elem.TunnelDst = addr
			if len(matches[15]) != 0 {
				elem.TunnelDstInvert = true
			}
			matched = true
		}
		if len(matches[19]) != 0 {
			addr, err := ParseAddress(string(matches[19]))
			if err != nil {
				goto END
			}
			elem.TunnelSrc = addr
			if len(matches[18]) != 0 {
				elem.TunnelSrcInvert = true
			}
			matched = true
		}
		if !matched {
			break
		}
		mPolicy.Elements = append(mPolicy.Elements, elem)
		index += len(matches[0])
		main = main[len(matches[0]):]
	}
END:
	if index != 0 {
		return index, true
	}
	return 0, false
}

func NewMatchQuota(yes bool, quota uint64) (*MatchQuota, error) {
	match := &MatchQuota{
		baseMatch: baseMatch{
			matchType: MatchTypeQuota,
			invert:    !yes,
		},
		Quota: quota,
	}
	return match, nil
}

type MatchQuota struct {
	baseMatch
	Quota uint64
}

func (mQuota *MatchQuota) Parse(main []byte) (int, bool) {
	// 1. "^quota: ([0-9]+) bytes"
	pattern := `^quota: ([0-9]+) bytes *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 2 {
		return 0, false
	}
	quota, err := strconv.ParseUint(string(matches[1]), 10, 64)
	if err != nil {
		return 0, false
	}
	mQuota.Quota = quota
	return len(matches[0]), true
}

type OptionMatchRateEst func(*MatchRateEst)

// For each estimator (either absolute or relative mode),
// calculate the difference between the estimator-determined flow rate
// and the static value chosen with the BPS/PPS options.
func WithMatchRateEstDelta() OptionMatchRateEst {
	return func(mRateEst *MatchRateEst) {
		mRateEst.RateestDelta = true
	}
}

// LT, GT or EQ
func WithMatchRateEstOperator(yes bool, operator Operator) OptionMatchRateEst {
	return func(mRateEst *MatchRateEst) {
		mRateEst.Operator = operator
		mRateEst.invert = !yes
	}
}

// Name of the one rate estimator for absolute mode.
func WithMatchRateEstName(name string) OptionMatchRateEst {
	return func(mRateEst *MatchRateEst) {
		mRateEst.Name = name
	}
}

// The names of the two rate estimators for relative mode.
func WithMatchRateEst1(name string) OptionMatchRateEst {
	return func(mRateEst *MatchRateEst) {
		mRateEst.Rateest1 = name
	}
}

// The names of the two rate estimators for relative mode.
func WithMatchRateEst2(name string) OptionMatchRateEst {
	return func(mRateEst *MatchRateEst) {
		mRateEst.Rateest2 = name
	}
}

func WithMatchRateBPS1(value int) OptionMatchRateEst {
	return func(mRateEst *MatchRateEst) {
		mRateEst.RateestBPS1 = value
	}
}

func WithMatchRateBPS2(value int) OptionMatchRateEst {
	return func(mRateEst *MatchRateEst) {
		mRateEst.RateestBPS2 = value
	}
}

func WithMatchRatePPS1(value int) OptionMatchRateEst {
	return func(mRateEst *MatchRateEst) {
		mRateEst.RateestPPS1 = value
	}
}

func WithMatchRatePPS2(value int) OptionMatchRateEst {
	return func(mRateEst *MatchRateEst) {
		mRateEst.RateestPPS2 = value
	}
}

func NewMatchRateEst(opts ...OptionMatchRateEst) (*MatchRateEst, error) {
	match := &MatchRateEst{
		baseMatch: baseMatch{
			matchType: MatchTypeRateEst,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchRateEst struct {
	baseMatch
	RateestDelta bool
	Operator     Operator
	Name         string
	Rateest1     string
	Rateest2     string
	Relative     bool
	RateestBPS1  int // in bytes
	RateestPPS1  int
	RateestBPS2  int // in bytes
	RateestPPS2  int
	//RateestLT    bool
	//RateestGT    bool
	//RateestEQ    bool
}

func (mRateEst *MatchRateEst) Parse(main []byte) (int, bool) {
	// 1. "^rateest match "
	// 2. "([0-9A-Za-z+-._]+)" #1
	// 3. "( delta)?" #2
	// 4. "( bps( ([0-9MKbit]+))?( ([0-9MKbit]+))?(( !)? (eq|lt|gt))?)?" #3 #4 #5 #6 #7 #8 #9 #10
	// 5. "( pps( ([0-9]+))?(( !)? (eq|lt|gt) ([0-9]+))?)?" #11 #12 #13 #14 #15 #16 #17
	// 6. "(( !)? (eq|lt|gt))?" #18 #19 #20
	// 7. "( ([0-9A-Za-z+-._]+))?" #21 #22
	// 8. "( bps( ([0-9MKbit]+)))?" #23 #24 #25
	// 9. "( pps( ([0-9]+)))?" #26 #27 #28
	pattern := `^rateest match ` +
		`([0-9A-Za-z+-._]+)` +
		`( delta)?` +
		`( bps( ([0-9MKbit]+))?( ([0-9MKbit]+))?(( !)? (eq|lt|gt))?)?` +
		`( pps( ([0-9]+))?(( !)? (eq|lt|gt) ([0-9]+))?)?` +
		`(( !)? (eq|lt|gt))?` +
		`( ([0-9A-Za-z+-._]+))?` +
		`( bps( ([0-9MKbit]+)))?` +
		`( pps( ([0-9]+)))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 29 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mRateEst.Rateest1 = string(matches[1])
	}
	if len(matches[2]) != 0 {
		mRateEst.RateestDelta = true
	}
	if len(matches[5]) != 0 {
		bps, err := bitsToBytes(string(matches[5]))
		if err != nil {
			return 0, false
		}
		mRateEst.RateestBPS1 = bps
	}
	if len(matches[7]) != 0 {
		bps, err := bitsToBytes(string(matches[7]))
		if err != nil {
			return 0, false
		}
		mRateEst.RateestBPS2 = bps
	}
	if len(matches[9]) != 0 || len(matches[15]) != 0 || len(matches[19]) != 0 {
		mRateEst.invert = true
	}
	if len(matches[10]) != 0 {
		switch string(matches[10]) {
		case "lt":
			mRateEst.Operator = OperatorLT
			//mRateEst.RateestLT = true
		case "eq":
			mRateEst.Operator = OperatorEQ
			//mRateEst.RateestEQ = true
		case "gt":
			mRateEst.Operator = OperatorGT
			//mRateEst.RateestGT = true
		}
	}
	if len(matches[13]) != 0 {
		pps, err := strconv.Atoi(string(matches[13]))
		if err != nil {
			return 0, false
		}
		mRateEst.RateestPPS1 = pps
	}
	if len(matches[17]) != 0 {
		pps, err := strconv.Atoi(string(matches[17]))
		if err != nil {
			return 0, false
		}
		mRateEst.RateestPPS2 = pps
	}
	if len(matches[20]) != 0 {
		switch string(matches[20]) {
		case "lt":
			mRateEst.Operator = OperatorLT
			//mRateEst.RateestLT = true
		case "eq":
			mRateEst.Operator = OperatorEQ
			//mRateEst.RateestEQ = true
		case "gt":
			mRateEst.Operator = OperatorGT
			//mRateEst.RateestGT = true
		}
	}
	if len(matches[22]) != 0 {
		mRateEst.Rateest2 = string(matches[22])
		mRateEst.Relative = true
	}
	if len(matches[25]) != 0 {
		bps, err := bitsToBytes(string(matches[25]))
		if err != nil {
			return 0, false
		}
		mRateEst.RateestBPS2 = bps
	}
	if len(matches[28]) != 0 {
		pps, err := strconv.Atoi(string(matches[28]))
		if err != nil {
			return 0, false
		}
		mRateEst.RateestPPS2 = pps
	}
	return len(matches[0]), true
}

// turn Mbits/Kbits/bits string to bytes
func bitsToBytes(bits string) (int, error) {
	length := len(bits)
	if length < 4 {
		return 0, errors.New("too short")
	}
	if strings.Compare(bits[length-4:], "Mbit") == 0 {
		bps, err := strconv.Atoi(bits[:length-4])
		if err != nil {
			return 0, err
		}
		return bps * 1000000 / 8, nil
	} else if strings.Compare(bits[length-4:], "Kbit") == 0 {
		bps, err := strconv.Atoi(bits[:length-4])
		if err != nil {
			return 0, err
		}
		return bps * 1000 / 8, nil
	} else if strings.Compare(bits[length-3:], "bit") == 0 {
		bps, err := strconv.Atoi(bits[:length-3])
		if err != nil {
			return 0, err
		}
		return bps / 8, nil
	} else {
		return 0, errors.New("unsupported")
	}
}

// Takes mostly 2 value, (value) or (value/mask)
// Matches packets with the given unsigned mark value
func NewMatchRealm(yes bool, value ...int) (*MatchRealm, error) {
	mRealm := &MatchRealm{
		baseMatch: baseMatch{
			matchType: MatchTypeRealm,
		},
	}
	switch len(value) {
	case 1:
		mRealm.Value = value[0]
		mRealm.Mask = -1
	case 2:
		mRealm.Value = value[0]
		mRealm.Mask = value[1]
	}
	mRealm.invert = !yes
	return mRealm, nil
}

// IPv4 specific
// Non-numeric support
// see http://linux-ip.net/gl/ip-cref/ip-cref-node172.html
type MatchRealm struct {
	baseMatch
	Value int
	Mask  int
}

func (mRealm *MatchRealm) Parse(main []byte) (int, bool) {
	// 1. "( !)?realm" #1
	// 2. " 0x([0-9A-Za-z]+)(/0x([0-9A-Za-z]+))?" #2 #3 #4
	pattern := `( !)?realm` +
		` ([0-9A-Za-z]+)(/([0-9A-Za-z]+))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mRealm.invert = true
	}
	if len(matches[2]) != 0 {
		str := strings.TrimPrefix(string(matches[2]), "0x")
		value, err := strconv.ParseInt(str, 16, 64)
		if err != nil {
			// TODO string format mask support
			mRealm.Value = -2
		} else {
			mRealm.Value = int(value)
		}
	}
	if len(matches[4]) != 0 {
		str := strings.TrimPrefix(string(matches[4]), "0x")
		mask, err := strconv.ParseInt(str, 16, 64)
		if err != nil {
			// TODO string format mask support
			mRealm.Mask = -2
		} else {
			mRealm.Mask = int(mask)
		}
	}
	return len(matches[0]), true
}

type OptionMatchRecent func(*MatchRecent)

// Specify the list to use for the commands.
func WithMatchRecentName(name string) OptionMatchRecent {
	return func(mRecent *MatchRecent) {
		mRecent.Name = name
	}
}

// This will add the source address of the packet to the list.
// If the source address is already in the list, this will update the existing entry.
func WithMatchRecentSet(yes bool) OptionMatchRecent {
	return func(mRecent *MatchRecent) {
		mRecent.Set = true
		mRecent.invert = !yes
	}
}

// Check if the source address of the packet is currently in the list.
func WithMatchRecentCheck(yes bool) OptionMatchRecent {
	return func(mRecent *MatchRecent) {
		mRecent.RCheck = true
		mRecent.invert = !yes
	}
}

// Like WithMatchRecentCheck, except it will update the "last seen" timestamp if it matches.
func WithMatchRecentUpdate(yes bool) OptionMatchRecent {
	return func(mRecent *MatchRecent) {
		mRecent.Update = true
		mRecent.invert = !yes
	}
}

// Check if the source address of the packet is currently in the list and
// if so that address will be removed from the list and the rule will return true.
// If the address is not found, false is returned.
func WithMatchRecentRemove(yes bool) OptionMatchRecent {
	return func(mRecent *MatchRecent) {
		mRecent.Remove = true
		mRecent.invert = !yes
	}
}

// Match/save the source address of each packet in the recent list table.
// This is the default.
func WithMatchRecentRSource() OptionMatchRecent {
	return func(mRecent *MatchRecent) {
		mRecent.RSource = true
	}
}

// Match/save the destination address of each packet in the recent list table.
func WithMatchRecentRDestination() OptionMatchRecent {
	return func(mRecent *MatchRecent) {
		mRecent.RDest = true
	}
}

// This option must be used in conjunction with one of Check or Update.
// When used, this will narrow the match to only happen when the address is
// in the list and was seen within the last given number of seconds.
func WithMatchRecentSeconds(seconds int) OptionMatchRecent {
	return func(mRecent *MatchRecent) {
		mRecent.Seconds = seconds
	}
}

// This option can only be used in conjunction with Seconds.
// When used, this will cause entries older than the last given number of seconds to be purged.
func WithMatchRecentReap() OptionMatchRecent {
	return func(mRecent *MatchRecent) {
		mRecent.Reap = true
	}
}

// see iptables-extensions
func WithMatchRTTL() OptionMatchRecent {
	return func(mRecent *MatchRecent) {
		mRecent.RTTL = true
	}
}

// see iptables-extensions
func WithMatchRecentHitCount(hitCount int) OptionMatchRecent {
	return func(mRecent *MatchRecent) {
		mRecent.HitCount = hitCount
	}
}

func WithMatchRecentMask(mask net.IPMask) OptionMatchRecent {
	return func(mRecent *MatchRecent) {
		mRecent.Mask = mask
	}
}

func NewMatchRecent(opts ...OptionMatchRecent) (*MatchRecent, error) {
	match := &MatchRecent{
		baseMatch: baseMatch{
			matchType: MatchTypeRecent,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchRecent struct {
	baseMatch
	Name   string
	Set    bool
	RCheck bool
	Update bool
	Remove bool

	RSource  bool
	RDest    bool
	Seconds  int
	Reap     bool
	HitCount int
	RTTL     bool
	Mask     net.IPMask
}

func (mRecent *MatchRecent) Parse(main []byte) (int, bool) {
	// 1. "^(! )?recent:" #1
	// 2. "( SET)?" #2
	// 3. "( CHECK)?" #3
	// 4. "( UPDATE)?" #4
	// 5. "( REMOVE)?" #5
	// 6. "( seconds: ([0-9]+))?" #6 #7
	// 7. "( reap)?" #8
	// 8. "( hit_count: ([0-9]+))?" #9 #10
	// 9. "( TTL-Match)?" #11
	// 10. " name: ([0-9A-Za-z+-._]+)" #12
	// 11. "( side: source)?" #13
	// 12. "( side: dest)?" #14
	// 13. "( mask: ([0-9A-Za-z.:]+))?" #15 #16
	pattern := `^(! )?recent:` +
		`( SET)?` +
		`( CHECK)?` +
		`( UPDATE)?` +
		`( REMOVE)?` +
		`( seconds: ([0-9]+))?` +
		`( reap)?` +
		`( hit_count: ([0-9]+))?` +
		`( TTL-Match)?` +
		` name: ([0-9A-Za-z+-._]+)` +
		`( side: source)?` +
		`( side: dest)?` +
		`( mask: ([0-9A-Za-z.:]+))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 17 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mRecent.invert = true
	}
	if len(matches[2]) != 0 {
		mRecent.Set = true
	}
	if len(matches[3]) != 0 {
		mRecent.RCheck = true
	}
	if len(matches[4]) != 0 {
		mRecent.Update = true
	}
	if len(matches[5]) != 0 {
		mRecent.Remove = true
	}
	if len(matches[7]) != 0 {
		seconds, err := strconv.Atoi(string(matches[7]))
		if err != nil {
			return 0, false
		}
		mRecent.Seconds = seconds
	}
	if len(matches[8]) != 0 {
		mRecent.Reap = true
	}
	if len(matches[10]) != 0 {
		hitCount, err := strconv.Atoi(string(matches[10]))
		if err != nil {
			return 0, false
		}
		mRecent.HitCount = hitCount
	}
	mRecent.Name = string(matches[12])
	if len(matches[13]) != 0 {
		mRecent.RSource = true
	}
	if len(matches[14]) != 0 {
		mRecent.RDest = true
	}
	if len(matches[16]) != 0 {
		ip := net.ParseIP(string(matches[16]))
		if ip == nil {
			return 0, false
		}
		mRecent.Mask = net.IPMask(ip)
	}
	return len(matches[0]), true
}

type OptionMatchRPFilter func(*MatchRPFilter)

// Used to specify that the reverse path filter test should match
// even if the selected output device is not the expected one.
func WithMatchRPFilterLoose() OptionMatchRPFilter {
	return func(mRPFilter *MatchRPFilter) {
		mRPFilter.Loose = true
	}
}

// Also use the packets' nfmark value when performing the reverse path route lookup.
func WithMatchRPFilterValidMark() OptionMatchRPFilter {
	return func(mRPFilter *MatchRPFilter) {
		mRPFilter.ValidMark = true
	}
}

//  This will permit packets arriving from the network with a source address
// that is also assigned to the local machine.
func WithMatchRPFilterAcceptLocal() OptionMatchRPFilter {
	return func(mRPFilter *MatchRPFilter) {
		mRPFilter.AcceptLocal = true
	}
}

// This will invert the sense of the match.
// Instead of matching packets that passed the reverse path filter test,
// match those that have failed it.
func WithMatchRPFilterInvert() OptionMatchRPFilter {
	return func(mRPFilter *MatchRPFilter) {
		mRPFilter.Invert = true
	}
}

func NewMatchRPFilter(opts ...OptionMatchRPFilter) (*MatchRPFilter, error) {
	match := &MatchRPFilter{
		baseMatch: baseMatch{
			matchType: MatchTypeRPFilter,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchRPFilter struct {
	baseMatch
	Loose       bool
	ValidMark   bool
	AcceptLocal bool
	Invert      bool
}

func (mRPFilter *MatchRPFilter) Parse(main []byte) (int, bool) {
	pattern := `^rpfilter( loose)?( validmark)?( accept-local)?( invert)?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mRPFilter.Loose = true
	}
	if len(matches[2]) != 0 {
		mRPFilter.ValidMark = true
	}
	if len(matches[3]) != 0 {
		mRPFilter.AcceptLocal = true
	}
	if len(matches[4]) != 0 {
		mRPFilter.Invert = true
	}
	return len(matches[0]), true
}

type OptionMatchRT func(*MatchRT)

// Match the type.
func WithMatchRTType(yes bool, typ int) OptionMatchRT {
	return func(mRT *MatchRT) {
		mRT.Type = typ
		mRT.TypeInvert = !yes
	}
}

// Takes mostly 2 value, (min) or (min, max)
// Match the `segments left' field (range).
func WithMatchRTSegsLeft(yes bool, segsleft ...int) OptionMatchRT {
	return func(mRT *MatchRT) {
		switch len(segsleft) {
		case 1:
			mRT.SegsLeftMin = segsleft[0]
			mRT.SegsLeftMax = -1
		case 2:
			mRT.SegsLeftMin = segsleft[0]
			mRT.SegsLeftMax = segsleft[1]
		}
		mRT.SegsLeftInvert = !yes
	}
}

// Match the length of this header.
func WithMatchRTLength(yes bool, length int) OptionMatchRT {
	return func(mRT *MatchRT) {
		mRT.Length = length
		mRT.LengthInvert = !yes
	}
}

// Match the reserved field when type == 0.
func WithMatchRTReserved() OptionMatchRT {
	return func(mRT *MatchRT) {
		mRT.Reserved = true
	}
}

// Match addresses when type == 0.
func WithMatchRTAddresses(addrs ...*Address) OptionMatchRT {
	return func(mRT *MatchRT) {
		mRT.Addrs = addrs
	}
}

// List of addresses is not a strict list when type == 0.
func WithMatchRTNoStrict() OptionMatchRT {
	return func(mRT *MatchRT) {
		mRT.NotStrict = true
	}
}

func NewMatchRT(opts ...OptionMatchRT) (*MatchRT, error) {
	match := &MatchRT{
		baseMatch: baseMatch{
			matchType: MatchTypeRT,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// IPv6 specific
// Non-numeric unsupport
type MatchRT struct {
	baseMatch
	Type        int
	SegsLeftMin int
	SegsLeftMax int
	Length      int
	Reserved    bool       // type == 0
	Addrs       []*Address // type == 0
	NotStrict   bool       // type == 0
	// invert
	TypeInvert     bool
	SegsLeftInvert bool
	LengthInvert   bool
}

func (mRT *MatchRT) Parse(main []byte) (int, bool) {
	// 1. "^rt"
	// 2. "( type:(!)?([0-9]+))?" #1 #2 #3
	// 3. "( segsleft:(!)?([0-9]+))?" #4 #5 #6
	// 4. "( segslefts:(!)?([0-9]+):([0-9]+))?" #7 #8 #9 #10
	// 5. "( length:(!)?([0-9]+))?" #11 #12 #13
	// 6. "( reserved)?" #14
	// 7. "( 0-addrs)?" #15
	// 8. "( ([0-9A-Za-z:,]+))?" #16 #17
	// 9. "( rt-0-not-strict)?" #18
	pattern := `^rt` +
		`( type:(!)?([0-9]+))?` +
		`( segsleft:(!)?([0-9]+))?` +
		`( segslefts:(!)?([0-9]+):([0-9]+))?` +
		`( length:(!)?([0-9]+))?` +
		`( reserved)?` +
		`( 0-addrs)?` +
		`( ([0-9A-Za-z:,]+))?` +
		`( rt-0-not-strict)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 19 {
		return 0, false
	}
	mRT.Addrs = []*Address{}
	if len(matches[3]) != 0 {
		typ, err := strconv.Atoi(string(matches[3]))
		if err != nil {
			return 0, false
		}
		mRT.Type = typ
		if len(matches[2]) != 0 {
			mRT.TypeInvert = true
		}
	}
	if len(matches[6]) != 0 {
		segsleft, err := strconv.Atoi(string(matches[6]))
		if err != nil {
			return 0, false
		}
		mRT.SegsLeftMin = segsleft
		if len(matches[5]) != 0 {
			mRT.SegsLeftInvert = true
		}
	}
	if len(matches[9]) != 0 {
		min, err := strconv.Atoi(string(matches[9]))
		if err != nil {
			return 0, false
		}
		max, err := strconv.Atoi(string(matches[10]))
		if err != nil {
			return 0, false
		}
		mRT.SegsLeftMin = min
		mRT.SegsLeftMax = max
		if len(matches[8]) != 0 {
			mRT.SegsLeftInvert = true
		}
	}
	if len(matches[13]) != 0 {
		length, err := strconv.Atoi(string(matches[13]))
		if err != nil {
			return 0, false
		}
		mRT.Length = length
		if len(matches[12]) != 0 {
			mRT.LengthInvert = true
		}
	}
	if len(matches[14]) != 0 {
		mRT.Reserved = true
	}
	if len(matches[17]) != 0 {
		elems := strings.Split(string(matches[17]), ",")
		for _, elem := range elems {
			addr, err := ParseAddress(elem)
			if err != nil {
				return 0, false
			}
			mRT.Addrs = append(mRT.Addrs, addr)
		}
	}
	if len(matches[18]) != 0 {
		mRT.NotStrict = true
	}
	return len(matches[0]), true
}

type SCTPType int

const (
	SCTPTypeDATA             SCTPType = 0
	SCTPTypeINIT             SCTPType = 1
	SCTPTypeINITACK          SCTPType = 2
	SCTPTypeSACK             SCTPType = 3
	SCTPTypeHEARTBEAT        SCTPType = 4
	SCTPTypeHEARTBEATACK     SCTPType = 5
	SCTPTypeABORT            SCTPType = 6
	SCTPTypeSHUTDOWN         SCTPType = 7
	SCTPTypeSHUTDOWNACK      SCTPType = 8
	SCTPTypeERROR            SCTPType = 9
	SCTPTypeCOOKIEECHO       SCTPType = 10
	SCTPTypeCOOKIEACK        SCTPType = 11
	SCTPTypeECNECNE          SCTPType = 12
	SCTPTypeECNCWR           SCTPType = 13
	SCTPTypeSHUTDOWNCOMPLETE SCTPType = 14
	SCTPTypeASCONF           SCTPType = 193
	SCTPTypeASCONFACK        SCTPType = 128
	SCTPTypeFORWARDTSN       SCTPType = 192
)

var (
	SCTPTypes = map[string]SCTPType{
		"DATA":             SCTPTypeDATA,
		"INIT":             SCTPTypeINIT,
		"INITACK":          SCTPTypeINITACK,
		"HEARTBEAT":        SCTPTypeHEARTBEAT,
		"HEARTBEATACK":     SCTPTypeHEARTBEATACK,
		"ABORT":            SCTPTypeABORT,
		"SHUTDOWN":         SCTPTypeSHUTDOWN,
		"SHUTDOWNACK":      SCTPTypeSHUTDOWNACK,
		"ERROR":            SCTPTypeERROR,
		"COOKIEECHO":       SCTPTypeCOOKIEECHO,
		"COOKIEACK":        SCTPTypeCOOKIEACK,
		"ECNECNE":          SCTPTypeECNECNE,
		"ECNCWR":           SCTPTypeECNCWR,
		"SHUTDOWNCOMPLETE": SCTPTypeSHUTDOWNCOMPLETE,
		"ASCONF":           SCTPTypeASCONF,
		"ASCONFACK":        SCTPTypeASCONFACK,
		"FORWARDTSN":       SCTPTypeFORWARDTSN,
	}
)

type ChuckFlag int

const (
	CF_I ChuckFlag = 1 << iota
	CF_U
	CF_B
	CF_E
	CF_i
	CF_u
	CF_b
	CF_e
	CF_T
	CF_t
)

type Chunk struct {
	Type      SCTPType
	ChuckFlag ChuckFlag
}

type OptionMatchSCTP func(*MatchSCTP)

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchSCTPSrcPort(yes bool, port ...int) OptionMatchSCTP {
	return func(mSCTP *MatchSCTP) {
		switch len(port) {
		case 1:
			mSCTP.SrcPortMin = port[0]
			mSCTP.SrcPortMax = -1
		case 2:
			mSCTP.SrcPortMin = port[0]
			mSCTP.SrcPortMax = port[1]
		}
		mSCTP.SrcPortInvert = !yes
	}
}

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchSCTPDstPort(yes bool, port ...int) OptionMatchSCTP {
	return func(mSCTP *MatchSCTP) {
		switch len(port) {
		case 1:
			mSCTP.DstPortMin = port[0]
			mSCTP.DstPortMax = -1
		case 2:
			mSCTP.DstPortMin = port[0]
			mSCTP.DstPortMax = port[1]
		}
		mSCTP.DstPortInvert = !yes
	}
}

func WithMatchSCTPChunk(rg MatchRange, chunks ...Chunk) OptionMatchSCTP {
	return func(mSCTP *MatchSCTP) {
		mSCTP.Range = rg
		mSCTP.Chunks = chunks
	}
}

func NewMatchSCTP(opts ...OptionMatchSCTP) (*MatchSCTP, error) {
	match := &MatchSCTP{
		baseMatch: baseMatch{
			matchType: MatchTypeSCTP,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchSCTP struct {
	baseMatch
	SrcPortMin int
	SrcPortMax int
	DstPortMin int
	DstPortMax int
	Chunks     []Chunk
	Range      MatchRange
	// invert
	SrcPortInvert bool
	DstPortInvert bool
}

func (mSCTP *MatchSCTP) Parse(main []byte) (int, bool) {
	// 1. "^sctp"
	// 2. "( spt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?" #1 #2 #3 #4 #5 #6 #7 #8
	// 3. "( dpt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?" #9 #10 #11 #12 #13 #14 #15 #16
	// 4. "(( !)? (any|all|only)( NONE| ALL| ([0-9A-Za-z:,]+))?)?" #17 #18 #19 #20 #21
	pattern := `^sctp` +
		`( spt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?` +
		`( dpt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?` +
		`(( !)? (any|all|only)( NONE| ALL| ([0-9A-Za-z:,]+))?)?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 22 {
		return 0, false
	}
	if len(matches[4]) != 0 {
		spt, err := strconv.Atoi(string(matches[4]))
		if err != nil {
			return 0, false
		}
		mSCTP.SrcPortMin = spt
		if len(matches[3]) != 0 {
			mSCTP.SrcPortInvert = true
		}
	}
	if len(matches[7]) != 0 {
		min, err := strconv.Atoi(string(matches[7]))
		if err != nil {
			return 0, false
		}
		max, err := strconv.Atoi(string(matches[8]))
		if err != nil {
			return 0, false
		}
		if len(matches[6]) != 0 {
			mSCTP.SrcPortInvert = true
		}
		mSCTP.SrcPortMin = min
		mSCTP.SrcPortMax = max
	}
	if len(matches[12]) != 0 {
		dpt, err := strconv.Atoi(string(matches[12]))
		if err != nil {
			return 0, false
		}
		mSCTP.DstPortMin = dpt
		if len(matches[11]) != 0 {
			mSCTP.DstPortInvert = true
		}
	}
	if len(matches[15]) != 0 {
		min, err := strconv.Atoi(string(matches[15]))
		if err != nil {
			return 0, false
		}
		max, err := strconv.Atoi(string(matches[16]))
		if err != nil {
			return 0, false
		}
		if len(matches[14]) != 0 {
			mSCTP.DstPortInvert = true
		}
		mSCTP.DstPortMin = min
		mSCTP.DstPortMax = max
	}
	if len(matches[19]) != 0 {
		switch string(matches[19]) {
		case "any":
			mSCTP.Range = ANY
		case "all":
			mSCTP.Range = ALL
		case "only":
			mSCTP.Range = ONLY
		}
	}
	mSCTP.Chunks = []Chunk{}
	if len(matches[21]) != 0 {
		elems := strings.Split(string(matches[21]), ",")
		for _, elem := range elems {
			chunk := Chunk{}
			parts := strings.Split(elem, ":")
			if len(parts) >= 1 {
				typ, ok := SCTPTypes[parts[0]]
				if ok {
					chunk.Type = typ
				} else {
					hex := strings.TrimPrefix(parts[0], "0x")
					typ64, err := strconv.ParseInt(hex, 16, 64)
					if err != nil {
						return 0, false
					}
					chunk.Type = SCTPType(typ64)
				}
			}
			if len(parts) >= 2 {
				for _, c := range parts[1] {
					switch c {
					case 'I':
						chunk.ChuckFlag |= CF_I
					case 'U':
						chunk.ChuckFlag |= CF_U
					case 'B':
						chunk.ChuckFlag |= CF_B
					case 'E':
						chunk.ChuckFlag |= CF_E
					case 'i':
						chunk.ChuckFlag |= CF_i
					case 'u':
						chunk.ChuckFlag |= CF_u
					case 'b':
						chunk.ChuckFlag |= CF_b
					case 'e':
						chunk.ChuckFlag |= CF_e
					case 'T':
						chunk.ChuckFlag |= CF_T
					case 't':
						chunk.ChuckFlag |= CF_t
					}
				}
			}
			mSCTP.Chunks = append(mSCTP.Chunks, chunk)
		}
	}
	return len(matches[0]), true
}

type Flag int

const (
	_ = iota
	FlagSrc
	FlagDst
)

type OptionMatchSet func(*MatchSet)

// There can be at least on and no more than six of flags.
func WithMatchSetName(yes bool, name string, flags ...Flag) OptionMatchSet {
	return func(mSet *MatchSet) {
		mSet.SetName = name
		mSet.SetNameInvert = !yes
		mSet.Flags = flags
	}
}

func WithMatchSetReturnNoMatch() OptionMatchSet {
	return func(mSet *MatchSet) {
		mSet.ReturnNoMatch = true
	}
}

// Default the packet and byte counters are updated, use this function to skip.
func WithMatchSetSkipCounterUpdate() OptionMatchSet {
	return func(mSet *MatchSet) {
		mSet.SkipCounterUpdate = true
	}
}

func WithMatchSetSkipSubCounterUpdate() OptionMatchSet {
	return func(mSet *MatchSet) {
		mSet.SkipSubCounterUpdate = true
	}
}

func WithMatchSetPacketsEqual(value int) OptionMatchSet {
	return func(mSet *MatchSet) {
		mSet.PacketsEQ = value
	}
}

func WithMatchSetPacketsNotEqual(value int) OptionMatchSet {
	return func(mSet *MatchSet) {
		mSet.PacketsEQ = value
		mSet.PacketsEQInvert = true
	}
}

func WithMatchSetPacketsLessThan(value int) OptionMatchSet {
	return func(mSet *MatchSet) {
		mSet.PacketsLT = value
	}
}

func WithMatchSetPacketsGreaterThan(value int) OptionMatchSet {
	return func(mSet *MatchSet) {
		mSet.PacketsGT = value
	}
}

func WithMatchSetBytesEqual(value int) OptionMatchSet {
	return func(mSet *MatchSet) {
		mSet.BytesEQ = value
	}
}

func WithMatchSetBytesNotEqual(value int) OptionMatchSet {
	return func(mSet *MatchSet) {
		mSet.BytesEQ = value
		mSet.BytesEQInvert = true
	}
}

func WithMatchSetBytesLessThan(value int) OptionMatchSet {
	return func(mSet *MatchSet) {
		mSet.BytesLT = value
	}
}

func WithMatchSetBytesGreaterThan(value int) OptionMatchSet {
	return func(mSet *MatchSet) {
		mSet.BytesGT = value
	}
}

func NewMatchSet(opts ...OptionMatchSet) (*MatchSet, error) {
	match := &MatchSet{
		baseMatch: baseMatch{
			matchType: MatchTypeSet,
		},
		PacketsEQ: -1,
		PacketsLT: -1,
		PacketsGT: -1,
		BytesEQ:   -1,
		BytesLT:   -1,
		BytesGT:   -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchSet struct {
	baseMatch
	SetName              string
	Flags                []Flag
	ReturnNoMatch        bool
	SkipCounterUpdate    bool
	SkipSubCounterUpdate bool
	PacketsEQ            int
	PacketsLT            int
	PacketsGT            int
	BytesEQ              int
	BytesLT              int
	BytesGT              int
	// invert
	SetNameInvert   bool
	PacketsEQInvert bool
	BytesEQInvert   bool
}

func (mSet *MatchSet) Parse(main []byte) (int, bool) {
	// 1. "^(! )?match-set ([0-9A-Za-z-_.]+)( (src|dst|,))?" #1 #2 #3 #4
	// 2. "( return-nomatch)?"#5
	// 3. "( ! update-counters)?" #6
	// 4. "( ! update-subcounters)?" #7
	// 5. "( packets-eq ([0-9]+))?" #8 #9
	// 6. "( ! packets-eq ([0-9]+))?" #10 #11
	// 7. "( packets-lt ([0-9]+))?" #12 #13
	// 8. "( packets-gt ([0-9]+))?" #14 #15
	// 9. "( bytes-eq ([0-9]+))?" #16 #17
	// 10. "( ! bytes-eq ([0-9]+))?" #18 #19
	// 11. "( bytes-lt ([0-9]+))?" #20 #21
	// 12. "( bytes-gt ([0-9]+))?" #22 #23
	pattern := `^(! )?match-set ([0-9A-Za-z-_.]+)( ([srcdst,]+))?` +
		`( return-nomatch)?` +
		`( ! update-counters)?` +
		`( ! update-subcounters)?` +
		`( packets-eq ([0-9]+))?` +
		`( ! packets-eq ([0-9]+))?` +
		`( packets-lt ([0-9]+))?` +
		`( packets-gt ([0-9]+))?` +
		`( bytes-eq ([0-9]+))?` +
		`( ! bytes-eq ([0-9]+))?` +
		`( bytes-lt ([0-9]+))?` +
		`( bytes-gt ([0-9]+))?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 24 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mSet.SetNameInvert = true
	}
	mSet.SetName = string(matches[2])
	mSet.Flags = []Flag{}
	if len(matches[4]) != 0 {
		flags := strings.Split(string(matches[4]), ",")
		for _, flag := range flags {
			if flag == "src" {
				mSet.Flags = append(mSet.Flags, FlagSrc)
			} else if flag == "dst" {
				mSet.Flags = append(mSet.Flags, FlagDst)
			}
		}
	}
	if len(matches[5]) != 0 {
		mSet.ReturnNoMatch = true
	}
	if len(matches[6]) != 0 {
		mSet.SkipCounterUpdate = true
	}
	if len(matches[7]) != 0 {
		mSet.SkipSubCounterUpdate = true
	}
	if len(matches[9]) != 0 {
		eq, err := strconv.Atoi(string(matches[9]))
		if err != nil {
			return 0, false
		}
		mSet.PacketsEQ = eq
	}
	if len(matches[11]) != 0 {
		eq, err := strconv.Atoi(string(matches[11]))
		if err != nil {
			return 0, false
		}
		mSet.PacketsEQ = eq
		mSet.PacketsEQInvert = true
	}
	if len(matches[13]) != 0 {
		lt, err := strconv.Atoi(string(matches[13]))
		if err != nil {
			return 0, false
		}
		mSet.PacketsLT = lt
	}
	if len(matches[15]) != 0 {
		gt, err := strconv.Atoi(string(matches[15]))
		if err != nil {
			return 0, false
		}
		mSet.PacketsGT = gt
	}
	if len(matches[17]) != 0 {
		eq, err := strconv.Atoi(string(matches[17]))
		if err != nil {
			return 0, false
		}
		mSet.BytesEQ = eq
	}
	if len(matches[19]) != 0 {
		eq, err := strconv.Atoi(string(matches[19]))
		if err != nil {
			return 0, false
		}
		mSet.BytesEQ = eq
		mSet.BytesEQInvert = true
	}
	if len(matches[21]) != 0 {
		lt, err := strconv.Atoi(string(matches[21]))
		if err != nil {
			return 0, false
		}
		mSet.BytesLT = lt
	}
	if len(matches[23]) != 0 {
		gt, err := strconv.Atoi(string(matches[23]))
		if err != nil {
			return 0, false
		}
		mSet.BytesGT = gt
	}
	return len(matches[0]), true
}

type OptionMatchSocket func(*MatchSocket)

// Ignore non-transparent sockets.
func WithMatchSocketTransparent() OptionMatchSocket {
	return func(mSocket *MatchSocket) {
		mSocket.Transparent = true
	}
}

// Do not ignore sockets bound to 'any' address.
// The socket match won't accept zero-bound listeners by default,
// since then local services could intercept traffic that would
// otherwise be forwarded.  This option therefore has security
// implications when used to match traffic being forwarded to
// redirect such packets to local machine with policy routing.
func WithMatchSocketNoWildcard() OptionMatchSocket {
	return func(mSocket *MatchSocket) {
		mSocket.NoWildcard = true
	}
}

func WithMatchSocketRestoreSKMark() OptionMatchSocket {
	return func(mSocket *MatchSocket) {
		mSocket.RestoreSKMark = true
	}
}

func NewMatchSocket(opts ...OptionMatchSocket) (*MatchSocket, error) {
	match := &MatchSocket{
		baseMatch: baseMatch{
			matchType: MatchTypeSocket,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchSocket struct {
	baseMatch
	Transparent   bool
	NoWildcard    bool
	RestoreSKMark bool
}

func (mSocket *MatchSocket) Parse(main []byte) (int, bool) {
	// 1. "^socket"
	// 2. "( --transparent)?"
	// 3. "( --nowildcard)?"
	// 4. "( --restore-skmark)?"
	pattern := `^socket( --transparent)?( --nowildcard)?( --restore-skmark)?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 4 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mSocket.Transparent = true
	}
	if len(matches[2]) != 0 {
		mSocket.NoWildcard = true
	}
	if len(matches[3]) != 0 {
		mSocket.RestoreSKMark = true
	}
	return len(matches[0]), true
}

func NewMatchState(state ConnTrackState) (*MatchState, error) {
	return &MatchState{
		baseMatch: baseMatch{
			matchType: MatchTypeState,
		},
		State: state,
	}, nil
}

type MatchState struct {
	baseMatch
	State ConnTrackState
}

func (mState *MatchState) Parse(main []byte) (int, bool) {
	pattern := `(! )?state ([0-9A-Za-z-_.,]+)?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mState.invert = true
	}
	if len(matches[2]) != 0 {
		states := strings.Split(string(matches[2]), ",")
		for _, state := range states {
			switch state {
			case CTStateINVALID:
				mState.State |= INVALID
			case CTStateNEW:
				mState.State |= NEW
			case CTStateESTABLISHED:
				mState.State |= ESTABLISHED
			case CTStateRELATED:
				mState.State |= RELATED
			case CTStateUNTRACKED:
				mState.State |= UNTRACKED
			default:
				return 0, false
			}
		}
	}
	return len(matches[0]), true
}

type StatisticMode int

const (
	_ StatisticMode = iota
	StatisticModeRandom
	StatisticModeNth
)

type OptionMatchStatistic func(*MatchStatistic)

// Set the matching mode of the matching rule.
func WithMatchStatisticMode(mode StatisticMode) OptionMatchStatistic {
	return func(mStatistic *MatchStatistic) {
		mStatistic.Mode = mode
	}
}

// Set the probability for a packet to be randomly matched.
func WithMatchStatisticProbability(yes bool, probability float64) OptionMatchStatistic {
	return func(mStatistic *MatchStatistic) {
		mStatistic.Probability = probability
		mStatistic.ProbabilityInvert = !yes
	}
}

// Match one packet every nth packet.
func WithMatchStatisticEvery(yes bool, every int) OptionMatchStatistic {
	return func(mStatistic *MatchStatistic) {
		mStatistic.Every = every
		mStatistic.EveryInvert = !yes
	}
}

// Set the initial counter value for the nth mode.
func WithMatchStatisticPacket(packet int) OptionMatchStatistic {
	return func(mStatistic *MatchStatistic) {
		mStatistic.Packet = packet
	}
}

func NewMatchStatistic(opts ...OptionMatchStatistic) (*MatchStatistic, error) {
	match := &MatchStatistic{
		baseMatch: baseMatch{
			matchType: MatchTypeStatistic,
		},
		Probability: -1,
		Every:       -1,
		Packet:      -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchStatistic struct {
	baseMatch
	Mode        StatisticMode
	Probability float64
	Every       int
	Packet      int
	// invert
	ProbabilityInvert bool
	EveryInvert       bool
}

func (mStatis *MatchStatistic) Parse(main []byte) (int, bool) {
	// 1. "^statistic"
	// 2. "( mode random( !)? probability ([0-9.]+))?" #1 #2 #3
	// 3. "( mode nth( !)? every ([0-9]+)( packet ([0-9]+))?)?" #4 #5 #6 #7 #8
	pattern := `^statistic` +
		`( mode random( !)? probability ([0-9.]+))?` +
		`( mode nth( !)? every ([0-9]+)( packet ([0-9]+))?)?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 9 {
		return 0, false
	}
	if len(matches[3]) != 0 {
		prob, err := strconv.ParseFloat(string(matches[3]), 64)
		if err != nil {
			return 0, false
		}
		mStatis.Probability = prob
		mStatis.Mode = StatisticModeRandom
		if len(matches[2]) != 0 {
			mStatis.ProbabilityInvert = true
		}
	}
	if len(matches[6]) != 0 {
		every, err := strconv.Atoi(string(matches[6]))
		if err != nil {
			return 0, false
		}
		mStatis.Every = every
		mStatis.Mode = StatisticModeNth
		if len(matches[5]) != 0 {
			mStatis.EveryInvert = true
		}
		if len(matches[8]) != 0 {
			packet, err := strconv.Atoi(string(matches[8]))
			if err != nil {
				return 0, false
			}
			mStatis.Packet = packet
		}
	}
	return len(matches[0]), true
}

type StringAlgo int

const (
	_ StringAlgo = iota
	StringAlgoBM
	StringAlgoKMP
)

type OptionMatchString func(*MatchString)

// Select the pattern matching strategy.
func WithMatchStringAlgo(algo StringAlgo) OptionMatchString {
	return func(mString *MatchString) {
		mString.Algo = algo
	}
}

// Set the offset from which it starts looking for any matching.
func WithMatchStringFrom(from int) OptionMatchString {
	return func(mString *MatchString) {
		mString.From = from
	}
}

// Set the offset up to which should be scanned.
func WithMatchStringTo(to int) OptionMatchString {
	return func(mString *MatchString) {
		mString.To = to
	}
}

// Matches the given pattern.
func WithMatchStringPattern(yes bool, pattern string) OptionMatchString {
	return func(mString *MatchString) {
		mString.Pattern = pattern
		mString.PatternInvert = !yes
	}
}

// Matches the given pattern in hex notation.
func WithMatchStringHexPattern(yes bool, hexPattern []byte) OptionMatchString {
	return func(mString *MatchString) {
		mString.HexPattern = hexPattern
		mString.HexPatternInvert = !yes
	}
}

func WithMatchStringIgnoreCase() OptionMatchString {
	return func(mString *MatchString) {
		mString.IgnoreCase = true
	}
}

func NewMatchString(opts ...OptionMatchString) (*MatchString, error) {
	match := &MatchString{
		baseMatch: baseMatch{
			matchType: MatchTypeString,
		},
		From: -1,
		To:   -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchString struct {
	baseMatch
	Algo       StringAlgo
	From       int
	To         int
	Pattern    string
	HexPattern []byte
	IgnoreCase bool
	// invert
	PatternInvert    bool
	HexPatternInvert bool
}

func (mString *MatchString) Parse(main []byte) (int, bool) {
	// 1. "^STRING match "
	// 2. "((!)? ("\|([0-9A-Za-z]+)\|"))?" #1 #2 #3 #4
	// 3. "((!)? ("([ -~]+)"))?" #5 #6 #7 #8
	// 4. " ALGO name (bm|kmp)" #9
	// 5. "( FROM ([0-9]+))?" #10 #11
	// 6. "( TO ([0-9]+))?" #12 #13
	// 7. "( ICASE)?" #14
	pattern := `^STRING match ` +
		`((!)? ("\|([0-9A-Za-z]+)\|"))?` +
		`((!)? ("([ -~]+)"))?` +
		` ALGO name (bm|kmp)` +
		`( FROM ([0-9]+))?` +
		`( TO ([0-9]+))?` +
		`( ICASE)?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 15 {
		return 0, false
	}
	if len(matches[4]) != 0 {
		hexstr, err := hex.DecodeString(string(matches[4]))
		if err != nil {
			return 0, false
		}
		mString.HexPattern = hexstr
		if len(matches[2]) != 0 {
			mString.HexPatternInvert = true
		}
	}
	if len(matches[8]) != 0 {
		str := string(matches[8])
		str = strings.ReplaceAll(str, `\\`, `\`)
		mString.Pattern = strings.ReplaceAll(str, `\"`, `"`)
		if len(matches[6]) != 0 {
			mString.PatternInvert = true
		}
	}
	switch string(matches[9]) {
	case "bm":
		mString.Algo = StringAlgoBM
	case "kmp":
		mString.Algo = StringAlgoKMP
	default:
		return 0, false
	}
	if len(matches[11]) != 0 {
		from, err := strconv.Atoi(string(matches[11]))
		if err != nil {
			return 0, false
		}
		mString.From = from
	}
	if len(matches[13]) != 0 {
		to, err := strconv.Atoi(string(matches[13]))
		if err != nil {
			return 0, false
		}
		mString.To = to
	}
	if len(matches[14]) != 0 {
		mString.IgnoreCase = true
	}
	return len(matches[0]), true
}

type OptionMatchTCP func(*MatchTCP)

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchTCPSrcPort(yes bool, port ...int) OptionMatchTCP {
	return func(mTCP *MatchTCP) {
		switch len(port) {
		case 1:
			mTCP.SrcPortMin = port[0]
		case 2:
			mTCP.SrcPortMin = port[0]
			mTCP.SrcPortMax = port[1]
		}
		mTCP.SrcPortInvert = !yes
	}
}

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchTCPDstPort(yes bool, port ...int) OptionMatchTCP {
	return func(mTCP *MatchTCP) {
		switch len(port) {
		case 1:
			mTCP.DstPortMin = port[0]
		case 2:
			mTCP.DstPortMin = port[0]
			mTCP.DstPortMax = port[1]
		}
		mTCP.DstPortInvert = !yes
	}
}

// Match when the TCP flags are as specified.
func WithMatchTCPFlags(yes bool, mask TCPFlag, set TCPFlag) OptionMatchTCP {
	return func(mTCP *MatchTCP) {
		mTCP.FlagsMask = mask
		mTCP.FlagsSet = set
		mTCP.FlagsInvert = !yes
	}
}

func WithMatchTCPOption(yes bool, option uint8) OptionMatchTCP {
	return func(mTCP *MatchTCP) {
		mTCP.Option = option
	}
}

func NewMatchTCP(opts ...OptionMatchTCP) (*MatchTCP, error) {
	match := &MatchTCP{
		baseMatch: baseMatch{
			matchType: MatchTypeTCP,
		},
		SrcPortMin: -1,
		SrcPortMax: -1,
		DstPortMin: -1,
		DstPortMax: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchTCP struct {
	baseMatch
	SrcPortMin int
	SrcPortMax int
	DstPortMin int
	DstPortMax int
	FlagsMask  TCPFlag
	FlagsSet   TCPFlag
	Option     uint8
	// invert
	SrcPortInvert bool
	DstPortInvert bool
	FlagsInvert   bool
	OptionInvert  bool
}

func (mTCP *MatchTCP) Parse(main []byte) (int, bool) {
	// 1. "^tcp"
	// 2. "( spt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?" #1 #2 #3 #4 #5 #6 #7 #8
	// 3. "( dpt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?" #9 #10 #11 #12 #13 #14 #15 #16
	// 4. "( option=(!)?([0-9]+))?" #17 #18 #19
	// 5. "( flags:(!)?((0x([0-9]+)/0x([0-9]+))|(([A-Z]+)/([A-Z]+))))?" #20 #21 #22 #23 #24 #25 #26 #27 #28
	// 6. "( Unknown invflags: 0x[0-9]+)?" #29
	pattern := `^tcp` +
		`( spt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?` +
		`( dpt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?` +
		`( option=(!)?([0-9]+))?` +
		`( flags:(!)?((0x([0-9]+)/0x([0-9]+))|(([A-Z,]+)/([A-Z,]+))))?` +
		`( Unknown invflags: 0x[0-9]+)?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 30 {
		return 0, false
	}
	if len(matches[4]) != 0 {
		spt, err := strconv.Atoi(string(matches[4]))
		if err != nil {
			return 0, false
		}
		mTCP.SrcPortMin = spt
		if len(matches[3]) != 0 {
			mTCP.SrcPortInvert = true
		}
	}
	if len(matches[7]) != 0 {
		min, err := strconv.Atoi(string(matches[7]))
		if err != nil {
			return 0, false
		}
		max, err := strconv.Atoi(string(matches[8]))
		if err != nil {
			return 0, false
		}
		if len(matches[6]) != 0 {
			mTCP.SrcPortInvert = true
		}
		mTCP.SrcPortMin = min
		mTCP.SrcPortMax = max
	}
	if len(matches[12]) != 0 {
		dpt, err := strconv.Atoi(string(matches[12]))
		if err != nil {
			return 0, false
		}
		mTCP.DstPortMin = dpt
		if len(matches[11]) != 0 {
			mTCP.DstPortInvert = true
		}
	}
	if len(matches[15]) != 0 {
		min, err := strconv.Atoi(string(matches[15]))
		if err != nil {
			return 0, false
		}
		max, err := strconv.Atoi(string(matches[16]))
		if err != nil {
			return 0, false
		}
		if len(matches[14]) != 0 {
			mTCP.DstPortInvert = true
		}
		mTCP.DstPortMin = min
		mTCP.DstPortMax = max
	}
	if len(matches[19]) != 0 {
		option, err := strconv.Atoi(string(matches[19]))
		if err != nil {
			return 0, false
		}
		mTCP.Option = uint8(option)
		if len(matches[18]) != 0 {
			mTCP.OptionInvert = true
		}
	}
	// numeric like: 0x02X/0x02X
	if len(matches[24]) != 0 {
		mask, err := strconv.ParseUint(string(matches[24]), 16, 8)
		if err != nil {
			return 0, false
		}
		set, err := strconv.ParseUint(string(matches[25]), 16, 8)
		if err != nil {
			return 0, false
		}
		mTCP.FlagsMask = TCPFlag(mask)
		mTCP.FlagsSet = TCPFlag(set)
	}
	// non-numeric like: SYN,FIN/SYN
	if len(matches[27]) != 0 {
		flags := strings.Split(string(matches[27]), ",")
		for _, flag := range flags {
			f, ok := TCPFlags[flag]
			if !ok {
				return 0, false
			}
			mTCP.FlagsMask |= f
		}
		flags = strings.Split(string(matches[28]), ",")
		for _, flag := range flags {
			f, ok := TCPFlags[flag]
			if !ok {
				return 0, false
			}
			mTCP.FlagsSet |= f
		}
	}
	return len(matches[0]), true
}

// This option takes mostly 2 mss, (min) or (min, max)
func NewMatchTCPMSS(yes bool, mss ...int) (*MatchTCPMSS, error) {
	match := &MatchTCPMSS{
		baseMatch: baseMatch{
			matchType: MatchTypeTCPMSS,
			invert:    !yes,
		},
	}
	switch len(mss) {
	case 1:
		match.MSSMin = mss[0]
	case 2:
		match.MSSMin = mss[0]
		match.MSSMax = mss[1]
	}
	return match, nil
}

type MatchTCPMSS struct {
	baseMatch
	MSSMin int
	MSSMax int
}

func (mTCPMSS *MatchTCPMSS) Parse(main []byte) (int, bool) {
	pattern := `^tcpmss match (!)?([0-9]+)(:([0-9]+))?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mTCPMSS.invert = true
	}
	if len(matches[2]) != 0 {
		min, err := strconv.Atoi(string(matches[2]))
		if err != nil {
			return 0, false
		}
		mTCPMSS.MSSMin = min
	}
	if len(matches[4]) != 0 {
		max, err := strconv.Atoi(string(matches[4]))
		if err != nil {
			return 0, false
		}
		mTCPMSS.MSSMax = max
	}
	return len(matches[0]), true
}

type OptionMatchTime func(mTime *MatchTime)

func WithMatchTimeDateStart(start Date) OptionMatchTime {
	return func(mTime *MatchTime) {
		mTime.DateStart = start
	}
}

func WithMatchTimeDateTop(top Date) OptionMatchTime {
	return func(mTime *MatchTime) {
		mTime.DateTop = top
	}
}

func WithMatchTimeDaytimeStart(start Daytime) OptionMatchTime {
	return func(mTime *MatchTime) {
		mTime.DaytimeStart = start
	}
}

func WithMatchTimeDaytimeTop(top Daytime) OptionMatchTime {
	return func(mTime *MatchTime) {
		mTime.DaytimeTop = top
	}
}

// Match on the given days of the month.
func WithMatchTimeMonthdays(monthdays Monthday) OptionMatchTime {
	return func(mTime *MatchTime) {
		mTime.Monthdays = monthdays
	}
}

// Match on the given weekdays.
func WithMatchTimeWeekdays(weekdays Weekday) OptionMatchTime {
	return func(mTime *MatchTime) {
		mTime.Weekdays = weekdays
	}
}

// Use the kernel timezone instead of UTC to determine
// whether a packet meets the time regulations.
func WithMatchTimeKernelTZ() OptionMatchTime {
	return func(mTime *MatchTime) {
		mTime.KernelTZ = true
	}
}

// Match this as a single time period instead distinct intervals.
func WithMatchTimeContiguous() OptionMatchTime {
	return func(mTime *MatchTime) {
		mTime.Contiguous = true
	}
}

func NewMatchTime(opts ...OptionMatchTime) (*MatchTime, error) {
	match := &MatchTime{
		baseMatch: baseMatch{
			matchType: MatchTypeTime,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchTime struct {
	baseMatch
	DaytimeStart Daytime
	DaytimeTop   Daytime
	DateStart    Date
	DateTop      Date
	Weekdays     Weekday
	Monthdays    Monthday
	KernelTZ     bool
	Contiguous   bool
}

func (mTime *MatchTime) Parse(main []byte) (int, bool) {
	// 1. "^TIME"
	// 2. "( from ([0-9:]+) to ([0-9:]+))?" #1 #2 #3
	// 3. "( on ((Mon|Tue|Wed|Thu|Fri|Sat|Sun|,)+))?" #4 #5 #6
	// 4. "( on ((1st|2nd|3rd|[0-9]+th|,)+))?" #7 #8 #9
	// 5. "( starting from ([0-9]{4}-[0-9]{2}-[0-9]{2}[T| ][0-9]{2}:[0-9]{2}:[0-9]{2}))?" #10 #11
	// 6. "( until date ([0-9]{4}-[0-9]{2}-[0-9]{2}[T| ][0-9]{2}:[0-9]{2}:[0-9]{2}))?" #12 #13
	// 7. "( UTC)?" #14
	// 8. "( contiguous)?" #15
	pattern := `^TIME` +
		`( from ([0-9:]+) to ([0-9:]+))?` +
		`( on ((Mon|Tue|Wed|Thu|Fri|Sat|Sun|,)+))?` +
		`( on ((1st|2nd|3rd|[0-9]+th|,)+))?` +
		`( starting from ([0-9]{4}-[0-9]{2}-[0-9]{2}[T| ][0-9]{2}:[0-9]{2}:[0-9]{2}))?` +
		`( until date ([0-9]{4}-[0-9]{2}-[0-9]{2}[T| ][0-9]{2}:[0-9]{2}:[0-9]{2}))?` +
		`( UTC)?` +
		`( contiguous)?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	fmt.Println(len(matches))
	if len(matches) != 16 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		start, err := ParseDaytime(string(matches[2]))
		if err != nil {
			return 0, false
		}
		top, err := ParseDaytime(string(matches[3]))
		if err != nil {
			return 0, false
		}
		mTime.DaytimeStart = start
		mTime.DaytimeTop = top
	}
	if len(matches[5]) != 0 {
		weekdays := strings.Split(string(matches[5]), ",")
		for _, weekday := range weekdays {
			wd, ok := Weekdays[weekday]
			if !ok {
				return 0, false
			}
			mTime.Weekdays |= wd
		}
	}
	if len(matches[8]) != 0 {
		monthdays := strings.Split(string(matches[8]), ",")
		for _, monthday := range monthdays {
			monthday = monthday[:len(monthday)-2]
			md, err := strconv.ParseUint(monthday, 10, 32)
			if err != nil {
				return 0, false
			}
			mTime.Monthdays |= 1 << uint32(md)
		}
	}
	if len(matches[11]) != 0 {
		de, err := ParseDate(string(matches[11]))
		if err != nil {
			return 0, false
		}
		mTime.DateStart = de
	}
	if len(matches[13]) != 0 {
		de, err := ParseDate(string(matches[13]))
		if err != nil {
			return 0, false
		}
		mTime.DateTop = de
	}
	if len(matches[14]) == 0 {
		mTime.KernelTZ = true
	}
	if len(matches[15]) != 0 {
		mTime.Contiguous = true
	}
	return len(matches[0]), true
}

// This option takes mostly 2 tos, (value) or (value/mask)
func NewMatchTOS(yes bool, tos ...TOS) (*MatchTOS, error) {
	match := &MatchTOS{
		baseMatch: baseMatch{
			matchType: MatchTypeTOS,
		},
	}
	switch len(tos) {
	case 1:
		match.Value = tos[0]
	case 2:
		match.Value = tos[0]
		match.Mask = tos[1]
	}
	match.invert = !yes
	return match, nil
}

type MatchTOS struct {
	baseMatch
	Value TOS
	Mask  TOS
}

func (mTOS *MatchTOS) Parse(main []byte) (int, bool) {
	// 1. "^tos match(!)?"
	// 2. "( (Minimize-Delay|Maximize-Throughput|Maximize-Reliability|Minimize-Cost|Normal-Service))?"
	// 3. "(0x([0-9A-Za-z]+)/0x([0-9A-Za-z]+))?"
	pattern := `^tos match(!)?` +
		`( (Minimize-Delay|Maximize-Throughput|Maximize-Reliability|Minimize-Cost|Normal-Service))?` +
		`(0x([0-9A-Za-z]+)/0x([0-9A-Za-z]+))?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 7 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mTOS.invert = true
	}
	if len(matches[3]) != 0 {
		tos, ok := TOSMap[string(matches[3])]
		if ok {
			mTOS.Value = tos
		}
		mTOS.Mask = TOS(0x3f)
	}
	if len(matches[5]) != 0 {
		value, err := strconv.ParseUint(string(matches[5]), 16, 8)
		if err != nil {
			return 0, false
		}
		mTOS.Value = TOS(value)
	}
	if len(matches[6]) != 0 {
		mask, err := strconv.ParseUint(string(matches[6]), 16, 8)
		if err != nil {
			return 0, false
		}
		mTOS.Mask = TOS(mask)
	}
	return len(matches[0]), true
}

type OptionMatchTTL func(*MatchTTL)

// Matches the given TTL value.
func WithMatchTTLEqual(ttl int) OptionMatchTTL {
	return func(mTTL *MatchTTL) {
		mTTL.Operator = OperatorEQ
		mTTL.Value = ttl
	}
}

// Doesn't match the given TTL value.
func WithMatchTTLNotEqual(ttl int) OptionMatchTTL {
	return func(mTTL *MatchTTL) {
		mTTL.Operator = OperatorNE
		mTTL.Value = ttl
	}
}

// Matches if TTL is greater than the given TTL value.
func WithMatchTTLGreaterThan(ttl int) OptionMatchTTL {
	return func(mTTL *MatchTTL) {
		mTTL.Operator = OperatorGT
		mTTL.Value = ttl
	}
}

// Matches if TTL is less than the given TTL value.
func WithMatchTTLLessThan(ttl int) OptionMatchTTL {
	return func(mTTL *MatchTTL) {
		mTTL.Operator = OperatorLT
		mTTL.Value = ttl
	}
}

func NewMatchTTL(opts ...OptionMatchTTL) (*MatchTTL, error) {
	match := &MatchTTL{
		baseMatch: baseMatch{
			matchType: MatchTypeTTL,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// IPv4 specific
// Non-numeric unsupport
type MatchTTL struct {
	baseMatch
	Operator Operator
	Value    int
}

func (mTTL *MatchTTL) Parse(main []byte) (int, bool) {
	pattern := `^TTL match TTL (==|!=|<|>) ([0-9]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	switch string(matches[1]) {
	case "==":
		mTTL.Operator = OperatorEQ
	case "!=":
		mTTL.Operator = OperatorNE
	case "<":
		mTTL.Operator = OperatorLT
	case ">":
		mTTL.Operator = OperatorGT
	default:
		return 0, false
	}
	value, err := strconv.Atoi(string(matches[2]))
	if err != nil {
		return 0, false
	}
	mTTL.Value = value
	return len(matches[0]), true
}

func NewMatchU32(yes bool, tests string) (*MatchU32, error) {
	return &MatchU32{
		baseMatch: baseMatch{
			matchType: MatchTypeU32,
			invert:    !yes,
		},
		Tests: tests,
	}, nil
}

type MatchU32 struct {
	baseMatch
	Tests string
}

func (mU32 *MatchU32) Parse(main []byte) (int, bool) {
	pattern := `^u32( !)? "([ -~]+)"`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		mU32.invert = true
	}
	mU32.Tests = string(matches[2])
	return len(matches[0]), true
}

type OptionMatchUDP func(*MatchUDP)

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchUDPSrcPort(yes bool, port ...int) OptionMatchUDP {
	return func(mUDP *MatchUDP) {
		switch len(port) {
		case 1:
			mUDP.SrcPortMin = port[0]
		case 2:
			mUDP.SrcPortMin = port[0]
			mUDP.SrcPortMax = port[1]
		}
		mUDP.SrcPortInvert = !yes
	}
}

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchUDPDstPort(yes bool, port ...int) OptionMatchUDP {
	return func(mUDP *MatchUDP) {
		switch len(port) {
		case 1:
			mUDP.DstPortMin = port[0]
		case 2:
			mUDP.DstPortMin = port[0]
			mUDP.DstPortMax = port[1]
		}
		mUDP.DstPortInvert = !yes
	}
}

func NewMatchUDP(opts ...OptionMatchUDP) (*MatchUDP, error) {
	match := &MatchUDP{
		baseMatch: baseMatch{
			matchType: MatchTypeUDP,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchUDP struct {
	baseMatch
	SrcPortMin int
	SrcPortMax int
	DstPortMin int
	DstPortMax int
	// invert
	SrcPortInvert bool
	DstPortInvert bool
}

func (mUDP *MatchUDP) Parse(main []byte) (int, bool) {
	// 1. "^udp"
	// 2. "( spt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?" #1 #2 #3 #4 #5 #6 #7 #8
	// 3. "( dpt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?" #9 #10 #11 #12 #13 #14 #15 #16
	// 4. "( Unknown invflags: 0x[0-9]+)?" #17
	pattern := `^udp` +
		`( spt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?` +
		`( dpt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?` +
		`( Unknown invflags: 0x[0-9]+)?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 18 {
		return 0, false
	}
	if len(matches[4]) != 0 {
		spt, err := strconv.Atoi(string(matches[4]))
		if err != nil {
			return 0, false
		}
		mUDP.SrcPortMin = spt
		if len(matches[3]) != 0 {
			mUDP.SrcPortInvert = true
		}
	}
	if len(matches[7]) != 0 {
		min, err := strconv.Atoi(string(matches[7]))
		if err != nil {
			return 0, false
		}
		max, err := strconv.Atoi(string(matches[8]))
		if err != nil {
			return 0, false
		}
		if len(matches[6]) != 0 {
			mUDP.SrcPortInvert = true
		}
		mUDP.SrcPortMin = min
		mUDP.SrcPortMax = max
	}
	if len(matches[12]) != 0 {
		dpt, err := strconv.Atoi(string(matches[12]))
		if err != nil {
			return 0, false
		}
		mUDP.DstPortMin = dpt
		if len(matches[11]) != 0 {
			mUDP.DstPortInvert = true
		}
	}
	if len(matches[15]) != 0 {
		min, err := strconv.Atoi(string(matches[15]))
		if err != nil {
			return 0, false
		}
		max, err := strconv.Atoi(string(matches[16]))
		if err != nil {
			return 0, false
		}
		if len(matches[14]) != 0 {
			mUDP.DstPortInvert = true
		}
		mUDP.DstPortMin = min
		mUDP.DstPortMax = max
	}
	return len(matches[0]), true
}

var (
	matchPrefixes = map[string]MatchType{
		"ADDRTYPE match":       MatchTypeAddrType,
		"ah":                   MatchTypeAH,
		"match bpf":            MatchTypeBPF,
		"cgroup":               MatchTypeCGroup,
		"cluster":              MatchTypeCluster,
		"/*":                   MatchTypeComment,
		"connbytes":            MatchTypeConnBytes,
		"! connbytes":          MatchTypeConnBytes,
		"connlabel":            MatchTypeConnLabel,
		"#conn":                MatchTypeConnLimit,
		"CONNMARK":             MatchTypeConnMark,
		"connmark":             MatchTypeConnMark,
		"ctstate":              MatchTypeConnTrack,
		"! ctstate":            MatchTypeConnTrack,
		"ctproto":              MatchTypeConnTrack,
		"! ctproto":            MatchTypeConnTrack,
		"ctstatus":             MatchTypeConnTrack,
		"! ctstatus":           MatchTypeConnTrack,
		"ctexpire":             MatchTypeConnTrack,
		"! ctexpire":           MatchTypeConnTrack,
		"ctdir":                MatchTypeConnTrack,
		"! ctdir":              MatchTypeConnTrack,
		"ctorigsrc":            MatchTypeConnTrack,
		"! ctorigsrc":          MatchTypeConnTrack,
		"ctorigdst":            MatchTypeConnTrack,
		"! ctorigdst":          MatchTypeConnTrack,
		"ctreplsrc":            MatchTypeConnTrack,
		"! ctreplsrc":          MatchTypeConnTrack,
		"ctrepldst":            MatchTypeConnTrack,
		"! ctrepldst":          MatchTypeConnTrack,
		"ctorigsrcport":        MatchTypeConnTrack,
		"! ctorigsrcport":      MatchTypeConnTrack,
		"ctorigdstport":        MatchTypeConnTrack,
		"! ctorigdstport":      MatchTypeConnTrack,
		"ctreplsrcport":        MatchTypeConnTrack,
		"! ctreplsrcport":      MatchTypeConnTrack,
		"ctrepldstport":        MatchTypeConnTrack,
		"! ctrepldstport":      MatchTypeConnTrack,
		"cpu":                  MatchTypeCPU,
		"dccp":                 MatchTypeDCCP,
		"src-group":            MatchTypeDevGroup,
		"! src-group":          MatchTypeDevGroup,
		"dst-group":            MatchTypeDevGroup,
		"! dst-group":          MatchTypeDevGroup,
		"DSCP match":           MatchTypeDSCP,
		"dst":                  MatchTypeDst,
		"ECN match":            MatchTypeECN,
		"esp":                  MatchTypeESP,
		"eui64":                MatchTypeEUI64,
		"frag":                 MatchTypeFrag,
		"limit: above":         MatchTypeHashLimit,
		"limit: up to":         MatchTypeHashLimit,
		"hbh":                  MatchTypeHBH,
		"helper match":         MatchTypeHelper,
		"HL":                   MatchTypeHL,
		"ipv6-icmp":            MatchTypeICMP,
		"icmp":                 MatchTypeICMP,
		"source IP range":      MatchTypeIPRange,
		"destination IP range": MatchTypeIPRange,
		"ipv6header":           MatchTypeIPv6Header,
		"ipvs":                 MatchTypeIPVS,
		"! ipvs":               MatchTypeIPVS,
		"vproto":               MatchTypeIPVS,
		"! vproto":             MatchTypeIPVS,
		"vaddr":                MatchTypeIPVS,
		"! vaddr":              MatchTypeIPVS,
		"vport":                MatchTypeIPVS,
		"! vport":              MatchTypeIPVS,
		"vdir":                 MatchTypeIPVS,
		"vmethod":              MatchTypeIPVS,
		"! vmethod":            MatchTypeIPVS,
		"vportctl":             MatchTypeIPVS,
		"! vportctl":           MatchTypeIPVS,
		"length":               MatchTypeLength,
		"limit: avg":           MatchTypeLimit,
		"MAC":                  MatchTypeMAC,
		"mark match":           MatchTypeMark,
		"MARK match":           MatchTypeMark,
		"mh":                   MatchTypeMH,
		"multiport":            MatchTypeMultiPort,
		"nfacct-name":          MatchTypeNFAcct,
		"OS fingerprint match": MatchTypeOSF,
		"owner":                MatchTypeOwner,
		"incl":                 MatchTypeOwner,
		"PHYSDEV match":        MatchTypePhysDev,
		"PKTTYPE":              MatchTypePktType,
		"policy match":         MatchTypePolicy,
		"quota:":               MatchTypeQuota,
		"rateest match":        MatchTypeRateEst,
		"realm":                MatchTypeRealm,
		"! realm":              MatchTypeRealm,
		"recent:":              MatchTypeRecent,
		"! recent:":            MatchTypeRecent,
		"rpfilter":             MatchTypeRPFilter,
		"rt":                   MatchTypeRT,
		"sctp":                 MatchTypeSCTP,
		"match-set":            MatchTypeSet,
		"! match-set":          MatchTypeSet,
		"socket":               MatchTypeSocket,
		"state":                MatchTypeState,
		"! state":              MatchTypeState,
		"statistic":            MatchTypeStatistic,
		"STRING match":         MatchTypeString,
		"tcp":                  MatchTypeTCP,
		"tcpmss match":         MatchTypeTCPMSS,
		"TIME":                 MatchTypeTime,
		"tos match":            MatchTypeTOS,
		"TTL":                  MatchTypeTTL,
		"u32":                  MatchTypeU32,
		"udp":                  MatchTypeUDP,
	}
)

// see https://git.netfilter.org/iptables/tree/extensions
func ParseMatch(params []byte) ([]Match, error) {
	trie := tree.NewTrie()
	for prefix, typ := range matchPrefixes {
		ok := trie.Add(prefix, typ)
		if !ok {
			return nil, ErrMatchParams
		}
	}
	matches := []Match{}
	for len(params) > 0 {
		node, ok := trie.LPM(string(params))
		if !ok {
			return nil, ErrMatchParams
		}
		typ := node.Value().(MatchType)
		// get match by match type
		match := MatchFactory(typ)
		if match != nil {
			return nil, ErrMatchParams
		}
		// index meaning the end of this match
		index, ok := match.Parse(params)
		if !ok {
			return nil, ErrMatchParams
		}
		matches = append(matches, match)
		params = params[index:]
	}
	return matches, nil
}
