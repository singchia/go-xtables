package iptables

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/singchia/go-hammer/tree"
	"github.com/singchia/go-xtables"
	"github.com/singchia/go-xtables/pkg/network"
)

type MatchType int

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

func (mt MatchType) Type() string {
	return "MatchType"
}

func (mt MatchType) Value() string {
	return strconv.Itoa(int(mt))
}

func (mt MatchType) String() string {
	switch mt {
	case MatchTypeAddrType:
		return "addrtype"
	case MatchTypeAH:
		return "ah"
	case MatchTypeBPF:
		return "bpf"
	case MatchTypeCGroup:
		return "cgroup"
	case MatchTypeCluster:
		return "cluster"
	case MatchTypeComment:
		return "comment"
	case MatchTypeConnBytes:
		return "connbytes"
	case MatchTypeConnLabel:
		return "connlabel"
	case MatchTypeConnLimit:
		return "connlimit"
	case MatchTypeConnMark:
		return "connmark"
	case MatchTypeConnTrack:
		return "conntrack"
	case MatchTypeCPU:
		return "cpu"
	case MatchTypeDCCP:
		return "dccp"
	case MatchTypeDevGroup:
		return "devgroup"
	case MatchTypeDSCP:
		return "dscp"
	case MatchTypeDst:
		return "dst"
	case MatchTypeECN:
		return "ecn"
	case MatchTypeESP:
		return "esp"
	case MatchTypeEUI64:
		return "eui64"
	case MatchTypeFrag:
		return "frag"
	case MatchTypeHashLimit:
		return "hashlimit"
	case MatchTypeHBH:
		return "hbh"
	case MatchTypeHelper:
		return "helper"
	case MatchTypeHL:
		return "hl"
	case MatchTypeICMP:
		return "icmp"
	case MatchTypeIPRange:
		return "iprange"
	case MatchTypeIPv6Header:
		return "ipv6header"
	case MatchTypeIPVS:
		return "ipvs"
	case MatchTypeLength:
		return "length"
	case MatchTypeLimit:
		return "limit"
	case MatchTypeMAC:
		return "mac"
	case MatchTypeMark:
		return "mark"
	case MatchTypeMH:
		return "mh"
	case MatchTypeMultiPort:
		return "multiport"
	case MatchTypeNFAcct:
		return "nfacct"
	case MatchTypeOSF:
		return "osf"
	case MatchTypeOwner:
		return "owner"
	case MatchTypePhysDev:
		return "physdev"
	case MatchTypePktType:
		return "pkttype"
	case MatchTypePolicy:
		return "policy"
	case MatchTypeQuota:
		return "quota"
	case MatchTypeRateEst:
		return "rateest"
	case MatchTypeRealm:
		return "realm"
	case MatchTypeRecent:
		return "recent"
	case MatchTypeRPFilter:
		return "rpfilter"
	case MatchTypeRT:
		return "rt"
	case MatchTypeSCTP:
		return "sctp"
	case MatchTypeSet:
		return "set"
	case MatchTypeSocket:
		return "socket"
	case MatchTypeSRH:
		return "srh"
	case MatchTypeState:
		return "state"
	case MatchTypeStatistic:
		return "statistic"
	case MatchTypeString:
		return "string"
	case MatchTypeTCP:
		return "tcp"
	case MatchTypeTCPMSS:
		return "tcpmss"
	case MatchTypeTime:
		return "time"
	case MatchTypeTOS:
		return "tos"
	case MatchTypeTTL:
		return "ttl"
	case MatchTypeU32:
		return "u32"
	case MatchTypeUDP:
		return "udp"
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

func matchFactory(matchType MatchType) Match {
	switch matchType {
	case MatchTypeAddrType:
		match, _ := newMatchAddrType()
		return match
	case MatchTypeAH:
		match, _ := newMatchAH()
		return match
	case MatchTypeBPF:
		match, _ := newMatchBPF()
		return match
	case MatchTypeCGroup:
		match, _ := newMatchCGroup()
		return match
	case MatchTypeCluster:
		match, _ := newMatchCluster()
		return match
	case MatchTypeComment:
		match, _ := newMatchComment("")
		return match
	case MatchTypeConnBytes:
		match, _ := newMatchConnBytes()
		return match
	case MatchTypeConnLabel:
		match, _ := newMatchConnLabel()
		return match
	case MatchTypeConnLimit:
		match, _ := newMatchConnLimit()
		return match
	case MatchTypeConnMark:
		match, _ := newMatchConnMark(true)
		return match
	case MatchTypeConnTrack:
		match, _ := newMatchConnTrack()
		return match
	case MatchTypeCPU:
		match, _ := newMatchCPU(true, -1)
		return match
	case MatchTypeDCCP:
		match, _ := newMatchDCCP()
		return match
	case MatchTypeDevGroup:
		match, _ := newMatchDevGroup()
		return match
	case MatchTypeDSCP:
		match, _ := newMatchDSCP()
		return match
	case MatchTypeDst:
		match, _ := newMatchDst()
		return match
	case MatchTypeECN:
		match, _ := newMatchECN()
		return match
	case MatchTypeESP:
		match, _ := newMatchESP(true)
		return match
	case MatchTypeEUI64:
		match, _ := newMatchEUI64()
		return match
	case MatchTypeFrag:
		match, _ := newMatchFrag()
		return match
	case MatchTypeHBH:
		match, _ := newMatchHBH()
		return match
	case MatchTypeHelper:
		match, _ := newMatchHelper("")
		return match
	case MatchTypeHL:
		match, _ := newMatchHL(0, -1)
		return match
	case MatchTypeICMP:
		match, _ := newMatchICMP(true, -1)
		return match
	case MatchTypeIPRange:
		match, _ := newMatchIPRange()
		return match
	case MatchTypeIPv6Header:
		match, _ := newMatchIPv6Header()
		return match
	case MatchTypeIPVS:
		match, _ := newMatchIPVS()
		return match
	case MatchTypeLength:
		match, _ := newMatchLength(true)
		return match
	case MatchTypeLimit:
		match, _ := newMatchLimit()
		return match
	case MatchTypeMAC:
		match, _ := newMatchMAC(true, nil)
		return match
	case MatchTypeMark:
		match, _ := newMatchMark(true)
		return match
	case MatchTypeMH:
		match, _ := newMatchMH(true)
		return match
	case MatchTypeMultiPort:
		match, _ := newMatchMultiPort()
		return match
	case MatchTypeNFAcct:
		match, _ := newMatchNFAcct("")
		return match
	case MatchTypeOSF:
		match, _ := newMatchOSF()
		return match
	case MatchTypeOwner:
		match, _ := newMatchOwner()
		return match
	case MatchTypePhysDev:
		match, _ := newMatchPhysDev()
		return match
	case MatchTypePktType:
		match, _ := newMatchPktType(true, -1)
		return match
	case MatchTypePolicy:
		match, _ := newMatchPolicy()
		return match
	case MatchTypeQuota:
		match, _ := newMatchQuota(true, -1)
		return match
	case MatchTypeRateEst:
		match, _ := newMatchRateEst()
		return match
	case MatchTypeRealm:
		match, _ := newMatchRealm(true)
		return match
	case MatchTypeRecent:
		match, _ := newMatchRecent()
		return match
	case MatchTypeRPFilter:
		match, _ := newMatchRPFilter()
		return match
	case MatchTypeRT:
		match, _ := newMatchRT()
		return match
	case MatchTypeSCTP:
		match, _ := newMatchSCTP()
		return match
	case MatchTypeSet:
		match, _ := newMatchSet()
		return match
	case MatchTypeSocket:
		match, _ := newMatchSocket()
		return match
	case MatchTypeState:
		match, _ := newMatchState(-1)
		return match
	case MatchTypeStatistic:
		match, _ := newMatchStatistic()
		return match
	case MatchTypeString:
		match, _ := newMatchString()
		return match
	case MatchTypeTCP:
		match, _ := newMatchTCP()
		return match
	case MatchTypeTCPMSS:
		match, _ := newMatchTCPMSS(true)
		return match
	case MatchTypeTime:
		match, _ := newMatchTime()
		return match
	case MatchTypeTOS:
		match, _ := newMatchTOS(true)
		return match
	case MatchTypeTTL:
		match, _ := newMatchTTL()
		return match
	case MatchTypeU32:
		match, _ := newMatchU32(true, "")
		return match
	case MatchTypeUDP:
		match, _ := newMatchUDP()
		return match
	default:
		return nil
	}
}

type baseMatch struct {
	matchType MatchType
	invert    bool
	addrType  network.AddressType
}

func (bm baseMatch) Type() MatchType {
	return bm.matchType
}

func (bm baseMatch) Short() string {
	return ""
}

func (bm *baseMatch) ShortArgs() []string {
	return nil
}

func (bm *baseMatch) Long() string {
	return ""
}

func (bm *baseMatch) LongArgs() []string {
	return nil
}

func (bm *baseMatch) Parse(params []byte) (int, bool) {
	return 0, false
}

func (bm *baseMatch) AddrType() network.AddressType {
	return bm.addrType
}

func (bm *baseMatch) Depends() []MatchType {
	return nil
}

type MatchIPv4 struct {
	*baseMatch
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
	*baseMatch
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
	*baseMatch
	Protocol network.Protocol
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
	*baseMatch
	address network.Address
}

func newMatchSource(invert bool, address network.Address) (*MatchSource, error) {
	return &MatchSource{
		baseMatch: &baseMatch{
			matchType: MatchTypeSource,
		},
		address: address,
	}, nil
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
	*baseMatch
	address network.Address
}

func newMatchDestination(invert bool, address network.Address) (*MatchDestination, error) {
	return &MatchDestination{
		baseMatch: &baseMatch{
			matchType: MatchTypeDestination,
		},
		address: address,
	}, nil
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
	*baseMatch
	iface string
}

func newMatchInInterface(invert bool, iface string) (*MatchInInterface, error) {
	return &MatchInInterface{
		baseMatch: &baseMatch{
			matchType: MatchTypeInInterface,
			invert:    invert,
		},
		iface: iface,
	}, nil
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
	*baseMatch
	iface string
}

func newMatchOutInterface(invert bool, iface string) (*MatchOutInterface, error) {
	return &MatchOutInterface{
		baseMatch: &baseMatch{
			matchType: MatchTypeOutInterface,
			invert:    invert,
		},
		iface: iface,
	}, nil
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
//
func WithMatchAddrTypeSrcType(invert bool, srcType AddrType) OptionMatchAddrType {
	return func(mAddrType *MatchAddrType) {
		mAddrType.SrcTypeInvert = invert
		mAddrType.SrcType = srcType
		mAddrType.HasSrcType = true
	}
}

// Matches if the destination address is of given type.
func WithMatchAddrTypeDstType(invert bool, dstType AddrType) OptionMatchAddrType {
	return func(mAddrType *MatchAddrType) {
		mAddrType.DstTypeInvert = invert
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

func newMatchAddrType(opts ...OptionMatchAddrType) (*MatchAddrType, error) {
	match := &MatchAddrType{
		baseMatch: &baseMatch{
			matchType: MatchTypeAddrType,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// Non-numeric unsupported
type MatchAddrType struct {
	*baseMatch
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
	args := make([]string, 0, 8)
	args = append(args, "-m", mAddrType.matchType.String())
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
func WithMatchAHSPI(invert bool, spi ...int) OptionMatchAH {
	return func(mAH *MatchAH) {
		switch len(spi) {
		case 1:
			mAH.SPIMin = spi[0]
			mAH.SPIMax = -1
		case 2:
			mAH.SPIMin = spi[0]
			mAH.SPIMax = spi[1]
		}
		mAH.SPIInvert = invert
	}
}

// Total length of this header in octets
func WithMatchAHSPILength(invert bool, length int) OptionMatchAH {
	return func(mAH *MatchAH) {
		mAH.LengthInvert = invert
		mAH.Length = length
	}
}

// Matches if the reserved field is filled with zero
func WithMatchAHReserved() OptionMatchAH {
	return func(mAH *MatchAH) {
		mAH.Reserved = true
	}
}

func newMatchAH(opts ...OptionMatchAH) (*MatchAH, error) {
	match := &MatchAH{
		baseMatch: &baseMatch{
			matchType: MatchTypeAH,
		},
		SPIMin: -1,
		SPIMax: -1,
		Length: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// Both ipv4 and ipv6
// Non-numeric unsupported
type MatchAH struct {
	*baseMatch
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

func (mAH *MatchAH) Short() string {
	return strings.Join(mAH.ShortArgs(), " ")
}

func (mAH *MatchAH) ShortArgs() []string {
	args := make([]string, 0, 7)
	if mAH.SPIMin > -1 {
		if mAH.SPIInvert {
			args = append(args, "!")
		}
		if mAH.SPIMax > -1 {
			args = append(args, "--ahspi",
				strconv.Itoa(mAH.SPIMin)+":"+strconv.Itoa(mAH.SPIMax))
		} else {
			args = append(args, "--ahspi", strconv.Itoa(mAH.SPIMin))
		}
	}
	if mAH.Length > -1 {
		if mAH.LengthInvert {
			args = append(args, "!")
		}
		args = append(args, "--ahlen", strconv.Itoa(mAH.Length))
	}
	if mAH.Reserved {
		args = append(args, "--ahres")
	}
	return args
}

func (mAH *MatchAH) Long() string {
	return mAH.Short()
}

func (mAH *MatchAH) LongArgs() []string {
	return mAH.ShortArgs()
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

func newMatchBPF(opts ...OptionMatchBPF) (*MatchBPF, error) {
	match := &MatchBPF{
		baseMatch: &baseMatch{
			matchType: MatchTypeBPF,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// Non-numeric unsupported
type MatchBPF struct {
	*baseMatch
	BPF    []BPFSockFilter
	BPFRaw string
	Path   string
}

func (mBPF *MatchBPF) Short() string {
	return strings.Join(mBPF.ShortArgs(), " ")
}

func (mBPF *MatchBPF) ShortArgs() []string {
	args := make([]string, 0, 6)
	args = append(args, "-m", mBPF.matchType.String())
	if mBPF.Path != "" {
		args = append(args, "--object-pinned", mBPF.Path)
	}
	if mBPF.BPFRaw != "" {
		args = append(args, "--bytecode", mBPF.BPFRaw)
	}
	return args
}

func (mBPF *MatchBPF) Long() string {
	return mBPF.Short()
}

func (mBPF *MatchBPF) LongArgs() []string {
	return mBPF.ShortArgs()
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
func WithMatchCGroupClassID(invert bool, classid int) OptionMatchCGroup {
	return func(mCGroup *MatchCGroup) {
		mCGroup.ClassID = classid
		mCGroup.ClassIDInvert = invert
	}
}

// Match cgroup2 membership.
func WithMatchCGroupPath(invert bool, path string) OptionMatchCGroup {
	return func(mCGroup *MatchCGroup) {
		mCGroup.Path = path
		mCGroup.PathInvert = invert
	}
}

func newMatchCGroup(opts ...OptionMatchCGroup) (*MatchCGroup, error) {
	match := &MatchCGroup{
		baseMatch: &baseMatch{
			matchType: MatchTypeCGroup,
		},
		ClassID: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// Non-numeric unsupported
type MatchCGroup struct {
	*baseMatch
	Path    string
	ClassID int
	// invert
	PathInvert    bool
	ClassIDInvert bool
}

func (mCG *MatchCGroup) Short() string {
	return strings.Join(mCG.ShortArgs(), " ")
}

func (mCG *MatchCGroup) ShortArgs() []string {
	args := make([]string, 0, 8)
	args = append(args, "-m", mCG.matchType.String())
	if mCG.ClassID > -1 {
		if mCG.ClassIDInvert {
			args = append(args, "!")
		}
		args = append(args, "--cgroup", strconv.Itoa(mCG.ClassID))
	}
	if mCG.Path != "" {
		if mCG.PathInvert {
			args = append(args, "!")
		}
		args = append(args, "--path", mCG.Path)
	}
	return args
}

func (mCG *MatchCGroup) Long() string {
	return mCG.Short()
}

func (mCG *MatchCGroup) LongArgs() []string {
	return mCG.ShortArgs()
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
func WithMatchClusterLocalNode(localNode int64) OptionMatchCluster {
	return func(mCluster *MatchCluster) {
		mCluster.LocalNodeMask = localNode
	}
}

// Set the local node number ID mask.
func WithMatchClusterLocalNodeMask(mask int64) OptionMatchCluster {
	return func(mCluster *MatchCluster) {
		mCluster.LocalNodeMask = mask
	}
}

// Set seed value of the Jenkins hash.
func WithMatchClusterHashSeed(seed int64) OptionMatchCluster {
	return func(mCluster *MatchCluster) {
		mCluster.HashSeed = seed
	}
}

func newMatchCluster(opts ...OptionMatchCluster) (*MatchCluster, error) {
	match := &MatchCluster{
		baseMatch: &baseMatch{
			matchType: MatchTypeCluster,
		},
		TotalNodes:    -1,
		LocalNodeMask: -1,
		HashSeed:      -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// Non-numeric unsupported
type MatchCluster struct {
	*baseMatch
	TotalNodes    int
	LocalNodeMask int64
	HashSeed      int64
}

func (mCluster *MatchCluster) Short() string {
	return strings.Join(mCluster.ShortArgs(), " ")
}

func (mCluster *MatchCluster) ShortArgs() []string {
	args := make([]string, 0, 9)
	args = append(args, "-m", mCluster.matchType.String())
	if mCluster.TotalNodes > -1 {
		args = append(args, "--cluster-total-nodes",
			strconv.Itoa(mCluster.TotalNodes))
	}
	if mCluster.LocalNodeMask > -1 {
		if mCluster.invert {
			args = append(args, "!")
		}
		args = append(args, "--cluster-local-nodemask",
			strconv.FormatInt(mCluster.LocalNodeMask, 10))
	}
	if mCluster.HashSeed > -1 {
		args = append(args, "--cluster-hash-seed",
			strconv.FormatInt(mCluster.HashSeed, 10))
	}
	return args
}

func (mCluster *MatchCluster) Long() string {
	return mCluster.Short()
}

func (mCluster *MatchCluster) LongArgs() []string {
	return mCluster.ShortArgs()
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
		mask, err := strconv.ParseInt(string(matches[2]), 16, 64)
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
		seed, err := strconv.ParseInt(string(matches[4]), 16, 54)
		if err != nil {
			return 0, false
		}
		mCluster.HashSeed = seed
	}
	return len(matches[0]), true
}

func newMatchComment(comment string) (*MatchComment, error) {
	match := &MatchComment{
		baseMatch: &baseMatch{
			matchType: MatchTypeComment,
		},
		Comment: comment,
	}
	return match, nil
}

// Non-numeric unsupported
type MatchComment struct {
	*baseMatch
	Comment string
}

func (mComment *MatchComment) ShortArgs() []string {
	args := make([]string, 0, 4)
	args = append(args, "-m", mComment.matchType.String())
	if mComment.Comment != "" {
		args = append(args, "--comment", mComment.Comment)
	}
	return args
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
func WithMatchConnBytes(invert bool, bytes ...int64) OptionMatchConnBytes {
	return func(mConnBytes *MatchConnBytes) {
		switch len(bytes) {
		case 1:
			mConnBytes.From = bytes[0]
			mConnBytes.To = -1
		case 2:
			mConnBytes.From = bytes[0]
			mConnBytes.To = bytes[1]
		}
		mConnBytes.invert = invert
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

func newMatchConnBytes(opts ...OptionMatchConnBytes) (*MatchConnBytes, error) {
	match := &MatchConnBytes{
		baseMatch: &baseMatch{
			matchType: MatchTypeConnBytes,
		},
		From:      -1,
		To:        -1,
		Direction: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// Non-numeric unsupported
type MatchConnBytes struct {
	*baseMatch
	From      int64
	To        int64
	Mode      ConnBytesMode
	Direction ConnTrackDir
}

func (mConnBytes *MatchConnBytes) Short() string {
	return strings.Join(mConnBytes.ShortArgs(), " ")
}

func (mConnBytes *MatchConnBytes) ShortArgs() []string {
	args := make([]string, 0, 10)
	args = append(args, "-m", mConnBytes.matchType.String())
	if mConnBytes.From > -1 {
		if mConnBytes.invert {
			args = append(args, "!")
		}
		args = append(args, "--connbytes", strconv.FormatInt(mConnBytes.From, 10))
		if mConnBytes.To > -1 {
			args = append(args, ":"+strconv.FormatInt(mConnBytes.To, 10))
		}
	}
	if mConnBytes.Mode != "" {
		args = append(args, "--connbytes-mode", string(mConnBytes.Mode))
	}
	if mConnBytes.Direction > -1 {
		args = append(args, "--connbytes-dir", mConnBytes.Direction.String())
	}
	return args
}

func (mConnBytes *MatchConnBytes) Long() string {
	return mConnBytes.Short()
}

func (mConnBytes *MatchConnBytes) LongArgs() []string {
	return mConnBytes.ShortArgs()
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
func WithMatchConnLabel(invert bool, label int) OptionMatchConnLabel {
	return func(mConnLabel *MatchConnLabel) {
		mConnLabel.Label = label
		mConnLabel.invert = invert
	}
}

// Matches if label name has been set on a connection.
func WithMatchConnLabelName(invert bool, name string) OptionMatchConnLabel {
	return func(mConnLabel *MatchConnLabel) {
		mConnLabel.LabelName = name
		mConnLabel.invert = invert
	}
}

// If the label has not been set on the connection, set it.
func WithMatchConnLabelSet() OptionMatchConnLabel {
	return func(mConnLabel *MatchConnLabel) {
		mConnLabel.Set = true
	}
}

func newMatchConnLabel(opts ...OptionMatchConnLabel) (*MatchConnLabel, error) {
	match := &MatchConnLabel{
		baseMatch: &baseMatch{
			matchType: MatchTypeConnLabel,
		},
		Label: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// Numeric unsupported
type MatchConnLabel struct {
	*baseMatch
	Label     int
	LabelName string
	Set       bool
}

func (mConnLabel *MatchConnLabel) Short() string {
	return strings.Join(mConnLabel.ShortArgs(), " ")
}

func (mConnLabel *MatchConnLabel) ShortArgs() []string {
	args := make([]string, 0, 6)
	args = append(args, "-m", mConnLabel.matchType.String())
	if mConnLabel.Label > -1 {
		if mConnLabel.invert {
			args = append(args, "!")
		}
		args = append(args, "--label", strconv.Itoa(mConnLabel.Label))
	} else if mConnLabel.LabelName != "" {
		if mConnLabel.invert {
			args = append(args, "!")
		}
		args = append(args, "--label", mConnLabel.LabelName)
	}
	if mConnLabel.Set {
		args = append(args, "--set")
	}
	return args
}

func (mConnLabel *MatchConnLabel) Long() string {
	return mConnLabel.Short()
}

func (mConnLabel *MatchConnLabel) LongArgs() []string {
	return mConnLabel.ShortArgs()
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

func newMatchConnLimit(opts ...OptionMatchConnLimit) (*MatchConnLimit, error) {
	match := &MatchConnLimit{
		baseMatch: &baseMatch{
			matchType: MatchTypeConnLimit,
		},
		Upto:  -1,
		Above: -1,
		Mask:  -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// Non-numeric unsupported
type MatchConnLimit struct {
	*baseMatch
	Upto  int
	Above int
	Mask  int
	Src   bool
	Dst   bool
}

func (mConnLimit *MatchConnLimit) Short() string {
	return strings.Join(mConnLimit.ShortArgs(), " ")
}

func (mConnLimit *MatchConnLimit) ShortArgs() []string {
	args := make([]string, 0, 10)
	args = append(args, "-m", mConnLimit.matchType.String())
	if mConnLimit.Upto > -1 {
		args = append(args, "--connlimit-upto", strconv.Itoa(mConnLimit.Upto))
	}
	if mConnLimit.Above > -1 {
		args = append(args, "--connlimit-above", strconv.Itoa(mConnLimit.Above))
	}
	if mConnLimit.Mask > -1 {
		args = append(args, "--connlimit-mask", strconv.Itoa(mConnLimit.Mask))
	}
	if mConnLimit.Src {
		args = append(args, "--connlimit-saddr")
	}
	if mConnLimit.Dst {
		args = append(args, "--connlimit-daddr")
	}
	return args
}

func (mConnLimit *MatchConnLimit) Long() string {
	return strings.Join(mConnLimit.ShortArgs(), " ")
}

func (mConnLimit *MatchConnLimit) LongArgs() []string {
	return mConnLimit.ShortArgs()
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

// Takes mostly 2 values, (mark) or (mark, mask)
// Matches packets in connections with the given mark value.
// If a mask is specified, this is logically ANDed with the mark before the comparison.
func newMatchConnMark(invert bool, value ...int) (*MatchConnMark, error) {
	mConnMark := &MatchConnMark{
		baseMatch: &baseMatch{
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
	mConnMark.invert = invert
	return mConnMark, nil
}

// Non-numeric unsupported
type MatchConnMark struct {
	*baseMatch
	Value int
	Mask  int
}

func (mConnMark *MatchConnMark) Short() string {
	return strings.Join(mConnMark.ShortArgs(), " ")
}

func (mConnMark *MatchConnMark) ShortArgs() []string {
	args := make([]string, 0, 6)
	args = append(args, "-m", mConnMark.matchType.String())
	if mConnMark.Value > -1 {
		if mConnMark.invert {
			args = append(args, "!")
		}
		if mConnMark.Mask > -1 {
			args = append(args, "--mark",
				strconv.Itoa(mConnMark.Value)+"/"+strconv.Itoa(mConnMark.Mask))
		} else {
			args = append(args, "--mark", strconv.Itoa(mConnMark.Value))
		}
	}
	return args
}

func (mConnMark *MatchConnMark) Long() string {
	return mConnMark.Short()
}

func (mConnMark *MatchConnMark) LongArgs() []string {
	return mConnMark.ShortArgs()
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

func (connTrackState ConnTrackState) String() string {
	switch connTrackState {
	case INVALID:
		return CTStateINVALID
	case NEW:
		return CTStateNEW
	case ESTABLISHED:
		return CTStateESTABLISHED
	case UNTRACKED:
		return CTStateUNTRACKED
	case SNAT:
		return CTStateSNAT
	case DNAT:
		return CTStateDNAT
	}
	return ""
}

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

func (connTrackStatus ConnTrackStatus) String() string {
	switch connTrackStatus {
	case NONE:
		return CTStatusNONE
	case EXPECTED:
		return CTStatusEXPECTED
	case SEEN_REPLY:
		return CTStatusSEEN_REPLY
	case ASSURED:
		return CTStatusASSURED
	case CONFIRMED:
		return CTStatusCONFIRMED
	}
	return ""
}

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

func (connTrack ConnTrackDir) String() string {
	switch connTrack {
	case ORIGINAL:
		return CTDirOriginal
	case REPLY:
		return CTDirReply
	case BOTH:
		return CTDirBoth
	}
	return ""
}

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
func WithMatchConnTrackProtocol(proto network.Protocol) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		mConnTrack.Proto = proto
	}
}

func WithMatchConnTrackOriginSrc(invert bool, addr *net.IPNet) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		addr, _ := network.ParseAddress(addr)
		mConnTrack.OrigSrc = addr
		mConnTrack.OrigSrcInvert = invert
	}
}

func WithMatchConnTrackOriginDst(invert bool, addr *net.IPNet) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		addr, _ := network.ParseAddress(addr)
		mConnTrack.OrigDst = addr
		mConnTrack.OrigDstInvert = invert
	}
}

func WithMatchConnTrackReplySrc(invert bool, addr *net.IPNet) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		addr, _ := network.ParseAddress(addr)
		mConnTrack.ReplSrc = addr
		mConnTrack.ReplSrcInvert = invert
	}
}

func WithMatchConnTrackReplyDst(invert bool, addr *net.IPNet) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		addr, _ := network.ParseAddress(addr)
		mConnTrack.ReplDst = addr
		mConnTrack.ReplDstInvert = invert
	}
}

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchConnTrackOriginSrcPort(invert bool, port ...int) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		switch len(port) {
		case 1:
			mConnTrack.OrigSrcPortMin = port[0]
			mConnTrack.OrigSrcPortMax = -1
		case 2:
			mConnTrack.OrigSrcPortMin = port[0]
			mConnTrack.OrigSrcPortMax = port[1]
		}
		mConnTrack.OrigSrcPortInvert = invert
	}
}

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchConnTrackOriginDstPort(invert bool, port ...int) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		switch len(port) {
		case 1:
			mConnTrack.OrigDstPortMin = port[0]
			mConnTrack.OrigDstPortMax = -1
		case 2:
			mConnTrack.OrigDstPortMin = port[0]
			mConnTrack.OrigDstPortMax = port[1]
		}
		mConnTrack.OrigDstPortInvert = invert
	}
}

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchConnTrackReplySrcPort(invert bool, port ...int) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		switch len(port) {
		case 1:
			mConnTrack.ReplSrcPortMin = port[0]
			mConnTrack.ReplSrcPortMax = -1
		case 2:
			mConnTrack.ReplSrcPortMin = port[0]
			mConnTrack.ReplSrcPortMax = port[1]
		}
		mConnTrack.ReplSrcPortInvert = invert
	}
}

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchConnTrackReplyDstPort(invert bool, port ...int) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		switch len(port) {
		case 1:
			mConnTrack.ReplDstPortMin = port[0]
			mConnTrack.ReplDstPortMax = -1
		case 2:
			mConnTrack.ReplDstPortMin = port[0]
			mConnTrack.ReplDstPortMax = port[1]
		}
		mConnTrack.ReplDstPortInvert = invert
	}
}

func WithMatchConnTrackDirection(dir ConnTrackDir) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		mConnTrack.Direction = dir
	}
}

// This option takes mostly 2 time, (min) or (min, max)
func WithMatchConnTrackExpire(invert bool, time ...int) OptionMatchConnTrack {
	return func(mConnTrack *MatchConnTrack) {
		switch len(time) {
		case 1:
			mConnTrack.ExpireMin = time[0]
			mConnTrack.ExpireMax = -1
		case 2:
			mConnTrack.ExpireMin = time[0]
			mConnTrack.ExpireMax = time[1]
		}
		mConnTrack.ExpireInvert = invert

	}
}

func newMatchConnTrack(opts ...OptionMatchConnTrack) (*MatchConnTrack, error) {
	match := &MatchConnTrack{
		baseMatch: &baseMatch{
			matchType: MatchTypeConnTrack,
		},
		State:          -1,
		Status:         -1,
		Proto:          -1,
		Direction:      -1,
		OrigSrcPortMin: -1,
		OrigSrcPortMax: -1,
		OrigDstPortMin: -1,
		OrigDstPortMax: -1,
		ReplSrcPortMin: -1,
		ReplSrcPortMax: -1,
		ReplDstPortMin: -1,
		ReplDstPortMax: -1,
		ExpireMin:      -1,
		ExpireMax:      -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// Non-numeric supported
type MatchConnTrack struct {
	*baseMatch
	State          ConnTrackState
	Status         ConnTrackStatus
	Direction      ConnTrackDir
	Proto          network.Protocol
	OrigSrc        network.Address
	OrigDst        network.Address
	ReplSrc        network.Address
	ReplDst        network.Address
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
	// unused
	DirectionInvert bool
}

func (mConnTrack *MatchConnTrack) Short() string {
	return strings.Join(mConnTrack.ShortArgs(), " ")
}

func (mConnTrack *MatchConnTrack) ShortArgs() []string {
	args := make([]string, 0, 49)
	args = append(args, "-m", mConnTrack.matchType.String())
	if mConnTrack.State > -1 {
		if mConnTrack.StateInvert {
			args = append(args, "!")
		}
		args = append(args, "--ctstate", mConnTrack.State.String())
	}
	if mConnTrack.Status > -1 {
		if mConnTrack.StatusInvert {
			args = append(args, "!")
		}
		args = append(args, "--ctstatus", mConnTrack.Status.String())
	}
	if mConnTrack.Proto > -1 {
		if mConnTrack.ProtoInvert {
			args = append(args, "!")
		}
		args = append(args, "--ctproto", strconv.Itoa(int(mConnTrack.Proto)))
	}
	if mConnTrack.OrigSrc != nil {
		if mConnTrack.OrigSrcInvert {
			args = append(args, "!")
		}
		args = append(args, "--ctorigsrc", mConnTrack.OrigSrc.String())
	}
	if mConnTrack.OrigDst != nil {
		if mConnTrack.OrigDstInvert {
			args = append(args, "!")
		}
		args = append(args, "--ctorigdst", mConnTrack.OrigDst.String())
	}
	if mConnTrack.ReplSrc != nil {
		if mConnTrack.ReplSrcInvert {
			args = append(args, "!")
		}
		args = append(args, "--ctreplsrc", mConnTrack.ReplSrc.String())
	}
	if mConnTrack.ReplDst != nil {
		if mConnTrack.ReplDstInvert {
			args = append(args, "!")
		}
		args = append(args, "--ctrepldst", mConnTrack.ReplDst.String())
	}
	if mConnTrack.OrigSrcPortMin > -1 {
		if mConnTrack.OrigSrcPortInvert {
			args = append(args, "!")
		}
		if mConnTrack.OrigSrcPortMax > -1 {
			args = append(args, "--ctorigsrcport",
				strconv.Itoa(mConnTrack.OrigSrcPortMin)+":"+strconv.Itoa(mConnTrack.OrigSrcPortMax))
		} else {
			args = append(args, "--ctorigsrcport",
				strconv.Itoa(mConnTrack.OrigSrcPortMin))
		}
	}
	if mConnTrack.OrigDstPortMin > -1 {
		if mConnTrack.OrigDstPortInvert {
			args = append(args, "!")
		}
		if mConnTrack.OrigDstPortMax > -1 {
			args = append(args, "--ctorigdstport",
				strconv.Itoa(mConnTrack.OrigDstPortMin)+":"+strconv.Itoa(mConnTrack.OrigDstPortMax))
		} else {
			args = append(args, "--ctorigdstport", strconv.Itoa(mConnTrack.OrigDstPortMin))
		}
	}
	if mConnTrack.ReplSrcPortMin > -1 {
		if mConnTrack.ReplSrcPortInvert {
			args = append(args, "!")
		}
		if mConnTrack.ReplSrcPortMax > -1 {
			args = append(args, "--ctreplsrcport",
				strconv.Itoa(mConnTrack.ReplSrcPortMin)+":"+strconv.Itoa(mConnTrack.ReplSrcPortMax))
		} else {
			args = append(args, "--ctreplsrcport", strconv.Itoa(mConnTrack.ReplSrcPortMin))
		}
	}
	if mConnTrack.ReplDstPortMin > -1 {
		if mConnTrack.ReplDstPortInvert {
			args = append(args, "!")
		}
		if mConnTrack.ReplDstPortMax > -1 {
			args = append(args, "--ctrepldstport",
				strconv.Itoa(mConnTrack.ReplDstPortMin)+":"+strconv.Itoa(mConnTrack.ReplDstPortMax))
		} else {
			args = append(args, "--ctrepldstport", strconv.Itoa(mConnTrack.ReplDstPortMin))
		}
	}
	if mConnTrack.ExpireMin > -1 {
		if mConnTrack.ExpireInvert {
			args = append(args, "!")
		}
		if mConnTrack.ExpireMax > -1 {
			args = append(args, "--ctexpire",
				strconv.Itoa(mConnTrack.ExpireMin)+":"+strconv.Itoa(mConnTrack.ExpireMax))
		} else {
			args = append(args, "--ctexpire", strconv.Itoa(mConnTrack.ExpireMin))
		}
	}
	if mConnTrack.Direction > -1 {
		args = append(args, "--ctdir", mConnTrack.Direction.String())
	}
	return args
}

func (mConnTrack *MatchConnTrack) Long() string {
	return mConnTrack.Short()
}

func (mConnTrack *MatchConnTrack) LongArgs() []string {
	return mConnTrack.ShortArgs()
}

func (mConnTrack *MatchConnTrack) Parse(main []byte) (int, bool) {
	pattern :=
		`^(! )?(state|ctstate|ctproto|ctstatus|ctexpire|ctdir|` + // #1 #2
			`ctorigsrc|ctorigdst|ctreplsrc|ctrepldst|` +
			`ctorigsrcport|ctorigdstport|ctreplsrcport|ctrepldstport)` +
			` +` +
			`((REPLY|ORIGINAL)|` + // #3 #4
			`(([0-9A-Za-z:/.,-]+)?)) *` // #5 #6
	reg := regexp.MustCompile(pattern)
	index := 0
	for len(main) > 0 {
		matches := reg.FindSubmatch(main)
		if len(matches) != 7 {
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
			statesRow := string(matches[6])
			states := strings.Split(statesRow, ",")
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
			protoRow := string(matches[6])
			proto, err := strconv.Atoi(protoRow)
			if err != nil {
				goto END
			}
			mConnTrack.Proto = network.Protocol(proto)
			mConnTrack.ProtoInvert = invert

		case CTStatus:
			statusRow := string(matches[6])
			statuses := strings.Split(statusRow, ",")
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
			expiresRow := string(matches[6])
			expires := strings.Split(expiresRow, ":")
			if len(expires) == 2 {
				max, err := strconv.Atoi(expires[1])
				if err != nil {
					goto END
				}
				mConnTrack.ExpireMax = max
			}
			min, err := strconv.Atoi(expires[0])
			if err != nil {
				goto END
			}
			mConnTrack.ExpireMin = min
			mConnTrack.ExpireInvert = invert

		case CTDir:
			dir := string(matches[4])
			if dir == CTDirREPLY {
				mConnTrack.Direction = REPLY
			} else if dir == CTDirORIGINAL {
				mConnTrack.Direction = ORIGINAL
			} else {
				goto END
			}
			mConnTrack.DirectionInvert = invert

		case CTOrigSrc:
			src := string(matches[6])
			if src == "anywhere" {
				addr := network.NewIP(nil)
				addr.SetAnywhere(mConnTrack.addrType)
				mConnTrack.OrigSrc = addr
			} else {
				addr, err := network.ParseAddress(src)
				if err != nil {
					goto END
				}
				mConnTrack.OrigSrc = addr
			}
			mConnTrack.OrigSrcInvert = invert

		case CTOrigDst:
			dst := string(matches[6])
			if dst == "anywhere" {
				addr := network.NewIP(nil)
				addr.SetAnywhere(mConnTrack.addrType)
				mConnTrack.OrigSrc = addr
			} else {
				addr, err := network.ParseAddress(dst)
				if err != nil {
					goto END
				}
				mConnTrack.OrigDst = addr
			}
			mConnTrack.OrigDstInvert = invert

		case CTReplSrc:
			src := string(matches[6])
			if src == "anywhere" {
				addr := network.NewIP(nil)
				addr.SetAnywhere(mConnTrack.addrType)
				mConnTrack.OrigSrc = addr
			} else {
				addr, err := network.ParseAddress(src)
				if err != nil {
					goto END
				}
				mConnTrack.ReplSrc = addr
			}
			mConnTrack.ReplSrcInvert = invert

		case CTReplDst:
			dst := string(matches[6])
			if dst == "anywhere" {
				addr := network.NewIP(nil)
				addr.SetAnywhere(mConnTrack.addrType)
				mConnTrack.OrigSrc = addr
			} else {
				addr, err := network.ParseAddress(dst)
				if err != nil {
					goto END
				}
				mConnTrack.ReplDst = addr
			}
			mConnTrack.ReplDstInvert = invert

		case CTOrigSrcPort:
			portsRow := string(matches[6])
			ports := strings.Split(portsRow, ":")
			if len(ports) == 2 {
				max, err := strconv.Atoi(ports[1])
				if err != nil {
					goto END
				}
				mConnTrack.OrigSrcPortMax = max
			}
			min, err := strconv.Atoi(ports[0])
			if err != nil {
				goto END
			}
			mConnTrack.OrigSrcPortMin = min
			mConnTrack.OrigSrcPortInvert = invert

		case CTOrigDstPort:
			portsRow := string(matches[6])
			ports := strings.Split(portsRow, ":")
			if len(ports) == 2 {
				max, err := strconv.Atoi(ports[1])
				if err != nil {
					goto END
				}
				mConnTrack.OrigDstPortMax = max
			}
			min, err := strconv.Atoi(ports[0])
			if err != nil {
				goto END
			}
			mConnTrack.OrigDstPortMin = min
			mConnTrack.OrigDstPortInvert = invert

		case CTReplSrcPort:
			portsRow := string(matches[6])
			ports := strings.Split(portsRow, ":")
			if len(ports) == 2 {
				max, err := strconv.Atoi(ports[1])
				if err != nil {
					goto END
				}
				mConnTrack.ReplSrcPortMax = max
			}
			min, err := strconv.Atoi(ports[0])
			if err != nil {
				goto END
			}
			mConnTrack.ReplSrcPortMin = min
			mConnTrack.ReplSrcPortInvert = invert

		case CTReplDstPort:
			portsRow := string(matches[6])
			ports := strings.Split(portsRow, ":")
			if len(ports) == 2 {
				max, err := strconv.Atoi(ports[1])
				if err != nil {
					goto END
				}
				mConnTrack.ReplDstPortMax = max
			}
			min, err := strconv.Atoi(ports[0])
			if err != nil {
				goto END
			}
			mConnTrack.ReplDstPortMin = min
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
func newMatchCPU(invert bool, cpu int) (*MatchCPU, error) {
	mCPU := &MatchCPU{
		baseMatch: &baseMatch{
			matchType: MatchTypeCPU,
			invert:    invert,
		},
		CPU: cpu,
	}
	return mCPU, nil
}

// Non-numeric unsupport
type MatchCPU struct {
	*baseMatch
	CPU int
}

func (mCPU *MatchCPU) Short() string {
	return strings.Join(mCPU.ShortArgs(), " ")
}

func (mCPU *MatchCPU) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mCPU.matchType.String())
	if mCPU.invert {
		args = append(args, "!")
	}
	args = append(args, "--cpu", strconv.Itoa(mCPU.CPU))
	return args
}

func (mCPU *MatchCPU) Long() string {
	return mCPU.Short()
}

func (mCPU *MatchCPU) LongArgs() []string {
	return mCPU.ShortArgs()
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

func (dccpType DCCPType) String() string {
	switch dccpType {
	case DCCPTypeREQUEST:
		return "REQUEST"
	case DCCPTypeRESPONSE:
		return "RESPONSE"
	case DCCPTypeDATA:
		return "DATA"
	case DCCPTypeACK:
		return "ACK"
	case DCCPTypeDATAACK:
		return "DATAACK"
	case DCCPTypeCLOSEREQ:
		return "CLOSEREQ"
	case DCCPTypeCLOSE:
		return "CLOSE"
	case DCCPTypeRESET:
		return "RESET"
	case DCCPTypeSYNC:
		return "SYNC"
	case DCCPTypeSYNCACK:
		return "SYNCACK"
	case DCCPTypeINVALID:
		return "INVALID"
	}
	return ""
}

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
func WithMatchDCCPSrcPort(invert bool, port ...int) OptionMatchDCCP {
	return func(mDCCP *MatchDCCP) {
		switch len(port) {
		case 1:
			mDCCP.SrcPortMin = port[0]
			mDCCP.SrcPortMax = -1
		case 2:
			mDCCP.SrcPortMin = port[0]
			mDCCP.SrcPortMax = port[1]
		}
		mDCCP.SrcPortInvert = invert
	}
}

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchDCCPDstPort(invert bool, port ...int) OptionMatchDCCP {
	return func(mDCCP *MatchDCCP) {
		switch len(port) {
		case 1:
			mDCCP.DstPortMin = port[0]
			mDCCP.DstPortMax = -1
		case 2:
			mDCCP.DstPortMin = port[0]
			mDCCP.DstPortMax = port[1]
		}
		mDCCP.DstPortInvert = invert
	}
}

// Match when the DCCP packet type in types.
func WithMatchDCCPMask(invert bool, types ...DCCPType) OptionMatchDCCP {
	return func(mDCCP *MatchDCCP) {
		for _, typ := range types {
			mDCCP.DCCPType |= typ
		}
		mDCCP.TypeInvert = invert
	}
}

// Match if DCCP option set.
func WithMatchDCCOption(invert bool, option int) OptionMatchDCCP {
	return func(mDCCP *MatchDCCP) {
		mDCCP.Option = option
		mDCCP.OptionInvert = invert
	}
}

func newMatchDCCP(opts ...OptionMatchDCCP) (*MatchDCCP, error) {
	match := &MatchDCCP{
		baseMatch: &baseMatch{
			matchType: MatchTypeDCCP,
		},
		SrcPortMin: -1,
		SrcPortMax: -1,
		DstPortMin: -1,
		DstPortMax: -1,
		DCCPType:   -1,
		Option:     -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// Non-numeric support
type MatchDCCP struct {
	*baseMatch
	SrcPortMin int
	SrcPortMax int
	DstPortMin int
	DstPortMax int
	DCCPType   DCCPType
	Option     int
	// invert
	SrcPortInvert bool
	DstPortInvert bool
	TypeInvert    bool
	OptionInvert  bool
}

func (mDCCP *MatchDCCP) Short() string {
	return strings.Join(mDCCP.ShortArgs(), " ")
}

func (mDCCP *MatchDCCP) ShortArgs() []string {
	args := make([]string, 0, 16)
	args = append(args, "-m", mDCCP.matchType.String())
	if mDCCP.SrcPortMin > -1 {
		if mDCCP.SrcPortInvert {
			args = append(args, "!")
		}
		args = append(args, "--sport", strconv.Itoa(mDCCP.SrcPortMin))
		if mDCCP.SrcPortMax > -1 {
			args = append(args, ":"+strconv.Itoa(mDCCP.SrcPortMax))
		}
	}
	if mDCCP.DstPortMin > -1 {
		if mDCCP.DstPortInvert {
			args = append(args, "!")
		}
		args = append(args, "--dport", strconv.Itoa(mDCCP.DstPortMin))
		if mDCCP.DstPortMax > -1 {
			args = append(args, ":"+strconv.Itoa(mDCCP.DstPortMax))
		}
	}
	if mDCCP.DCCPType > -1 {
		if mDCCP.TypeInvert {
			args = append(args, "!")
		}
		args = append(args, "--dccp-types", mDCCP.DCCPType.String())
	}
	if mDCCP.Option > -1 {
		if mDCCP.OptionInvert {
			args = append(args, "!")
		}
		args = append(args, "--dccp-option", strconv.Itoa(mDCCP.Option))
	}
	return args
}

func (mDCCP *MatchDCCP) Long() string {
	return strings.Join(mDCCP.LongArgs(), " ")
}

func (mDCCP *MatchDCCP) LongArgs() []string {
	args := make([]string, 0, 16)
	args = append(args, "-m", mDCCP.matchType.String())
	if mDCCP.SrcPortMin > -1 {
		if mDCCP.SrcPortInvert {
			args = append(args, "!")
		}
		args = append(args, "--source-port", strconv.Itoa(mDCCP.SrcPortMin))
		if mDCCP.SrcPortMax > -1 {
			args = append(args, ":"+strconv.Itoa(mDCCP.SrcPortMax))
		}
	}
	if mDCCP.DstPortMin > -1 {
		if mDCCP.DstPortInvert {
			args = append(args, "!")
		}
		args = append(args, "--destination-port", strconv.Itoa(mDCCP.DstPortMin))
		if mDCCP.DstPortMax > -1 {
			args = append(args, ":"+strconv.Itoa(mDCCP.DstPortMax))
		}
	}
	if mDCCP.DCCPType > -1 {
		if mDCCP.TypeInvert {
			args = append(args, "!")
		}
		args = append(args, "--dccp-types", mDCCP.DCCPType.String())
	}
	if mDCCP.Option > -1 {
		if mDCCP.OptionInvert {
			args = append(args, "!")
		}
		args = append(args, "--dccp-option", strconv.Itoa(mDCCP.Option))
	}
	return args
}

// the service name may match patten '[0-9a-z/.*_+-]+'
func (mDCCP *MatchDCCP) Parse(main []byte) (int, bool) {
	// 1. "^dccp"
	// 2. "( spt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?" #1 #2 #3 #4 #5 #6 #7 #8
	// 3. "( dpt(:(!)?([0-9]+))?(s:(!)?([0-9]+):([0-9]+))?)?" #9 #10 #11 #12 #13 #14 #15 #16
	// 4. "(( !)? ([0-9,]+))?" #17 #18 #19
	// 5. "( option=(!)?([0-9]+))?" #20 #21 #22
	pattern := `^dccp` +
		`( spt(:(!)?([0-9]+))?(s:(!)?([0-9a-z/.*_+-]+):([0-9a-z/.*_+-]+))?)?` +
		`( dpt(:(!)?([0-9]+))?(s:(!)?([0-9a-z/.*_+-]+):([0-9a-z/.*_+-]+))?)?` +
		`(( !)? ([0-9a-z/.*_+-,]+))?` +
		`( option=(!)?([0-9]+))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 23 {
		return 0, false
	}
	if len(matches[4]) != 0 {
		sptRow := string(matches[4])
		spt, err := strconv.Atoi(sptRow)
		if err != nil {
			spt = network.GetPortByServiceAndProtocol(network.Service(sptRow), network.ProtocolDCCP)
			if spt == -1 {
				return 0, false
			}
		}
		mDCCP.SrcPortMin = spt
		if len(matches[3]) != 0 {
			mDCCP.SrcPortInvert = true
		}
	}
	if len(matches[7]) != 0 {
		minRow := string(matches[7])
		min, err := strconv.Atoi(minRow)
		if err != nil {
			min = network.GetPortByServiceAndProtocol(network.Service(minRow), network.ProtocolDCCP)
			if min == -1 {
				return 0, false
			}
		}
		maxRow := string(matches[8])
		max, err := strconv.Atoi(maxRow)
		if err != nil {
			max = network.GetPortByServiceAndProtocol(network.Service(maxRow), network.ProtocolDCCP)
			if max == -1 {
				return 0, false
			}
		}
		if len(matches[6]) != 0 {
			mDCCP.SrcPortInvert = true
		}
		mDCCP.SrcPortMin = min
		mDCCP.SrcPortMax = max
	}
	if len(matches[12]) != 0 {
		dptRow := string(matches[12])
		dpt, err := strconv.Atoi(dptRow)
		if err != nil {
			dpt = network.GetPortByServiceAndProtocol(network.Service(dptRow), network.ProtocolDCCP)
			if dpt == -1 {
				return 0, false
			}
		}
		mDCCP.DstPortMin = dpt
		if len(matches[11]) != 0 {
			mDCCP.DstPortInvert = true
		}
	}
	if len(matches[15]) != 0 {
		minRow := string(matches[15])
		min, err := strconv.Atoi(minRow)
		if err != nil {
			min = network.GetPortByServiceAndProtocol(network.Service(minRow), network.ProtocolDCCP)
			if min == -1 {
				return 0, false
			}
		}
		maxRow := string(matches[16])
		max, err := strconv.Atoi(maxRow)
		if err != nil {
			max = network.GetPortByServiceAndProtocol(network.Service(maxRow), network.ProtocolDCCP)
			if max == -1 {
				return 0, false
			}
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
				value, ok := DCCPTypes[elem]
				if !ok {
					return 0, false
				}
				mDCCP.DCCPType |= value
			} else {
				mDCCP.DCCPType |= 1 << typ
			}
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
func WithMatchDevGroupSrc(invert bool, src int64) OptionMatchDevGroup {
	return func(mDevGroup *MatchDevGroup) {
		mDevGroup.SrcGroup = src
		mDevGroup.SrcGroupInvert = invert
	}
}

// Match device group of outgoing device.
func WithMatchDevGroupDst(invert bool, dst int64) OptionMatchDevGroup {
	return func(mDevGroup *MatchDevGroup) {
		mDevGroup.DstGroup = dst
		mDevGroup.DstGroupInvert = invert
	}
}

func newMatchDevGroup(opts ...OptionMatchDevGroup) (*MatchDevGroup, error) {
	match := &MatchDevGroup{
		baseMatch: &baseMatch{
			matchType: MatchTypeDevGroup,
		},
		SrcGroup: -1,
		DstGroup: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchDevGroup struct {
	*baseMatch
	SrcGroup int64
	DstGroup int64
	// invert
	SrcGroupInvert bool
	DstGroupInvert bool
}

func (mDevGroup *MatchDevGroup) Short() string {
	return strings.Join(mDevGroup.ShortArgs(), " ")
}

func (mDevGroup *MatchDevGroup) ShortArgs() []string {
	args := make([]string, 0, 8)
	args = append(args, "-m", mDevGroup.matchType.String())
	if mDevGroup.SrcGroup > -1 {
		if mDevGroup.SrcGroupInvert {
			args = append(args, "!")
		}
		args = append(args, "--src-group",
			"0x"+strconv.FormatInt(mDevGroup.SrcGroup, 16))
	}
	if mDevGroup.DstGroup > -1 {
		if mDevGroup.DstGroupInvert {
			args = append(args, "!")
		}
		args = append(args, "--dst-group",
			"0x"+strconv.FormatInt(mDevGroup.DstGroup, 16))
	}
	return args
}

func (mDevGroup *MatchDevGroup) Long() string {
	return mDevGroup.Short()
}

func (mDevGroup *MatchDevGroup) LongArgs() []string {
	return mDevGroup.ShortArgs()
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
			group, err := strconv.ParseInt(string(matches[3]), 16, 64)
			if err != nil {
				goto END
			}
			mDevGroup.SrcGroup = group
			mDevGroup.SrcGroupInvert = invert
		case "dst-group":
			group, err := strconv.ParseInt(string(matches[3]), 16, 64)
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
func WithMatchDSCPValue(invert bool, value int) OptionMatchDSCP {
	return func(mDSCP *MatchDSCP) {
		mDSCP.Value = value
		mDSCP.invert = invert
	}
}

func WithMatchDSCPClass(invert bool, class DSCPClass) OptionMatchDSCP {
	return func(mDSCP *MatchDSCP) {
		mDSCP.Value = int(class)
		mDSCP.invert = invert
	}
}

func newMatchDSCP(opts ...OptionMatchDSCP) (*MatchDSCP, error) {
	match := &MatchDSCP{
		baseMatch: &baseMatch{
			matchType: MatchTypeDSCP,
		},
		Value: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchDSCP struct {
	*baseMatch
	Value int
}

func (mDSCP *MatchDSCP) Short() string {
	return strings.Join(mDSCP.ShortArgs(), " ")
}

func (mDSCP *MatchDSCP) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mDSCP.matchType.String())
	if mDSCP.Value > -1 {
		if mDSCP.invert {
			args = append(args, "!")
		}
		args = append(args, "--dscp", strconv.Itoa(mDSCP.Value))
	}
	return args
}

func (mDSCP *MatchDSCP) Long() string {
	return mDSCP.Short()
}

func (mDSCP *MatchDSCP) LongArgs() []string {
	return mDSCP.ShortArgs()
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
func WithMatchDstLen(invert bool, length int) OptionMatchDst {
	return func(mDst *MatchDst) {
		mDst.Length = length
		mDst.invert = invert
	}
}

// Numeric type of option and the length of the option data in octets.
func WithMatchDstOpts(opts ...network.IPv6Option) OptionMatchDst {
	return func(mDst *MatchDst) {
		mDst.Options = opts
	}
}

func newMatchDst(opts ...OptionMatchDst) (*MatchDst, error) {
	match := &MatchDst{
		baseMatch: &baseMatch{
			matchType: MatchTypeDst,
		},
		Length: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// IPv6 specific
// Non-numeric unsupport
type MatchDst struct {
	*baseMatch
	Length  int
	Options []network.IPv6Option
}

func (mDst *MatchDst) Short() string {
	return strings.Join(mDst.ShortArgs(), " ")
}

func (mDst *MatchDst) ShortArgs() []string {
	args := make([]string, 0, 7)
	args = append(args, "-m", mDst.matchType.String())
	if mDst.Length > -1 {
		if mDst.invert {
			args = append(args, "!")
		}
		args = append(args, "--dst-len", strconv.Itoa(mDst.Length))
	}
	if mDst.Options != nil && len(mDst.Options) != 0 {
		opts := ""
		sep := ""
		for _, opt := range mDst.Options {
			opts += sep + strconv.Itoa(opt.Type)
			if opt.Length > 0 {
				opts += ":" + strconv.Itoa(opt.Length)
			}
			sep = ","
		}
		args = append(args, "--dst-opts", opts)
	}
	return args
}

func (mDst *MatchDst) Long() string {
	return mDst.Short()
}

func (mDst *MatchDst) LongArgs() []string {
	return mDst.ShortArgs()
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
	mDst.Options = []network.IPv6Option{}
	if len(matches[5]) != 0 {
		elems := strings.Split(string(matches[5]), ",")
		for _, elem := range elems {
			opt := network.IPv6Option{
				Type:   -1,
				Length: -1,
			}
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
func WithMatchECNECE(invert bool) OptionMatchECN {
	return func(mECN *MatchECN) {
		mECN.ECE = true
		mECN.ECEInvert = invert
	}
}

// This matches if the TCP ECN CWR (Congestion Window Received) bit is set.
func WithMatchECNCWR(invert bool) OptionMatchECN {
	return func(mECN *MatchECN) {
		mECN.CWR = true
		mECN.CWRInvert = invert
	}
}

// This matches a particular IPv4/IPv6 ECT (ECN-Capable Transport).
// You have to specify a number between `0' and `3'.
func WithMatchECNECT(invert bool, ect int) OptionMatchECN {
	return func(mECN *MatchECN) {
		mECN.ECT = ect
		mECN.ECTInvert = invert
	}
}

func newMatchECN(opts ...OptionMatchECN) (*MatchECN, error) {
	match := &MatchECN{
		baseMatch: &baseMatch{
			matchType: MatchTypeECN,
		},
		ECT: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchECN struct {
	*baseMatch
	ECE       bool
	CWR       bool
	ECT       int
	ECEInvert bool
	CWRInvert bool
	ECTInvert bool
}

func (mECN *MatchECN) Short() string {
	return strings.Join(mECN.ShortArgs(), " ")
}

func (mECN *MatchECN) ShortArgs() []string {
	args := make([]string, 0, 9)
	args = append(args, "-m", mECN.matchType.String())
	if mECN.ECE {
		if mECN.ECEInvert {
			args = append(args, "!")
		}
		args = append(args, "--ecn-tcp-ece")
	}
	if mECN.CWR {
		if mECN.CWRInvert {
			args = append(args, "!")
		}
		args = append(args, "--ecn-tcp-cwr")
	}
	if mECN.ECT > -1 {
		if mECN.ECTInvert {
			args = append(args, "!")
		}
		args = append(args, "--ecn-tcp-ect", strconv.Itoa(mECN.ECT))
	}
	return args
}

func (mECN *MatchECN) Long() string {
	return mECN.Short()
}

func (mECN *MatchECN) LongArgs() []string {
	return mECN.ShortArgs()
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
func newMatchESP(invert bool, spi ...int) (*MatchESP, error) {
	match := &MatchESP{
		baseMatch: &baseMatch{
			matchType: MatchTypeESP,
		},
		SPIMin: -1,
		SPIMax: -1,
	}
	switch len(spi) {
	case 1:
		match.SPIMin = spi[0]
		match.SPIMax = -1
	case 2:
		match.SPIMin = spi[0]
		match.SPIMax = spi[1]
	}
	match.invert = invert
	return match, nil
}

type MatchESP struct {
	*baseMatch
	SPIMin int
	SPIMax int
}

func (mESP *MatchESP) Short() string {
	return strings.Join(mESP.ShortArgs(), " ")
}

func (mESP *MatchESP) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mESP.matchType.String())
	if mESP.SPIMin > -1 {
		if mESP.invert {
			args = append(args, "!")
		}
		if mESP.SPIMax > -1 {
			args = append(args, "--espspi",
				strconv.Itoa(mESP.SPIMin)+":"+strconv.Itoa(mESP.SPIMax))
		}
	}
	return args
}

func (mESP *MatchESP) Long() string {
	return mESP.Short()
}

func (mESP *MatchESP) LongArgs() []string {
	return mESP.ShortArgs()
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
func newMatchEUI64() (*MatchEUI64, error) {
	return &MatchEUI64{
		baseMatch: &baseMatch{
			matchType: MatchTypeEUI64,
		},
	}, nil
}

// IPv6 specific
// Non-numeric unsupport
type MatchEUI64 struct {
	*baseMatch
}

func (mEUI64 *MatchEUI64) Short() string {
	return strings.Join(mEUI64.ShortArgs(), " ")
}

func (mEUI64 *MatchEUI64) ShortArgs() []string {
	return []string{"-m", mEUI64.matchType.String()}
}

func (mEUI64 *MatchEUI64) Long() string {
	return mEUI64.Short()
}

func (mEUI64 *MatchEUI64) LongArgs() []string {
	return mEUI64.ShortArgs()
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
func WithMatchFragID(invert bool, id ...int) OptionMatchFrag {
	return func(mFrag *MatchFrag) {
		switch len(id) {
		case 1:
			mFrag.IDMin = id[0]
			mFrag.IDMax = -1
		case 2:
			mFrag.IDMin = id[0]
			mFrag.IDMax = id[1]
		}
		mFrag.IDInvert = invert
	}
}

// This option cannot be used with kernel version 2.6.10 or later.
// The length of Fragment header is static and this option doesn't make sense.
func WithMatchFragLen(invert bool, length int) OptionMatchFrag {
	return func(mFrag *MatchFrag) {
		mFrag.Length = length
		mFrag.LengthInvert = invert
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

func newMatchFrag(opts ...OptionMatchFrag) (*MatchFrag, error) {
	match := &MatchFrag{
		baseMatch: &baseMatch{
			matchType: MatchTypeFrag,
		},
		IDMin:  -1,
		IDMax:  -1,
		Length: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// IPv6 specific
// Non-numeric unsupport
type MatchFrag struct {
	*baseMatch
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

func (mFrag *MatchFrag) Short() string {
	return strings.Join(mFrag.ShortArgs(), " ")
}

func (mFrag *MatchFrag) ShortArgs() []string {
	args := make([]string, 0, 12)
	args = append(args, "-m", mFrag.matchType.String())
	if mFrag.IDMin > -1 {
		if mFrag.IDInvert {
			args = append(args, "!")
		}
		if mFrag.IDMax > -1 {
			args = append(args, "--fragid",
				strconv.Itoa(mFrag.IDMin)+":"+strconv.Itoa(mFrag.IDMax))
		} else {
			args = append(args, "--fragid", strconv.Itoa(mFrag.IDMin))
		}
	}
	return args
}

func (mFrag *MatchFrag) Long() string {
	return mFrag.Short()
}

func (mFrag *MatchFrag) LongArgs() []string {
	return mFrag.ShortArgs()
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
func WithMatchHashLimitUpto(rate xtables.Rate) OptionMatchHashLimit {
	return func(mHashLimit *MatchHashLimit) {
		mHashLimit.Avg = rate
	}
}

// Match if the rate is above amount/quantum.
func WithMatchHashLimitAbove(rate xtables.Rate) OptionMatchHashLimit {
	return func(mHashLimit *MatchHashLimit) {
		mHashLimit.Avg = rate
		mHashLimit.AvgInvert = true
	}
}

// Maximum initial number of packets to match:
// this number gets recharged by one every time the limit specified above is not reached,
// up to this number; the default is 5.
func WithMatchHashLimitBurst(burst int) OptionMatchHashLimit {
	return func(mHashLimit *MatchHashLimit) {
		mHashLimit.Burst = burst
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
		baseMatch: &baseMatch{
			matchType: MatchTypeHashLimit,
		},
		Burst:               -1,
		SrcMask:             -1,
		DstMask:             -1,
		HashtableSize:       -1,
		HashtableMax:        -1,
		HashtableGCInterval: -1,
		HashtableExpire:     -1,
		RateInterval:        -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type HashLimitMode uint8

func (hashLimitMode HashLimitMode) String() string {
	mode := ""
	sep := ""
	if (hashLimitMode & HashLimitModeSrcIP) != 0 {
		mode += sep + "srcip"
		sep = ","
	}
	if (hashLimitMode & HashLimitModeSrcPort) != 0 {
		mode += sep + "srcport"
		sep = ","
	}
	if (hashLimitMode & HashLimitModeDstIP) != 0 {
		mode += sep + "dstip"
		sep = ","
	}
	if (hashLimitMode & HashLimitModeDstPort) != 0 {
		mode += sep + "dstport"
	}
	return mode
}

const (
	HashLimitModeSrcIP HashLimitMode = 1 << iota
	HashLimitModeSrcPort
	HashLimitModeDstIP
	HashLimitModeDstPort
)

type MatchHashLimit struct {
	*baseMatch
	Avg                 xtables.Rate // <= avg
	Burst               int
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
	AvgInvert bool // > avg, true means above, false means upto
}

func (mHashLimit *MatchHashLimit) Short() string {
	return strings.Join(mHashLimit.ShortArgs(), " ")
}

func (mHashLimit *MatchHashLimit) ShortArgs() []string {
	args := make([]string, 0, 27)
	args = append(args, "-m", mHashLimit.matchType.String())
	if (mHashLimit.Avg != xtables.Rate{}) {
		if mHashLimit.AvgInvert {
			args = append(args, "--hashlimit-above", mHashLimit.Avg.String())
		} else {
			args = append(args, "--hashlimit-upto", mHashLimit.Avg.String())
		}
	}
	if mHashLimit.Burst > -1 {
		args = append(args, "--hashlimit-burst", strconv.Itoa(mHashLimit.Burst))
	}
	if mHashLimit.Mode != 0 {
		args = append(args, "--hashlimit-mode", mHashLimit.Mode.String())
	}
	if mHashLimit.SrcMask > -1 {
		args = append(args, "--hashlimit-srcmask",
			strconv.Itoa(mHashLimit.SrcMask))
	}
	if mHashLimit.DstMask > -1 {
		args = append(args, "--hashlimit-dstmask",
			strconv.Itoa(mHashLimit.DstMask))
	}
	if mHashLimit.Name != "" {
		args = append(args, "--hashlimit-name", mHashLimit.Name)
	}
	if mHashLimit.HashtableSize > -1 {
		args = append(args, "--hashlimit-htable-size",
			strconv.Itoa(mHashLimit.HashtableSize))
	}
	if mHashLimit.HashtableMax > -1 {
		args = append(args, "--hashlimit-htable-max",
			strconv.Itoa(mHashLimit.HashtableMax))
	}
	if mHashLimit.HashtableExpire > -1 {
		args = append(args, "--hashlimit-htable-expire",
			strconv.Itoa(mHashLimit.HashtableExpire))
	}
	if mHashLimit.HashtableGCInterval > -1 {
		args = append(args, "--hashlimit-htable-interval",
			strconv.Itoa(mHashLimit.HashtableGCInterval))
	}
	if mHashLimit.RateInterval > -1 {
		args = append(args, "--hashlimit-rate-interval",
			strconv.Itoa(mHashLimit.RateInterval))
	}
	if mHashLimit.RateMatch {
		args = append(args, "--hashlimit-rate-match")
	}
	return args
}

func (mHashLimit *MatchHashLimit) Long() string {
	return mHashLimit.Short()
}

func (mHashLimit *MatchHashLimit) LongShort() []string {
	return mHashLimit.ShortArgs()
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
	unit := xtables.Unit(0)
	switch string(matches[3]) {
	case "sec":
		unit = xtables.Second
	case "min":
		unit = xtables.Minute
	case "hour":
		unit = xtables.Hour
	case "day":
		unit = xtables.Day
	case "bs":
		unit = xtables.BPS
	case "kb/s":
		unit = xtables.KBPS
	case "mb/s":
		unit = xtables.MBPS
	}
	mHashLimit.Avg = xtables.Rate{avg, unit}
	if len(matches[5]) != 0 {
		burst, err := strconv.Atoi(string(matches[5]))
		if err != nil {
			return 0, false
		}
		mHashLimit.Burst = burst
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
func WithMatchHBHLength(invert bool, length int) OptionMatchHBH {
	return func(mHBH *MatchHBH) {
		mHBH.Length = length
		mHBH.invert = invert
	}
}

// Numeric type of option and the length of the option data in octets.
func WithMatchHBHOpts(opts ...network.IPv6Option) OptionMatchHBH {
	return func(mHBH *MatchHBH) {
		mHBH.Options = opts
	}
}

func newMatchHBH(opts ...OptionMatchHBH) (*MatchHBH, error) {
	match := &MatchHBH{
		baseMatch: &baseMatch{
			matchType: MatchTypeHBH,
		},
		Length: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// IPv6 specific
// Non-numeric unsupport
type MatchHBH struct {
	*baseMatch
	Length  int
	Options []network.IPv6Option
}

func (mHBH *MatchHBH) Short() string {
	return strings.Join(mHBH.ShortArgs(), " ")
}

func (mHBH *MatchHBH) ShortArgs() []string {
	args := make([]string, 0, 7)
	args = append(args, "-m", mHBH.matchType.String())
	if mHBH.Length > -1 {
		if mHBH.invert {
			args = append(args, "!")
		}
		args = append(args, "--hbh-len", strconv.Itoa(mHBH.Length))
	}
	if mHBH.Options != nil && len(mHBH.Options) > 0 {
		opts := ""
		sep := ""
		for _, opt := range mHBH.Options {
			opts += sep + strconv.Itoa(opt.Type)
			if opt.Length > 0 {
				opts += ":" + strconv.Itoa(opt.Length)
			}
			sep = ","
		}
		args = append(args, "--hbh-opts", opts)
	}
	return args
}

func (mHBH *MatchHBH) Long() string {
	return mHBH.Short()
}

func (mHBH *MatchHBH) LongArgs() []string {
	return mHBH.ShortArgs()
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
	mHBH.Options = []network.IPv6Option{}
	if len(matches[5]) != 0 {
		elems := strings.Split(string(matches[5]), ",")
		for _, elem := range elems {
			opt := network.IPv6Option{}
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
func newMatchHelper(name string) (*MatchHelper, error) {
	mHelper := &MatchHelper{
		baseMatch: &baseMatch{
			matchType: MatchTypeHelper,
		},
		Name: name,
	}
	return mHelper, nil
}

type MatchHelper struct {
	*baseMatch
	Name string
}

func (mHelper *MatchHelper) Short() string {
	return strings.Join(mHelper.ShortArgs(), " ")
}

func (mHelper *MatchHelper) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mHelper.matchType.String())
	if mHelper.Name != "" {
		if mHelper.invert {
			args = append(args, "!")
		}
		args = append(args, "--helper", mHelper.Name)
	}
	return args
}

func (mHelper *MatchHelper) Long() string {
	return mHelper.Short()
}

func (mHelper *MatchHelper) LongArgs() []string {
	return mHelper.ShortArgs()
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
func newMatchHL(operator xtables.Operator, value int) (*MatchHL, error) {
	mHL := &MatchHL{
		baseMatch: &baseMatch{
			matchType: MatchTypeHL,
		},
		Operator: operator,
		Value:    value,
	}
	return mHL, nil
}

type MatchHL struct {
	*baseMatch
	Operator xtables.Operator
	Value    int
}

func (mHL *MatchHL) Short() string {
	return strings.Join(mHL.ShortArgs(), " ")
}

func (mHL *MatchHL) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mHL.matchType.String())
	switch mHL.Operator {
	case xtables.OperatorNE:
		args = append(args, "!", "--hl-eq", strconv.Itoa(mHL.Value))
	case xtables.OperatorEQ:
		args = append(args, "--hl-eq", strconv.Itoa(mHL.Value))
	case xtables.OperatorLT:
		args = append(args, "--hl-lt", strconv.Itoa(mHL.Value))
	case xtables.OperatorGT:
		args = append(args, "--hl-gt", strconv.Itoa(mHL.Value))
	}
	return args
}

func (mHL *MatchHL) Long() string {
	return mHL.Short()
}

func (mHL *MatchHL) LongArgs() []string {
	return mHL.ShortArgs()
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
		mHL.Operator = xtables.OperatorEQ
	case "!=":
		mHL.Operator = xtables.OperatorNE
	case "<":
		mHL.Operator = xtables.OperatorLT
	case ">":
		mHL.Operator = xtables.OperatorGT
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

func WithMatchICMPCode(code network.ICMPCode) OptionMatchICMP {
	return func(mICMP *MatchICMP) {
		mICMP.CodeMin = code
	}
}

func newMatchICMP(invert bool, typ network.ICMPType, opts ...OptionMatchICMP) (*MatchICMP, error) {
	match := &MatchICMP{
		ICMPType: typ,
		baseMatch: &baseMatch{
			matchType: MatchTypeICMP,
			invert:    invert,
		},
		CodeMin:    -1,
		CodeMax:    -1,
		typeString: "--icmp-type",
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// IPv6 and IPv4 specific
// Non-numeric support
type MatchICMP struct {
	*baseMatch
	ICMPType   network.ICMPType
	CodeMin    network.ICMPCode
	CodeMax    network.ICMPCode
	typeString string
}

func (mICMP *MatchICMP) Depends() []MatchType {
	return []MatchType{MatchTypeIPv4, MatchTypeIPv6}
}

func (mICMP *MatchICMP) Short() string {
	return strings.Join(mICMP.ShortArgs(), " ")
}

func (mICMP *MatchICMP) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mICMP.matchType.String())
	if mICMP.CodeMin > -1 {
		args = append(args, mICMP.typeString,
			strconv.Itoa(int(mICMP.ICMPType))+"/"+strconv.Itoa(int(mICMP.CodeMin)))
	} else {
		args = append(args, mICMP.typeString,
			strconv.Itoa(int(mICMP.ICMPType)))
	}
	return args
}

func (mICMP *MatchICMP) Long() string {
	return mICMP.Short()
}

func (mICMP *MatchICMP) LongArgs() []string {
	return mICMP.ShortArgs()
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
		mICMP.addrType = network.AddressTypeIPv6
	case "icmp":
		mICMP.addrType = network.AddressTypeIPv4
	}
	if len(matches[4]) != 0 {
		typ, err := strconv.Atoi(string(matches[4]))
		if err != nil {
			return 0, false
		}
		mICMP.ICMPType = network.ICMPType(typ)
		if len(matches[3]) != 0 {
			mICMP.invert = true
		}
	}
	if len(matches[7]) != 0 {
		code, err := strconv.Atoi(string(matches[7]))
		if err != nil {
			return 0, false
		}
		mICMP.CodeMin = network.ICMPCode(code)
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
		mICMP.CodeMin = network.ICMPCode(codeMin)
		mICMP.CodeMax = network.ICMPCode(codeMax)
	}
	if len(matches[13]) != 0 {
		str := string(matches[13])
		switch mICMP.addrType {
		case network.AddressTypeIPv4:
			typ, ok := network.ICMP4Types[str]
			if !ok {
				code, ok := network.ICMP4Codes[str]
				if !ok {
					return 0, false
				} else {
					mICMP.CodeMin = network.ICMPCode(code.Code)
					mICMP.ICMPType = network.ICMPType(code.Type)
				}
			} else {
				mICMP.ICMPType = network.ICMPType(typ)
			}
		case network.AddressTypeIPv6:
			typ, ok := network.ICMPv6TypeMap[str]
			if !ok {
				code, ok := network.ICMPv6Codes[str]
				if !ok {
					return 0, false
				} else {
					mICMP.CodeMin = network.ICMPCode(code.Code)
					mICMP.ICMPType = network.ICMPType(code.Type)
				}
			} else {
				mICMP.ICMPType = network.ICMPType(typ)
			}
		}
	}
	return len(matches[0]), true
}

type OptionMatchIPRange func(*MatchIPRange)

// This option takes mostly 2 ips, (min) or (min, max)
// Match source IP in the specified range.
func WithMatchIPRangeSrc(invert bool, ip ...net.IP) OptionMatchIPRange {
	return func(mIPRange *MatchIPRange) {
		switch len(ip) {
		case 1:
			mIPRange.SrcIPMin = ip[0]
		case 2:
			mIPRange.SrcIPMin = ip[0]
			mIPRange.SrcIPMax = ip[1]
		}
		mIPRange.SrcIPInvert = invert
	}
}

// This option takes mostly 2 ips, (min) or (min, max)
// Match destination IP in the specified range.
func WithMatchIPRangeDst(invert bool, ip ...net.IP) OptionMatchIPRange {
	return func(mIPRange *MatchIPRange) {
		switch len(ip) {
		case 1:
			mIPRange.DstIPMin = ip[0]
		case 2:
			mIPRange.DstIPMin = ip[0]
			mIPRange.DstIPMax = ip[1]
		}
		mIPRange.DstIPInvert = invert
	}
}

func newMatchIPRange(opts ...OptionMatchIPRange) (*MatchIPRange, error) {
	match := &MatchIPRange{
		baseMatch: &baseMatch{
			matchType: MatchTypeIPRange,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchIPRange struct {
	*baseMatch
	SrcIPMin    net.IP
	SrcIPMax    net.IP
	DstIPMin    net.IP
	DstIPMax    net.IP
	SrcIPInvert bool
	DstIPInvert bool
}

func (mIPRange *MatchIPRange) Short() string {
	return strings.Join(mIPRange.ShortArgs(), " ")
}

func (mIPRange *MatchIPRange) ShortArgs() []string {
	args := make([]string, 0, 8)
	args = append(args, "-m", mIPRange.matchType.String())
	if mIPRange.SrcIPMin != nil {
		if mIPRange.SrcIPInvert {
			args = append(args, "!")
		}
		if mIPRange.SrcIPMax != nil {
			args = append(args, "--src-range",
				mIPRange.SrcIPMin.String()+"-"+mIPRange.SrcIPMax.String())
		} else {
			args = append(args, "--src-range", mIPRange.SrcIPMin.String())
		}
	}
	if mIPRange.DstIPMin != nil {
		if mIPRange.DstIPInvert {
			args = append(args, "!")
		}
		if mIPRange.DstIPMax != nil {
			args = append(args, "--src-range",
				mIPRange.DstIPMin.String()+"-"+mIPRange.DstIPMax.String())
		} else {
			args = append(args, "--src-range", mIPRange.DstIPMin.String())
		}
	}
	return args
}

func (mIPRange *MatchIPRange) Long() string {
	return mIPRange.Short()
}

func (mIPRange *MatchIPRange) LongArgs() []string {
	return mIPRange.ShortArgs()
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
func WithMatchIPv6Header(headers ...network.IPv6HeaderType) OptionMatchIPv6Header {
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

func newMatchIPv6Header(opts ...OptionMatchIPv6Header) (*MatchIPv6Header, error) {
	match := &MatchIPv6Header{
		baseMatch: &baseMatch{
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
	*baseMatch
	Soft          bool
	IPHeaderTypes []network.IPv6HeaderType
}

func (mIPv6 *MatchIPv6Header) Short() string {
	return strings.Join(mIPv6.ShortArgs(), " ")
}

func (mIPv6 *MatchIPv6Header) ShortArgs() []string {
	args := make([]string, 0, 6)
	args = append(args, "-m", mIPv6.matchType.String())
	if mIPv6.Soft {
		args = append(args, "--soft")
	}
	if mIPv6.IPHeaderTypes != nil && len(mIPv6.IPHeaderTypes) != 0 {
		opts := ""
		sep := ""
		for _, head := range mIPv6.IPHeaderTypes {
			opts += sep + head.String()
			sep = ","
		}
		args = append(args, "--header", opts)
	}
	return args
}

func (mIPv6 *MatchIPv6Header) Long() string {
	return mIPv6.Short()
}

func (mIPv6 *MatchIPv6Header) LongArgs() []string {
	return mIPv6.ShortArgs()
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
	mIPv6.IPHeaderTypes = []network.IPv6HeaderType{}
	// 0x02X
	if len(matches[4]) != 0 {
		hex, err := strconv.ParseUint(string(matches[4]), 16, 8)
		if err != nil {
			return 0, false
		}
		hex8 := uint8(hex)
		for hex8 != 0 {
			for _, mask := range network.IPv6HeaderTypeMasks {
				v, _ := network.IPv6HeaderTypeMaskMap[mask]
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
			typ, ok := network.IPv6HeaderTypes[elem]
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

func (ipvsMethod IPVSMethod) String() string {
	switch ipvsMethod {
	case GATE:
		return IPVSGATE
	case IPIP:
		return IPVSIPIP
	case MASQ:
		return IPVSMASQ
	case UNKNOWN:
		return IPVSUNKNOWN
	default:
		return ""
	}
}

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
func WithMatchIPVS(invert bool) OptionMatchIPVS {
	return func(mIPVS *MatchIPVS) {
		mIPVS.IPVS = invert
	}
}

// VIP protocol to match.
func WithMatchVProto(invert bool, proto network.Protocol) OptionMatchIPVS {
	return func(mIPVS *MatchIPVS) {
		mIPVS.VProto = proto
		mIPVS.VProtoInvert = invert
	}
}

// VIP address to match.
func WithMatchVAddr(invert bool, addr network.Address) OptionMatchIPVS {
	return func(mIPVS *MatchIPVS) {
		mIPVS.VAddr = addr
		mIPVS.VAddrInvert = invert
	}
}

//  VIP port to match.
func WithMatchVPort(invert bool, port int) OptionMatchIPVS {
	return func(mIPVS *MatchIPVS) {
		mIPVS.VPort = port
		mIPVS.VPortInvert = invert
	}
}

// Flow direction of packet
func WithMatchVDir(dir ConnTrackDir) OptionMatchIPVS {
	return func(mIPVS *MatchIPVS) {
		mIPVS.VDir = dir
	}
}

// IPVS forwarding method used.
func WithMatchVMethod(invert bool, method IPVSMethod) OptionMatchIPVS {
	return func(mIPVS *MatchIPVS) {
		mIPVS.VMethod = method
		mIPVS.VMethodInvert = invert
	}
}

// VIP port of the controlling connection to match.
func WithMatchVPortCtl(invert bool, portCtl int) OptionMatchIPVS {
	return func(mIPVS *MatchIPVS) {
		mIPVS.VPortCtl = portCtl
		mIPVS.VPortCtlInvert = invert
	}
}

func newMatchIPVS(opts ...OptionMatchIPVS) (*MatchIPVS, error) {
	match := &MatchIPVS{
		baseMatch: &baseMatch{
			matchType: MatchTypeIPVS,
		},
		VProto:   -1,
		VPort:    -1,
		VDir:     -1,
		VMethod:  -1,
		VPortCtl: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchIPVS struct {
	*baseMatch
	IPVS     bool
	VProto   network.Protocol
	VAddr    network.Address
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

func (mIPVS *MatchIPVS) Short() string {
	return strings.Join(mIPVS.ShortArgs(), " ")
}

func (mIPVS *MatchIPVS) ShortArgs() []string {
	args := make([]string, 0, 19)
	args = append(args, "-m", mIPVS.matchType.String())
	if mIPVS.IPVS {
		if mIPVS.IPVSInvert {
			args = append(args, "!")
		}
		args = append(args, "--ipvs")
	}
	if mIPVS.VProto > -1 {
		if mIPVS.VProtoInvert {
			args = append(args, "!")
		}
		args = append(args, "--vproto", strconv.Itoa(int(mIPVS.VProto)))
	}
	if mIPVS.VAddr != nil {
		if mIPVS.VAddrInvert {
			args = append(args, "!")
		}
		args = append(args, "--vaddr", mIPVS.VAddr.String())
	}
	if mIPVS.VPort > -1 {
		if mIPVS.VPortInvert {
			args = append(args, "!")
		}
		args = append(args, "--vport", strconv.Itoa(int(mIPVS.VPort)))
	}
	if mIPVS.VDir > -1 {
		args = append(args, "--vdir", mIPVS.VDir.String())
	}
	if mIPVS.VMethod > -1 {
		if mIPVS.VMethodInvert {
			args = append(args, "!")
		}
		args = append(args, "--vmethod", mIPVS.VMethod.String())
	}
	if mIPVS.VPortCtl > -1 {
		if mIPVS.VPortCtlInvert {
			args = append(args, "!")
		}
		args = append(args, "--vportctl", strconv.Itoa(int(mIPVS.VPortCtl)))
	}
	return args
}

func (mIPVS *MatchIPVS) Long() string {
	return mIPVS.Short()
}

func (mIPVS *MatchIPVS) LongArgs() []string {
	return mIPVS.ShortArgs()
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
			mIPVS.VProto = network.Protocol(proto)
			mIPVS.VProtoInvert = invert
		case IPVSVAddr:
			vaddr := string(matches[4])
			addr, err := network.ParseAddress(vaddr)
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
func newMatchLength(invert bool, length ...int) (*MatchLength, error) {
	match := &MatchLength{
		baseMatch: &baseMatch{
			matchType: MatchTypeLength,
		},
		LengthMin: -1,
		LengthMax: -1,
	}
	switch len(length) {
	case 1:
		match.LengthMin = length[0]
		match.LengthMax = -1
	case 2:
		match.LengthMin = length[0]
		match.LengthMax = length[1]
	}
	match.invert = invert
	return match, nil
}

type MatchLength struct {
	*baseMatch
	LengthMin int
	LengthMax int
}

func (mLength *MatchLength) Short() string {
	return strings.Join(mLength.ShortArgs(), " ")
}

func (mLength *MatchLength) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mLength.matchType.String())
	if mLength.LengthMin > -1 {
		if mLength.invert {
			args = append(args, "!")
		}
		if mLength.LengthMax > -1 {
			args = append(args, "--length",
				strconv.Itoa(mLength.LengthMin)+":"+strconv.Itoa(mLength.LengthMax))
		} else {
			args = append(args, "--length", strconv.Itoa(mLength.LengthMin))
		}
	}
	return args
}

func (mLength *MatchLength) Long() string {
	return mLength.Short()
}

func (mLength *MatchLength) LongArgs() []string {
	return mLength.ShortArgs()
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
func WithMatchLimit(rate xtables.Rate) OptionMatchLimit {
	return func(mLimit *MatchLimit) {
		mLimit.Avg = rate
	}
}

// Maximum initial number of packets to match.
func WithMatchLimitBurst(burst int) OptionMatchLimit {
	return func(mLimit *MatchLimit) {
		mLimit.Burst = burst
	}
}

func newMatchLimit(opts ...OptionMatchLimit) (*MatchLimit, error) {
	match := &MatchLimit{
		baseMatch: &baseMatch{
			matchType: MatchTypeLimit,
		},
		Burst: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchLimit struct {
	*baseMatch
	Avg   xtables.Rate
	Burst int
}

func (mLimit *MatchLimit) Short() string {
	return strings.Join(mLimit.ShortArgs(), " ")
}

func (mLimit *MatchLimit) ShortArgs() []string {
	args := make([]string, 0, 6)
	args = append(args, "-m", mLimit.matchType.String())
	if (mLimit.Avg != xtables.Rate{}) {
		args = append(args, "--limit", mLimit.Avg.String())
	}
	if mLimit.Burst > -1 {
		args = append(args, "--limit-burst", strconv.Itoa(mLimit.Burst))
	}
	return args
}

func (mLimit *MatchLimit) Long() string {
	return mLimit.Short()
}

func (mLimit *MatchLimit) LongArgs() []string {
	return mLimit.ShortArgs()
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
	unit := xtables.Unit(0)
	switch string(matches[3]) {
	case "second":
		unit = xtables.Second
	case "minute":
		unit = xtables.Minute
	case "hour":
		unit = xtables.Hour
	case "day":
		unit = xtables.Day
	default:
		return 0, false
	}
	mLimit.Avg = xtables.Rate{
		avg, unit,
	}
	mLimit.Burst = burst
	return len(matches[0]), true
}

// Match source MAC address.
func newMatchMAC(invert bool, mac net.HardwareAddr) (*MatchMAC, error) {
	match := &MatchMAC{
		baseMatch: &baseMatch{
			matchType: MatchTypeMAC,
			invert:    invert,
		},
		SrcMac: mac,
	}
	return match, nil
}

type MatchMAC struct {
	*baseMatch
	SrcMac net.HardwareAddr
}

func (mMAC *MatchMAC) Short() string {
	return strings.Join(mMAC.ShortArgs(), " ")
}

func (mMAC *MatchMAC) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mMAC.matchType.String())
	if mMAC.SrcMac != nil {
		if mMAC.invert {
			args = append(args, "!")
		}
		args = append(args, "--mac-source", mMAC.SrcMac.String())
	}
	return args
}

func (mMAC *MatchMAC) Long() string {
	return mMAC.Short()
}

func (mMAC *MatchMAC) LongArgs() []string {
	return mMAC.ShortArgs()
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

// The argument value takes mostly 2 values, mark or mark/mask.
// Matches packets with the given unsigned mark value
func newMatchMark(invert bool, value ...int) (*MatchMark, error) {
	mMark := &MatchMark{
		baseMatch: &baseMatch{
			matchType: MatchTypeMark,
		},
		Value: -1,
		Mask:  -1,
	}
	switch len(value) {
	case 1:
		mMark.Value = value[0]
		mMark.Mask = -1
	case 2:
		mMark.Value = value[0]
		mMark.Mask = value[1]
	}
	mMark.invert = invert
	return mMark, nil
}

type MatchMark struct {
	*baseMatch
	Value int
	Mask  int
}

func (mMark *MatchMark) Short() string {
	return strings.Join(mMark.ShortArgs(), " ")
}

func (mMark *MatchMark) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mMark.matchType.String())
	if mMark.Value > -1 {
		if mMark.invert {
			args = append(args, "!")
		}
		if mMark.Mask > -1 {
			args = append(args, "--mark",
				strconv.Itoa(mMark.Value)+"/"+strconv.Itoa(mMark.Mask))
		} else {
			args = append(args, "--mark", strconv.Itoa(mMark.Value))
		}
	}
	return args
}

func (mMark *MatchMark) Long() string {
	return mMark.Short()
}

func (mMark *MatchMark) LongArgs() []string {
	return mMark.ShortArgs()
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

type MHType int

func (mhType MHType) String() string {
	switch mhType {
	case BRR:
		return "brr"
	case HOTI:
		return "hoti"
	case COTI:
		return "coti"
	case HOT:
		return "hot"
	case COT:
		return "cot"
	case BU:
		return "bu"
	case BA:
		return "ba"
	case BE:
		return "be"
	default:
		return ""
	}
}

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
func newMatchMH(invert bool, typ ...MHType) (*MatchMH, error) {
	match := &MatchMH{
		baseMatch: &baseMatch{
			matchType: MatchTypeMH,
			invert:    invert,
		},
		TypeMin: -1,
		TypeMax: -1,
	}
	switch len(typ) {
	case 1:
		match.TypeMin = typ[0]
	case 2:
		match.TypeMin = typ[0]
		match.TypeMax = typ[1]
	}
	return match, nil
}

// IPv6 specific
// Non-numeric support
type MatchMH struct {
	*baseMatch
	TypeMin MHType
	TypeMax MHType
}

func (mMH *MatchMH) Short() string {
	return strings.Join(mMH.ShortArgs(), " ")
}

func (mMH *MatchMH) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mMH.matchType.String())
	if mMH.TypeMin > -1 {
		if mMH.invert {
			args = append(args, "!")
		}
		if mMH.TypeMax > -1 {
			args = append(args, "--mh-type",
				mMH.TypeMin.String()+":", mMH.TypeMax.String())
		} else {
			args = append(args, "--mh-type", mMH.TypeMin.String())
		}
	}
	return args
}

func (mMH *MatchMH) Long() string {
	return mMH.Short()
}

func (mMH *MatchMH) LongArgs() []string {
	return mMH.ShortArgs()
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

type PortRange struct {
	Start int
	End   int
}

type OptionMatchMultiPort func(*MatchMultiPort)

// Match if the source port is one of the given ports.
func WithMatchMultiPortSrc(invert bool, ports ...PortRange) OptionMatchMultiPort {
	return func(mMultiPort *MatchMultiPort) {
		mMultiPort.SrcPorts = ports
		mMultiPort.invert = invert
	}
}

//  Match if the destination port is one of the given ports.
func WithMatchMultiPortDst(invert bool, ports ...PortRange) OptionMatchMultiPort {
	return func(mMultiPort *MatchMultiPort) {
		mMultiPort.DstPorts = ports
		mMultiPort.invert = invert
	}
}

// Match if either the source or destination ports are equal to one of the given ports.
func WithMatchMultiPort(invert bool, ports ...PortRange) OptionMatchMultiPort {
	return func(mMultiPort *MatchMultiPort) {
		mMultiPort.Ports = ports
		mMultiPort.invert = invert
	}
}

func newMatchMultiPort(opts ...OptionMatchMultiPort) (*MatchMultiPort, error) {
	match := &MatchMultiPort{
		baseMatch: &baseMatch{
			matchType: MatchTypeMultiPort,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchMultiPort struct {
	*baseMatch
	SrcPorts []PortRange
	DstPorts []PortRange
	Ports    []PortRange
}

func (mMultiPort *MatchMultiPort) Short() string {
	return strings.Join(mMultiPort.ShortArgs(), " ")
}

func (mMultiPort *MatchMultiPort) ShortArgs() []string {
	args := make([]string, 0, 11)
	args = append(args, "-m", mMultiPort.matchType.String())
	if mMultiPort.SrcPorts != nil && len(mMultiPort.SrcPorts) != 0 {
		ports := ""
		sep := ""
		for _, port := range mMultiPort.SrcPorts {
			ports += sep + strconv.Itoa(port.Start)
			if port.End > 0 {
				ports += ":" + strconv.Itoa(port.End)
			}
			sep = ","
		}
		args = append(args, "--sports", ports)
	}
	if mMultiPort.DstPorts != nil && len(mMultiPort.DstPorts) != 0 {
		ports := ""
		sep := ""
		for _, port := range mMultiPort.DstPorts {
			ports += sep + strconv.Itoa(port.Start)
			if port.End > 0 {
				ports += ":" + strconv.Itoa(port.End)
			}
			sep = ","
		}
		args = append(args, "--dports", ports)
	}
	if mMultiPort.Ports != nil && len(mMultiPort.Ports) != 0 {
		ports := ""
		sep := ""
		for _, port := range mMultiPort.Ports {
			ports += sep + strconv.Itoa(port.Start)
			if port.End > 0 {
				ports += ":" + strconv.Itoa(port.End)
			}
			sep = ","
		}
		args = append(args, "--ports", ports)
	}
	return args
}

func (mMultiPort *MatchMultiPort) Long() string {
	return strings.Join(mMultiPort.LongArgs(), " ")
}

func (mMultiPort *MatchMultiPort) LongArgs() []string {
	args := make([]string, 0, 11)
	args = append(args, "-m", mMultiPort.matchType.String())
	if mMultiPort.SrcPorts != nil && len(mMultiPort.SrcPorts) != 0 {
		ports := ""
		sep := ""
		for _, port := range mMultiPort.SrcPorts {
			ports += sep + strconv.Itoa(port.Start)
			if port.End > 0 {
				ports += ":" + strconv.Itoa(port.End)
			}
			sep = ","
		}
		args = append(args, "--source-ports", ports)
	}
	if mMultiPort.DstPorts != nil && len(mMultiPort.DstPorts) != 0 {
		ports := ""
		sep := ""
		for _, port := range mMultiPort.DstPorts {
			ports += sep + strconv.Itoa(port.Start)
			if port.End > 0 {
				ports += ":" + strconv.Itoa(port.End)
			}
			sep = ","
		}
		args = append(args, "--destination-ports", ports)
	}
	if mMultiPort.Ports != nil && len(mMultiPort.Ports) != 0 {
		ports := ""
		sep := ""
		for _, port := range mMultiPort.Ports {
			ports += sep + strconv.Itoa(port.Start)
			if port.End > 0 {
				ports += ":" + strconv.Itoa(port.End)
			}
			sep = ","
		}
		args = append(args, "--ports", ports)
	}
	return args
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

func newMatchNFAcct(name string) (*MatchNFAcct, error) {
	match := &MatchNFAcct{
		baseMatch: &baseMatch{
			matchType: MatchTypeNFAcct,
		},
		AccountingName: name,
	}
	return match, nil
}

type MatchNFAcct struct {
	*baseMatch
	AccountingName string
}

func (mNFAcct *MatchNFAcct) Short() string {
	return strings.Join(mNFAcct.ShortArgs(), " ")
}

func (mNFAcct *MatchNFAcct) ShortArgs() []string {
	args := make([]string, 0, 4)
	args = append(args, "-m", mNFAcct.matchType.String())
	if mNFAcct.AccountingName != "" {
		args = append(args, "--nfacct-name", mNFAcct.AccountingName)
	}
	return args
}

func (mNFAcct *MatchNFAcct) Long() string {
	return mNFAcct.Short()
}

func (mNFAcct *MatchNFAcct) LongArgs() []string {
	return mNFAcct.ShortArgs()
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
func WithMatchOSFGenre(invert bool, genre string) OptionMatchOSF {
	return func(mOSF *MatchOSF) {
		mOSF.Genre = genre
		mOSF.invert = invert
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

func newMatchOSF(opts ...OptionMatchOSF) (*MatchOSF, error) {
	match := &MatchOSF{
		baseMatch: &baseMatch{
			matchType: MatchTypeOSF,
		},
		TTLLevel: -1,
		LogLevel: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchOSF struct {
	*baseMatch
	Genre    string
	TTLLevel int
	LogLevel int
}

func (mOSF *MatchOSF) Short() string {
	return strings.Join(mOSF.ShortArgs(), " ")
}

func (mOSF *MatchOSF) ShortArgs() []string {
	args := make([]string, 0, 9)
	args = append(args, "-m", mOSF.matchType.String())
	if mOSF.Genre != "" {
		if mOSF.invert {
			args = append(args, "!")
		}
		args = append(args, "--genre", mOSF.Genre)
	}
	if mOSF.TTLLevel > -1 {
		args = append(args, "--ttl", strconv.Itoa(mOSF.TTLLevel))
	}
	if mOSF.LogLevel > -1 {
		args = append(args, "--log", strconv.Itoa(mOSF.LogLevel))
	}
	return args
}

func (mOSF *MatchOSF) Long() string {
	return mOSF.Short()
}

func (mOSF *MatchOSF) LongArgs() []string {
	return mOSF.ShortArgs()
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
func WithMatchOwnerUid(invert bool, uid ...int) OptionMatchOwner {
	return func(mOwner *MatchOwner) {
		switch len(uid) {
		case 1:
			mOwner.UidOwnerMin = uid[0]
		case 2:
			mOwner.UidOwnerMin = uid[0]
			mOwner.UidOwnerMax = uid[1]
		}
		mOwner.UidOwnerInvert = invert
	}
}

// Matches if the packet socket's file structure (if it has one) is owned by the given user.
func WithMatchOwnerUser(invert bool, name string) OptionMatchOwner {
	return func(mOwner *MatchOwner) {
		mOwner.User = name
		mOwner.UidOwnerInvert = invert
	}
}

// Matches if the packet socket's file structure is owned by the given group.
func WithMatchOwnerGid(invert bool, gid ...int) OptionMatchOwner {
	return func(mOwner *MatchOwner) {
		switch len(gid) {
		case 1:
			mOwner.GidOwnerMin = gid[0]
		case 2:
			mOwner.GidOwnerMin = gid[0]
			mOwner.GidOwnerMax = gid[1]
		}
		mOwner.GidOwnerInvert = invert
	}
}

// Matches if the packet socket's file structure is owned by the given group.
func WithMatchOwnerGroup(invert bool, group string) OptionMatchOwner {
	return func(mOwner *MatchOwner) {
		mOwner.Group = group
		mOwner.GidOwnerInvert = invert
	}
}

// Group to be also checked in the supplementary groups of a process.
func WithMatchOwnerSupplGroups() OptionMatchOwner {
	return func(mOwner *MatchOwner) {
		mOwner.SupplGroups = true
	}
}

// Matches if the packet is associated with a socket.
func WithMatchOwnerSocketExists(invert bool) OptionMatchOwner {
	return func(mOwner *MatchOwner) {
		mOwner.HasSocketExists = true
		mOwner.SocketExistsInvert = invert
	}
}

func newMatchOwner(opts ...OptionMatchOwner) (*MatchOwner, error) {
	match := &MatchOwner{
		baseMatch: &baseMatch{
			matchType: MatchTypeOwner,
		},
		UidOwnerMin: -1,
		UidOwnerMax: -1,
		GidOwnerMin: -1,
		GidOwnerMax: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchOwner struct {
	*baseMatch
	UidOwnerMin     int
	UidOwnerMax     int
	User            string
	GidOwnerMin     int
	GidOwnerMax     int
	Group           string
	SupplGroups     bool
	HasSocketExists bool
	// invert
	UidOwnerInvert     bool
	GidOwnerInvert     bool
	SocketExistsInvert bool
}

func (mOwner *MatchOwner) Short() string {
	return strings.Join(mOwner.ShortArgs(), " ")
}

func (mOwner *MatchOwner) ShortArgs() []string {
	args := make([]string, 0, 7)
	args = append(args, "-m", mOwner.matchType.String())
	if mOwner.User != "" {
		if mOwner.UidOwnerInvert {
			args = append(args, "!")
		}
		args = append(args, "--uid-owner", mOwner.User)
	}
	if mOwner.UidOwnerMin > -1 {
		if mOwner.UidOwnerInvert {
			args = append(args, "!")
		}
		if mOwner.UidOwnerMax > -1 {
			args = append(args, "--uid-owner",
				strconv.Itoa(mOwner.UidOwnerMin)+"-"+strconv.Itoa(mOwner.UidOwnerMax))
		} else {
			args = append(args, "--uid-owner", strconv.Itoa(mOwner.UidOwnerMin))
		}
	}
	if mOwner.Group != "" {
		if mOwner.GidOwnerInvert {
			args = append(args, "!")
		}
		args = append(args, "--gid-owner", mOwner.Group)
	}
	if mOwner.GidOwnerMin > -1 {
		if mOwner.GidOwnerInvert {
			args = append(args, "!")
		}
		if mOwner.GidOwnerMax > -1 {
			args = append(args, "--gid-owner",
				strconv.Itoa(mOwner.GidOwnerMin)+"-"+strconv.Itoa(mOwner.GidOwnerMax))
		} else {
			args = append(args, "--gid-owner", strconv.Itoa(mOwner.GidOwnerMin))
		}
	}
	if mOwner.SupplGroups {
		args = append(args, "--suppl-groups")
	}
	if mOwner.HasSocketExists {
		if mOwner.SocketExistsInvert {
			args = append(args, "!")
		}
		args = append(args, "--socket-exists")
	}
	return args
}

func (mOwner *MatchOwner) Long() string {
	return mOwner.Short()
}

func (mOwner *MatchOwner) LongArgs() []string {
	return mOwner.ShortArgs()
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
				minmax := strings.Split(uidRaw, "-")
				if len(minmax) != 2 {
					mOwner.User = uidRaw
				} else {
					min, err := strconv.Atoi(minmax[0])
					if err != nil {
						mOwner.User = uidRaw
					}
					max, err := strconv.Atoi(minmax[1])
					if err != nil {
						mOwner.User = uidRaw
					}
					mOwner.UidOwnerMin = min
					mOwner.UidOwnerMax = max
				}
			} else {
				mOwner.UidOwnerMin = uid
			}
			mOwner.UidOwnerInvert = invert
		case "owner GID match":
			gidRaw := string(matches[4])
			gid, err := strconv.Atoi(gidRaw)
			if err != nil {
				minmax := strings.Split(gidRaw, "-")
				if len(minmax) != 2 {
					mOwner.Group = gidRaw
				} else {
					min, err := strconv.Atoi(minmax[0])
					if err != nil {
						mOwner.Group = gidRaw
					}
					max, err := strconv.Atoi(minmax[1])
					if err != nil {
						mOwner.Group = gidRaw
					}
					mOwner.GidOwnerMin = min
					mOwner.GidOwnerMax = max
				}

			} else {
				mOwner.GidOwnerMin = gid
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
func WithMatchPhysDevIn(invert bool, in string) OptionMatchPhysDev {
	return func(mPhysDev *MatchPhysDev) {
		mPhysDev.PhysDevIn = in
		mPhysDev.PhysDevInInvert = invert
	}
}

// Name of a bridge port via which a packet is going to be sent.
func WithMatchPhysDevOut(invert bool, out string) OptionMatchPhysDev {
	return func(mPhysDev *MatchPhysDev) {
		mPhysDev.PhysDevOut = out
		mPhysDev.PhysDevOutInvert = invert
	}
}

// Matches if the packet has entered through a bridge interface.
func WithMatchPhysDevIsIn(invert bool) OptionMatchPhysDev {
	return func(mPhysDev *MatchPhysDev) {
		mPhysDev.PhysDevIsIn = true
		mPhysDev.PhysDevIsInInvert = true
	}
}

// Matches if the packet will leave through a bridge interface.
func WithMatchPhysDevIsOut(invert bool) OptionMatchPhysDev {
	return func(mPhysDev *MatchPhysDev) {
		mPhysDev.PhysDevIsOut = true
		mPhysDev.PhysDevIsOutInvert = true
	}
}

func WithMatchPhysDevIsBridged(invert bool) OptionMatchPhysDev {
	return func(mPhysDev *MatchPhysDev) {
		mPhysDev.PhysDevIsBridged = true
		mPhysDev.PhysDevIsBridgedInvert = true
	}
}

func newMatchPhysDev(opts ...OptionMatchPhysDev) (*MatchPhysDev, error) {
	match := &MatchPhysDev{
		baseMatch: &baseMatch{
			matchType: MatchTypePhysDev,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchPhysDev struct {
	*baseMatch
	PhysDevIn        string
	PhysDevOut       string
	PhysDevIsIn      bool
	PhysDevIsOut     bool
	PhysDevIsBridged bool
	// invert
	PhysDevInInvert        bool
	PhysDevOutInvert       bool
	PhysDevIsInInvert      bool
	PhysDevIsOutInvert     bool
	PhysDevIsBridgedInvert bool
}

func (mPhysDev *MatchPhysDev) Short() string {
	return strings.Join(mPhysDev.ShortArgs(), " ")
}

func (mPhysDev *MatchPhysDev) ShortArgs() []string {
	args := make([]string, 0, 13)
	args = append(args, "-m", mPhysDev.matchType.String())
	if mPhysDev.PhysDevIn != "" {
		if mPhysDev.PhysDevInInvert {
			args = append(args, "!")
		}
		args = append(args, "--physdev-in", mPhysDev.PhysDevIn)
	}
	if mPhysDev.PhysDevOut != "" {
		if mPhysDev.PhysDevOutInvert {
			args = append(args, "!")
		}
		args = append(args, "--physdev-out", mPhysDev.PhysDevOut)
	}
	if mPhysDev.PhysDevIsIn {
		if mPhysDev.PhysDevIsInInvert {
			args = append(args, "!")
		}
		args = append(args, "--physdev-is-in")
	}
	if mPhysDev.PhysDevIsOut {
		if mPhysDev.PhysDevIsOutInvert {
			args = append(args, "!")
		}
		args = append(args, "--physdev-is-out")
	}
	if mPhysDev.PhysDevIsBridged {
		if mPhysDev.PhysDevIsBridgedInvert {
			args = append(args, "!")
		}
		args = append(args, "--physdev-is-bridged")
	}
	return args
}

func (mPhysDev *MatchPhysDev) Long() string {
	return mPhysDev.Short()
}

func (mPhysDev *MatchPhysDev) LongArgs() []string {
	return mPhysDev.ShortArgs()
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
		mPhysDev.PhysDevIsIn = true
		if len(matches[2]) != 0 {
			mPhysDev.PhysDevIsInInvert = true
		}
	}
	if len(matches[5]) != 0 {
		mPhysDev.PhysDevIn = string(matches[5])
		if len(matches[3]) != 0 {
			mPhysDev.PhysDevInInvert = true
		}
	}
	if len(matches[6]) != 0 {
		mPhysDev.PhysDevIsOut = true
		if len(matches[7]) != 0 {
			mPhysDev.PhysDevIsOutInvert = true
		}
	}
	if len(matches[10]) != 0 {
		mPhysDev.PhysDevOut = string(matches[10])
		if len(matches[8]) != 0 {
			mPhysDev.PhysDevOutInvert = true
		}
	}
	if len(matches[11]) != 0 {
		mPhysDev.PhysDevIsBridged = true
		if len(matches[12]) != 0 {
			mPhysDev.PhysDevIsBridgedInvert = true
		}
	}
	return len(matches[0]), true
}

type PktType int

func (pktType PktType) String() string {
	switch pktType {
	case Unicast:
		return PktTypeUnicast
	case Broadcast:
		return PktTypeBroadcast
	case Multicast:
		return PktTypeMulticast
	default:
		return ""
	}
}

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

func newMatchPktType(invert bool, pktType PktType) (*MatchPktType, error) {
	match := &MatchPktType{
		baseMatch: &baseMatch{
			matchType: MatchTypePktType,
			invert:    invert,
		},
		PktType: pktType,
	}
	return match, nil
}

type MatchPktType struct {
	*baseMatch
	PktType PktType
}

func (mPktType *MatchPktType) Short() string {
	return strings.Join(mPktType.ShortArgs(), " ")
}

func (mPktType *MatchPktType) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mPktType.matchType.String())
	if mPktType.PktType > -1 {
		if mPktType.invert {
			args = append(args, "!")
		}
		args = append(args, "--pkt-type", mPktType.PktType.String())
	}
	return args
}

func (mPktType *MatchPktType) Long() string {
	return mPktType.Short()
}

func (mPktType *MatchPktType) LongArgs() []string {
	return mPktType.ShortArgs()
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

func (policyMode PolicyMode) String() string {
	switch policyMode {
	case Tunnel:
		return "tunnel"
	case Transport:
		return "transport"
	default:
		return ""
	}
}

const (
	_ PolicyMode = iota
	Tunnel
	Transport
	Unknown
)

type PolicyPol int

func (policyPol PolicyPol) String() string {
	switch policyPol {
	case None:
		return "none"
	case IPSec:
		return "ipsec"
	default:
		return ""
	}
}

const (
	_ PolicyPol = iota
	None
	IPSec
)

// The field won't be use must be set to -1
type MatchPolicyElement struct {
	ReqID     int
	SPI       int
	Proto     network.Protocol
	Mode      PolicyMode
	TunnelSrc network.Address
	TunnelDst network.Address
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
func WithMatchPolicyDir(dir xtables.Direction) OptionMatchPolicy {
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

func newMatchPolicy(opts ...OptionMatchPolicy) (*MatchPolicy, error) {
	match := &MatchPolicy{
		baseMatch: &baseMatch{
			matchType: MatchTypePolicy,
		},
		Dir: -1,
		Pol: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchPolicy struct {
	*baseMatch
	Dir      xtables.Direction
	Pol      PolicyPol
	Strict   bool
	Elements []*MatchPolicyElement
}

func (mPolicy *MatchPolicy) Short() string {
	return strings.Join(mPolicy.ShortArgs(), " ")
}

func (mPolicy *MatchPolicy) ShortArgs() []string {
	args := []string{}
	args = append(args, "-m", mPolicy.matchType.String())
	if mPolicy.Dir > -1 {
		args = append(args, "--dir", mPolicy.Dir.String())
	}
	if mPolicy.Pol > -1 {
		args = append(args, "--pol", mPolicy.Pol.String())
	}
	if mPolicy.Strict {
		args = append(args, "--strict")
	}
	if mPolicy.Elements != nil && len(mPolicy.Elements) != 0 {
		sep := ""
		for _, elem := range mPolicy.Elements {
			if sep != "" {
				args = append(args, sep)
			}
			if elem.ReqID > -1 {
				if elem.ReqIDInvert {
					args = append(args, "!")
				}
				args = append(args, "--reqid", strconv.Itoa(elem.ReqID))
			}
			if elem.SPI > -1 {
				if elem.SPIInvert {
					args = append(args, "!")
				}
				args = append(args, "--spi", strconv.Itoa(elem.SPI))
			}
			if elem.Proto > -1 {
				if elem.ProtoInvert {
					args = append(args, "!")
				}
				args = append(args, "--proto", strconv.Itoa(int(elem.Proto)))
			}
			if elem.Mode > -1 {
				if elem.ModeInvert {
					args = append(args, "!")
				}
				args = append(args, "--mode", elem.Mode.String())
			}
			if elem.TunnelSrc != nil {
				if elem.TunnelSrcInvert {
					args = append(args, "!")
				}
				args = append(args, "--tunnel-src", elem.TunnelSrc.String())
			}
			if elem.TunnelDst != nil {
				if elem.TunnelDstInvert {
					args = append(args, "!")
				}
				args = append(args, "--tunnel-dst", elem.TunnelDst.String())
			}
			sep = "--next"
		}
	}
	return args
}

func (mPolicy *MatchPolicy) Long() string {
	return mPolicy.Short()
}

func (mPolicy *MatchPolicy) LongArgs() []string {
	return mPolicy.ShortArgs()
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
		mPolicy.Dir = xtables.In
		if matches[1][4] == 'o' {
			mPolicy.Dir = xtables.Out
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
				elem.Proto = network.ProtocolAH
			case ESP:
				elem.Proto = network.ProtocolESP
			case IPComp:
				elem.Proto = network.ProtocolIPComp
			default:
				proto, err := strconv.Atoi(protocol)
				if err != nil {
					goto END
				}
				elem.Proto = network.Protocol(proto)
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
			addr, err := network.ParseAddress(string(matches[16]))
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
			addr, err := network.ParseAddress(string(matches[19]))
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

func newMatchQuota(invert bool, quota int64) (*MatchQuota, error) {
	match := &MatchQuota{
		baseMatch: &baseMatch{
			matchType: MatchTypeQuota,
			invert:    invert,
		},
		Quota: quota,
	}
	return match, nil
}

type MatchQuota struct {
	*baseMatch
	Quota int64
}

func (mQuota *MatchQuota) Short() string {
	return strings.Join(mQuota.ShortArgs(), " ")
}

func (mQuota *MatchQuota) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mQuota.matchType.String())
	if mQuota.invert {
		args = append(args, "!")
	}
	args = append(args, "--quota", strconv.FormatInt(mQuota.Quota, 10))
	return args
}

func (mQuota *MatchQuota) Long() string {
	return mQuota.Short()
}

func (mQuota *MatchQuota) LongArgs() []string {
	return mQuota.ShortArgs()
}

func (mQuota *MatchQuota) Parse(main []byte) (int, bool) {
	// 1. "^quota: ([0-9]+) bytes"
	pattern := `^quota: ([0-9]+) bytes *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 2 {
		return 0, false
	}
	quota, err := strconv.ParseInt(string(matches[1]), 10, 64)
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
func WithMatchRateEstOperator(invert bool, operator xtables.Operator) OptionMatchRateEst {
	return func(mRateEst *MatchRateEst) {
		mRateEst.Operator = operator
		mRateEst.invert = invert
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

func WithMatchRateBPS(value int) OptionMatchRateEst {
	return func(mRateEst *MatchRateEst) {
		mRateEst.RateestBPS = value
	}
}

func WithMatchRatePPS(value int) OptionMatchRateEst {
	return func(mRateEst *MatchRateEst) {
		mRateEst.RateestPPS = value
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

func newMatchRateEst(opts ...OptionMatchRateEst) (*MatchRateEst, error) {
	match := &MatchRateEst{
		baseMatch: &baseMatch{
			matchType: MatchTypeRateEst,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchRateEst struct {
	*baseMatch
	RateestDelta bool
	Operator     xtables.Operator
	Name         string
	Rateest1     string
	Rateest2     string
	Relative     bool
	RateestBPS   int // in bytes
	RateestPPS   int
	RateestBPS1  int // in bytes
	RateestPPS1  int
	RateestBPS2  int // in bytes
	RateestPPS2  int
	//RateestLT    bool
	//RateestGT    bool
	//RateestEQ    bool
}

func (mRateEst *MatchRateEst) Short() string {
	return strings.Join(mRateEst.ShortArgs(), " ")
}

func (mRateEst *MatchRateEst) ShortArgs() []string {
	args := make([]string, 0, 27)
	args = append(args, "-m", mRateEst.matchType.String())
	if mRateEst.RateestDelta {
		args = append(args, "--rateest-delta")
	}
	switch mRateEst.Operator {
	case xtables.OperatorLT:
		if mRateEst.invert {
			args = append(args, "!")
		}
		args = append(args, "--rateest-lt")
	case xtables.OperatorGT:
		if mRateEst.invert {
			args = append(args, "!")
		}
		args = append(args, "--rateest-gt")
	case xtables.OperatorEQ:
		if mRateEst.invert {
			args = append(args, "!")
		}
		args = append(args, "--rateest-eq")
	}
	if mRateEst.Name != "" {
		args = append(args, "--rateest", mRateEst.Name)
	}
	if mRateEst.Rateest1 != "" {
		args = append(args, "--rateest1", mRateEst.Name)
	}
	if mRateEst.Rateest2 != "" {
		args = append(args, "--rateest2", mRateEst.Name)
	}
	if mRateEst.RateestBPS > -1 {
		args = append(args, "--rateest-bps",
			strconv.Itoa(mRateEst.RateestBPS))
	}
	if mRateEst.RateestPPS > -1 {
		args = append(args, "--rateest-pps",
			strconv.Itoa(mRateEst.RateestPPS))
	}
	if mRateEst.RateestBPS1 > -1 {
		args = append(args, "--rateest-bps1",
			strconv.Itoa(mRateEst.RateestBPS1))
	}
	if mRateEst.RateestPPS1 > -1 {
		args = append(args, "--rateest-pps1",
			strconv.Itoa(mRateEst.RateestPPS1))
	}
	if mRateEst.RateestBPS2 > -1 {
		args = append(args, "--rateest-bps2",
			strconv.Itoa(mRateEst.RateestBPS1))
	}
	if mRateEst.RateestPPS2 > -1 {
		args = append(args, "--rateest-pps2",
			strconv.Itoa(mRateEst.RateestPPS1))
	}
	return args
}

func (mRateEst *MatchRateEst) Long() string {
	return mRateEst.Short()
}

func (mRateEst *MatchRateEst) LongArgs() []string {
	return mRateEst.ShortArgs()
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
			mRateEst.Operator = xtables.OperatorLT
			//mRateEst.RateestLT = true
		case "eq":
			mRateEst.Operator = xtables.OperatorEQ
			//mRateEst.RateestEQ = true
		case "gt":
			mRateEst.Operator = xtables.OperatorGT
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
			mRateEst.Operator = xtables.OperatorLT
			//mRateEst.RateestLT = true
		case "eq":
			mRateEst.Operator = xtables.OperatorEQ
			//mRateEst.RateestEQ = true
		case "gt":
			mRateEst.Operator = xtables.OperatorGT
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
	if mRateEst.RateestBPS2 == -1 {
		mRateEst.RateestBPS = mRateEst.RateestBPS1
	}
	if mRateEst.RateestPPS2 == -1 {
		mRateEst.RateestPPS = mRateEst.RateestPPS1
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

// Takes mostly 2 values, (value) or (value/mask)
// Matches packets with the given unsigned mark value
func newMatchRealm(invert bool, value ...int) (*MatchRealm, error) {
	mRealm := &MatchRealm{
		baseMatch: &baseMatch{
			matchType: MatchTypeRealm,
		},
		Value: -1,
		Mask:  -1,
	}
	switch len(value) {
	case 1:
		mRealm.Value = value[0]
		mRealm.Mask = -1
	case 2:
		mRealm.Value = value[0]
		mRealm.Mask = value[1]
	}
	mRealm.invert = invert
	return mRealm, nil
}

// IPv4 specific
// Non-numeric support
// see http://linux-ip.net/gl/ip-cref/ip-cref-node172.html
type MatchRealm struct {
	*baseMatch
	Value int
	Mask  int
}

func (mRealm *MatchRealm) Short() string {
	return strings.Join(mRealm.ShortArgs(), " ")
}

func (mRealm *MatchRealm) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mRealm.matchType.String())
	if mRealm.Value > -1 {
		if mRealm.invert {
			args = append(args, "!")
		}
		if mRealm.Mask > -1 {
			args = append(args, "--realm",
				strconv.Itoa(mRealm.Value)+"/"+strconv.Itoa(mRealm.Mask))
		} else {
			args = append(args, "--realm", strconv.Itoa(mRealm.Value))
		}
	}
	return args
}

func (mRealm *MatchRealm) Long() string {
	return mRealm.Short()
}

func (mRealm *MatchRealm) LongArgs() []string {
	return mRealm.ShortArgs()
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
func WithMatchRecentSet(invert bool) OptionMatchRecent {
	return func(mRecent *MatchRecent) {
		mRecent.Set = true
		mRecent.invert = invert
	}
}

// Check if the source address of the packet is currently in the list.
func WithMatchRecentCheck(invert bool) OptionMatchRecent {
	return func(mRecent *MatchRecent) {
		mRecent.RCheck = true
		mRecent.invert = invert
	}
}

// Like WithMatchRecentCheck, except it will update the "last seen" timestamp if it matches.
func WithMatchRecentUpdate(invert bool) OptionMatchRecent {
	return func(mRecent *MatchRecent) {
		mRecent.Update = true
		mRecent.invert = invert
	}
}

// Check if the source address of the packet is currently in the list and
// if so that address will be removed from the list and the rule will return true.
// If the address is not found, false is returned.
func WithMatchRecentRemove(invert bool) OptionMatchRecent {
	return func(mRecent *MatchRecent) {
		mRecent.Remove = true
		mRecent.invert = invert
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

func newMatchRecent(opts ...OptionMatchRecent) (*MatchRecent, error) {
	match := &MatchRecent{
		baseMatch: &baseMatch{
			matchType: MatchTypeRecent,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchRecent struct {
	*baseMatch
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

func (mRecent *MatchRecent) Short() string {
	return strings.Join(mRecent.ShortArgs(), " ")
}

func (mRecent *MatchRecent) ShortArgs() []string {
	args := []string{}
	args = append(args, "-m", mRecent.matchType.String())
	if mRecent.Name != "" {
		args = append(args, "--name", mRecent.Name)
	}
	if mRecent.Set {
		if mRecent.invert {
			args = append(args, "!")
		}
		args = append(args, "--set")
	}
	if mRecent.RSource {
		args = append(args, "--resource")
	}
	if mRecent.RDest {
		args = append(args, "--rdest")
	}
	if mRecent.Mask != nil {
		args = append(args, "--mask", mRecent.Mask.String())
	}
	if mRecent.RCheck {
		if mRecent.invert {
			args = append(args, "!")
		}
		args = append(args, "--rcheck")
	}
	if mRecent.Update {
		if mRecent.invert {
			args = append(args, "!")
		}
		args = append(args, "--update")
	}
	if mRecent.Remove {
		if mRecent.invert {
			args = append(args, "!")
		}
		args = append(args, "--remove")
	}
	if mRecent.Seconds > -1 {
		if mRecent.invert {
			args = append(args, "!")
		}
		args = append(args, "--seconds", strconv.Itoa(mRecent.Seconds))
	}
	if mRecent.Reap {
		if mRecent.invert {
			args = append(args, "!")
		}
		args = append(args, "--reap")
	}
	if mRecent.HitCount > -1 {
		if mRecent.invert {
			args = append(args, "!")
		}
		args = append(args, "--hitcount", strconv.Itoa(mRecent.HitCount))
	}
	if mRecent.RTTL {
		if mRecent.invert {
			args = append(args, "!")
		}
		args = append(args, "--rttl")
	}
	return args
}

func (mRecent *MatchRecent) Long() string {
	return mRecent.Short()
}

func (mRecent *MatchRecent) LongArgs() []string {
	return mRecent.ShortArgs()
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

func newMatchRPFilter(opts ...OptionMatchRPFilter) (*MatchRPFilter, error) {
	match := &MatchRPFilter{
		baseMatch: &baseMatch{
			matchType: MatchTypeRPFilter,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchRPFilter struct {
	*baseMatch
	Loose       bool
	ValidMark   bool
	AcceptLocal bool
	Invert      bool
}

func (mRPFilter *MatchRPFilter) Short() string {
	return strings.Join(mRPFilter.ShortArgs(), " ")
}

func (mRPFilter *MatchRPFilter) ShortArgs() []string {
	args := make([]string, 0, 6)
	args = append(args, "-m", mRPFilter.matchType.String())
	if mRPFilter.Loose {
		args = append(args, "--loose")
	}
	if mRPFilter.ValidMark {
		args = append(args, "--validmark")
	}
	if mRPFilter.AcceptLocal {
		args = append(args, "--accept-local")
	}
	if mRPFilter.invert {
		args = append(args, "--invert")
	}
	return args
}

func (mRPFilter *MatchRPFilter) Long() string {
	return mRPFilter.Short()
}

func (mRPFilter *MatchRPFilter) LongArgs() []string {
	return mRPFilter.ShortArgs()
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
func WithMatchRTType(invert bool, typ int) OptionMatchRT {
	return func(mRT *MatchRT) {
		mRT.RTType = typ
		mRT.TypeInvert = invert
	}
}

// Takes mostly 2 values, (min) or (min, max)
// Match the `segments left' field (range).
func WithMatchRTSegsLeft(invert bool, segsleft ...int) OptionMatchRT {
	return func(mRT *MatchRT) {
		switch len(segsleft) {
		case 1:
			mRT.SegsLeftMin = segsleft[0]
			mRT.SegsLeftMax = -1
		case 2:
			mRT.SegsLeftMin = segsleft[0]
			mRT.SegsLeftMax = segsleft[1]
		}
		mRT.SegsLeftInvert = invert
	}
}

// Match the length of this header.
func WithMatchRTLength(invert bool, length int) OptionMatchRT {
	return func(mRT *MatchRT) {
		mRT.Length = length
		mRT.LengthInvert = invert
	}
}

// Match the reserved field when type == 0.
func WithMatchRTReserved() OptionMatchRT {
	return func(mRT *MatchRT) {
		mRT.Reserved = true
	}
}

// Match addresses when type == 0.
func WithMatchRTAddresses(addrs ...network.Address) OptionMatchRT {
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

func newMatchRT(opts ...OptionMatchRT) (*MatchRT, error) {
	match := &MatchRT{
		baseMatch: &baseMatch{
			matchType: MatchTypeRT,
		},
		RTType:      -1,
		SegsLeftMin: -1,
		SegsLeftMax: -1,
		Length:      -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

// IPv6 specific
// Non-numeric unsupport
type MatchRT struct {
	*baseMatch
	RTType      int
	SegsLeftMin int
	SegsLeftMax int
	Length      int
	Reserved    bool              // type == 0
	Addrs       []network.Address // type == 0
	NotStrict   bool              // type == 0
	// invert
	TypeInvert     bool
	SegsLeftInvert bool
	LengthInvert   bool
}

func (mRT *MatchRT) Short() string {
	return strings.Join(mRT.ShortArgs(), ",")
}

func (mRT *MatchRT) ShortArgs() []string {
	args := make([]string, 0, 15)
	args = append(args, "-m", mRT.matchType.String())
	if mRT.RTType > -1 {
		if mRT.TypeInvert {
			args = append(args, "!")
		}
		args = append(args, "--rt-type", strconv.Itoa(mRT.RTType))
	}
	if mRT.SegsLeftMin > -1 {
		if mRT.SegsLeftInvert {
			args = append(args, "!")
		}
		if mRT.SegsLeftMax > -1 {
			args = append(args, "--rt-segsleft",
				strconv.Itoa(mRT.SegsLeftMin)+":"+strconv.Itoa(mRT.SegsLeftMax))
		} else {
			args = append(args, "--rt-segsleft", strconv.Itoa(mRT.SegsLeftMin))
		}
	}
	if mRT.Length > -1 {
		if mRT.LengthInvert {
			args = append(args, "!")
		}
		args = append(args, "--rt-len", strconv.Itoa(mRT.Length))
	}
	if mRT.Reserved {
		args = append(args, "--rt-0-res")
	}
	if mRT.Addrs != nil && len(mRT.Addrs) != 0 {
		addrs := ""
		sep := ""
		for _, addr := range mRT.Addrs {
			addrs += sep + addr.String()
			sep = ","
		}
		args = append(args, "--rt-0-addrs", addrs)
	}
	if mRT.NotStrict {
		args = append(args, "--rt-0-not-strict")
	}
	return args
}

func (mRT *MatchRT) Long() string {
	return mRT.Short()
}

func (mRT *MatchRT) LongArgs() []string {
	return mRT.ShortArgs()
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
	mRT.Addrs = []network.Address{}
	if len(matches[3]) != 0 {
		typ, err := strconv.Atoi(string(matches[3]))
		if err != nil {
			return 0, false
		}
		mRT.RTType = typ
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
			addr, err := network.ParseAddress(elem)
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

func (sctpType SCTPType) String() string {
	switch sctpType {
	case SCTPTypeDATA:
		return "DATA"
	case SCTPTypeINIT:
		return "INIT"
	case SCTPTypeINITACK:
		return "INITACK"
	case SCTPTypeSACK:
		return "SACK"
	case SCTPTypeHEARTBEAT:
		return "HEARTBEAT"
	case SCTPTypeHEARTBEATACK:
		return "HEARTBEATACK"
	case SCTPTypeABORT:
		return "ABORT"
	case SCTPTypeSHUTDOWN:
		return "SHUTDOWN"
	case SCTPTypeSHUTDOWNACK:
		return "SHUTDOWNACK"
	case SCTPTypeERROR:
		return "ERROR"
	case SCTPTypeCOOKIEECHO:
		return "COOKIEECHO"
	case SCTPTypeCOOKIEACK:
		return "COOKIEACK"
	case SCTPTypeECNECNE:
		return "ECNECNE"
	case SCTPTypeECNCWR:
		return "ECNCWR"
	case SCTPTypeSHUTDOWNCOMPLETE:
		return "SHUTDOWNCOMPLETE"
	case SCTPTypeASCONF:
		return "ASCONF"
	case SCTPTypeASCONFACK:
		return "ASCONFACK"
	case SCTPTypeFORWARDTSN:
		return "FORWARDTSN"
	default:
		return ""
	}
}

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
		"SACK":             SCTPTypeSACK,
		"HEARTBEAT":        SCTPTypeHEARTBEAT,
		"HEARTBEATACK":     SCTPTypeHEARTBEATACK,
		"ABORT":            SCTPTypeABORT,
		"ERROR":            SCTPTypeERROR,
		"SHUTDOWN":         SCTPTypeSHUTDOWN,
		"SHUTDOWNACK":      SCTPTypeSHUTDOWNACK,
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

type ChunkFlag int

func (chunkFlag ChunkFlag) String() string {
	flag := ""
	if chunkFlag&CF_I != 0 {
		flag += "I"
	}
	if chunkFlag&CF_U != 0 {
		flag += "U"
	}
	if chunkFlag&CF_B != 0 {
		flag += "B"
	}
	if chunkFlag&CF_E != 0 {
		flag += "E"
	}
	if chunkFlag&CF_i != 0 {
		flag += "i"
	}
	if chunkFlag&CF_u != 0 {
		flag += "u"
	}
	if chunkFlag&CF_b != 0 {
		flag += "b"
	}
	if chunkFlag&CF_e != 0 {
		flag += "e"
	}
	if chunkFlag&CF_T != 0 {
		flag += "T"
	}
	if chunkFlag&CF_t != 0 {
		flag += "t"
	}
	return flag
}

const (
	CF_I ChunkFlag = 1 << iota
	CF_U
	CF_B
	CF_E
	CF_i
	CF_u
	CF_b
	CF_e
	CF_T
	CF_t
	CF_ALL = CF_I | CF_U | CF_B | CF_E | CF_i | CF_u | CF_b | CF_e | CF_T | CF_t
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

type Chunk struct {
	Type      SCTPType
	ChunkFlag ChunkFlag
}

type OptionMatchSCTP func(*MatchSCTP)

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchSCTPSrcPort(invert bool, port ...int) OptionMatchSCTP {
	return func(mSCTP *MatchSCTP) {
		switch len(port) {
		case 1:
			mSCTP.SrcPortMin = port[0]
			mSCTP.SrcPortMax = -1
		case 2:
			mSCTP.SrcPortMin = port[0]
			mSCTP.SrcPortMax = port[1]
		}
		mSCTP.SrcPortInvert = invert
	}
}

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchSCTPDstPort(invert bool, port ...int) OptionMatchSCTP {
	return func(mSCTP *MatchSCTP) {
		switch len(port) {
		case 1:
			mSCTP.DstPortMin = port[0]
			mSCTP.DstPortMax = -1
		case 2:
			mSCTP.DstPortMin = port[0]
			mSCTP.DstPortMax = port[1]
		}
		mSCTP.DstPortInvert = invert
	}
}

func WithMatchSCTPChunk(invert bool, rg MatchRange, chunks ...Chunk) OptionMatchSCTP {
	return func(mSCTP *MatchSCTP) {
		mSCTP.ChunksInvert = invert
		mSCTP.Range = rg
		mSCTP.Chunks = chunks
	}
}

func newMatchSCTP(opts ...OptionMatchSCTP) (*MatchSCTP, error) {
	match := &MatchSCTP{
		baseMatch: &baseMatch{
			matchType: MatchTypeSCTP,
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

type MatchSCTP struct {
	*baseMatch
	SrcPortMin int
	SrcPortMax int
	DstPortMin int
	DstPortMax int
	Chunks     []Chunk
	Range      MatchRange
	// invert
	SrcPortInvert bool
	DstPortInvert bool
	ChunksInvert  bool
}

func (mSCTP *MatchSCTP) Short() string {
	return strings.Join(mSCTP.ShortArgs(), " ")
}

func (mSCTP *MatchSCTP) ShortArgs() []string {
	args := []string{}
	args = append(args, "-m", mSCTP.matchType.String())
	if mSCTP.SrcPortMin > -1 {
		if mSCTP.SrcPortInvert {
			args = append(args, "!")
		}
		if mSCTP.SrcPortMax > -1 {
			args = append(args, "--sport",
				strconv.Itoa(mSCTP.SrcPortMin)+":"+strconv.Itoa(mSCTP.SrcPortMax))
		} else {
			args = append(args, "--sport", strconv.Itoa(mSCTP.SrcPortMin))
		}
	}
	if mSCTP.DstPortMin > -1 {
		if mSCTP.DstPortInvert {
			args = append(args, "!")
		}
		if mSCTP.DstPortMax > -1 {
			args = append(args, "--dport",
				strconv.Itoa(mSCTP.DstPortMin)+":"+strconv.Itoa(mSCTP.DstPortMax))
		} else {
			args = append(args, "--dport", strconv.Itoa(mSCTP.DstPortMin))
		}
	}
	if mSCTP.Chunks != nil && len(mSCTP.Chunks) > 0 {
		if mSCTP.ChunksInvert {
			args = append(args, "!")
		}
		args = append(args, "--chunk-types", mSCTP.Range.String())
		flags := ""
		sep := ""
		for _, chunk := range mSCTP.Chunks {
			flags += sep + chunk.Type.String()
			if chunk.ChunkFlag.String() != "" {
				flags += ":" + chunk.ChunkFlag.String()
			}
			sep = " "
		}
		args = append(args, flags)
	}
	return args
}

func (mSCTP *MatchSCTP) Long() string {
	return mSCTP.Short()
}

func (mSCTP *MatchSCTP) LongArgs() []string {
	args := []string{}
	args = append(args, "-m", mSCTP.matchType.String())
	if mSCTP.SrcPortMin > -1 {
		if mSCTP.SrcPortInvert {
			args = append(args, "!")
		}
		if mSCTP.SrcPortMax > -1 {
			args = append(args, "--source-port",
				strconv.Itoa(mSCTP.SrcPortMin)+":"+strconv.Itoa(mSCTP.SrcPortMax))
		} else {
			args = append(args, "--source-port", strconv.Itoa(mSCTP.SrcPortMin))
		}
	}
	if mSCTP.DstPortMin > -1 {
		if mSCTP.DstPortInvert {
			args = append(args, "!")
		}
		if mSCTP.DstPortMax > -1 {
			args = append(args, "--destination-port",
				strconv.Itoa(mSCTP.DstPortMin)+":"+strconv.Itoa(mSCTP.DstPortMax))
		} else {
			args = append(args, "--destination-port", strconv.Itoa(mSCTP.DstPortMin))
		}
	}
	if mSCTP.Chunks != nil && len(mSCTP.Chunks) > 0 {
		if mSCTP.ChunksInvert {
			args = append(args, "!")
		}
		args = append(args, "--chunk-types", mSCTP.Range.String())
		flags := ""
		sep := ""
		for _, chunk := range mSCTP.Chunks {
			flags += sep + chunk.Type.String()
			if chunk.ChunkFlag.String() != "" {
				flags += ":" + chunk.ChunkFlag.String()
			}
			sep = " "
		}
		args = append(args, flags)
	}
	return args
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
						chunk.ChunkFlag |= CF_I
					case 'U':
						chunk.ChunkFlag |= CF_U
					case 'B':
						chunk.ChunkFlag |= CF_B
					case 'E':
						chunk.ChunkFlag |= CF_E
					case 'i':
						chunk.ChunkFlag |= CF_i
					case 'u':
						chunk.ChunkFlag |= CF_u
					case 'b':
						chunk.ChunkFlag |= CF_b
					case 'e':
						chunk.ChunkFlag |= CF_e
					case 'T':
						chunk.ChunkFlag |= CF_T
					case 't':
						chunk.ChunkFlag |= CF_t
					}
				}
			}
			mSCTP.Chunks = append(mSCTP.Chunks, chunk)
		}
	}
	return len(matches[0]), true
}

type Flag int

func (flag Flag) String() string {
	switch flag {
	case FlagSrc:
		return "src"
	case FlagDst:
		return "dst"
	default:
		return ""
	}
}

const (
	_ = iota
	FlagSrc
	FlagDst
)

type OptionMatchSet func(*MatchSet)

// There can be at least on and no more than six of flags.
func WithMatchSetName(invert bool, name string, flags ...Flag) OptionMatchSet {
	return func(mSet *MatchSet) {
		mSet.SetName = name
		mSet.SetNameInvert = invert
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

func newMatchSet(opts ...OptionMatchSet) (*MatchSet, error) {
	match := &MatchSet{
		baseMatch: &baseMatch{
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
	*baseMatch
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

func (mSet *MatchSet) Short() string {
	return strings.Join(mSet.ShortArgs(), " ")
}

func (mSet *MatchSet) ShortArgs() []string {
	args := []string{}
	args = append(args, "-m", mSet.matchType.String())
	if mSet.SetName != "" {
		if mSet.SetNameInvert {
			args = append(args, "!")
		}
		args = append(args, "--match-set", mSet.SetName)
		if mSet.Flags != nil && len(mSet.Flags) != 0 {
			flags := ""
			sep := ""
			for _, flag := range mSet.Flags {
				flags += sep + flag.String()
				sep = ","
			}
			args = append(args, flags)
		}
	}
	if mSet.ReturnNoMatch {
		args = append(args, "--return-nomatch")
	}
	if mSet.SkipCounterUpdate {
		args = append(args, "!", "--update-counters")
	}
	if mSet.SkipSubCounterUpdate {
		args = append(args, "!", "--update-subcounters")
	}
	if mSet.PacketsEQ > -1 {
		if mSet.PacketsEQInvert {
			args = append(args, "!")
		}
		args = append(args, "--packets-eq", strconv.Itoa(mSet.PacketsEQ))
	}
	if mSet.PacketsLT > -1 {
		args = append(args, "--packets-lt", strconv.Itoa(mSet.PacketsLT))
	}
	if mSet.PacketsGT > -1 {
		args = append(args, "--packets-gt", strconv.Itoa(mSet.PacketsGT))
	}
	if mSet.BytesEQ > -1 {
		if mSet.BytesEQInvert {
			args = append(args, "!")
		}
		args = append(args, "--bytes-eq", strconv.Itoa(mSet.BytesEQ))
	}
	if mSet.BytesLT > -1 {
		args = append(args, "--bytes-lt", strconv.Itoa(mSet.BytesLT))
	}
	if mSet.BytesGT > -1 {
		args = append(args, "--bytes-gt", strconv.Itoa(mSet.BytesGT))
	}
	return args
}

func (mSet *MatchSet) Long() string {
	return mSet.Short()
}

func (mSet *MatchSet) LongArgs() []string {
	return mSet.ShortArgs()
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

func newMatchSocket(opts ...OptionMatchSocket) (*MatchSocket, error) {
	match := &MatchSocket{
		baseMatch: &baseMatch{
			matchType: MatchTypeSocket,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchSocket struct {
	*baseMatch
	Transparent   bool
	NoWildcard    bool
	RestoreSKMark bool
}

func (mSocket *MatchSocket) Short() string {
	return strings.Join(mSocket.ShortArgs(), " ")
}

func (mSocket *MatchSocket) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mSocket.matchType.String())
	if mSocket.Transparent {
		args = append(args, "--transparent")
	}
	if mSocket.NoWildcard {
		args = append(args, "--nowildcard")
	}
	if mSocket.RestoreSKMark {
		args = append(args, "--restore-skmark")
	}
	return args
}

func (mSocket *MatchSocket) Long() string {
	return mSocket.Short()
}

func (mSocket *MatchSocket) LongArgs() []string {
	return mSocket.ShortArgs()
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

func newMatchState(state ConnTrackState) (*MatchState, error) {
	return &MatchState{
		baseMatch: &baseMatch{
			matchType: MatchTypeState,
		},
		State: state,
	}, nil
}

type MatchState struct {
	*baseMatch
	State ConnTrackState
}

func (mState *MatchState) Short() string {
	return strings.Join(mState.ShortArgs(), " ")
}

func (mState *MatchState) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mState.matchType.String())
	if mState.State > -1 {
		if mState.invert {
			args = append(args, "!")
		}
		args = append(args, "--state", mState.State.String())
	}
	return args
}

func (mState *MatchState) Long() string {
	return mState.Short()
}

func (mState *MatchState) LongArgs() []string {
	return mState.ShortArgs()
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

func (statisticMode StatisticMode) String() string {
	switch statisticMode {
	case StatisticModeRandom:
		return "random"
	case StatisticModeNth:
		return "nth"
	default:
		return ""
	}
}

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
func WithMatchStatisticProbability(invert bool, probability float64) OptionMatchStatistic {
	return func(mStatistic *MatchStatistic) {
		mStatistic.Probability = probability
		mStatistic.ProbabilityInvert = invert
	}
}

// Match one packet every nth packet.
func WithMatchStatisticEvery(invert bool, every int) OptionMatchStatistic {
	return func(mStatistic *MatchStatistic) {
		mStatistic.Every = every
		mStatistic.EveryInvert = invert
	}
}

// Set the initial counter value for the nth mode.
func WithMatchStatisticPacket(packet int) OptionMatchStatistic {
	return func(mStatistic *MatchStatistic) {
		mStatistic.Packet = packet
	}
}

func newMatchStatistic(opts ...OptionMatchStatistic) (*MatchStatistic, error) {
	match := &MatchStatistic{
		baseMatch: &baseMatch{
			matchType: MatchTypeStatistic,
		},
		Mode:        -1,
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
	*baseMatch
	Mode        StatisticMode
	Probability float64
	Every       int
	Packet      int
	// invert
	ProbabilityInvert bool
	EveryInvert       bool
}

func (mStatis *MatchStatistic) Short() string {
	return strings.Join(mStatis.ShortArgs(), " ")
}

func (mStatis *MatchStatistic) ShortArgs() []string {
	args := make([]string, 0, 12)
	args = append(args, "-m", mStatis.matchType.String())
	if mStatis.Mode > -1 {
		args = append(args, "--mode", mStatis.Mode.String())
	}
	if mStatis.Probability > -1 {
		if mStatis.ProbabilityInvert {
			args = append(args, "!")
		}
		args = append(args, "--probability",
			strconv.FormatFloat(mStatis.Probability, 'f', 2, 64))
	}
	if mStatis.Every > -1 {
		if mStatis.EveryInvert {
			args = append(args, "!")
		}
		args = append(args, "--every", strconv.Itoa(mStatis.Every))
	}
	if mStatis.Packet > -1 {
		args = append(args, "--packet", strconv.Itoa(mStatis.Packet))
	}
	return args
}

func (mStatis *MatchStatistic) Long() string {
	return mStatis.Short()
}

func (mStatis *MatchStatistic) LongArgs() []string {
	return mStatis.ShortArgs()
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

func (stringAlgo StringAlgo) String() string {
	switch stringAlgo {
	case StringAlgoBM:
		return "bm"
	case StringAlgoKMP:
		return "kmp"
	default:
		return ""
	}
}

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
func WithMatchStringPattern(invert bool, pattern string) OptionMatchString {
	return func(mString *MatchString) {
		mString.Pattern = pattern
		mString.PatternInvert = invert
	}
}

// Matches the given pattern in hex notation.
func WithMatchStringHexPattern(invert bool, hexPattern []byte) OptionMatchString {
	return func(mString *MatchString) {
		mString.HexPattern = hexPattern
		mString.HexPatternInvert = invert
	}
}

func WithMatchStringIgnoreCase() OptionMatchString {
	return func(mString *MatchString) {
		mString.IgnoreCase = true
	}
}

func newMatchString(opts ...OptionMatchString) (*MatchString, error) {
	match := &MatchString{
		baseMatch: &baseMatch{
			matchType: MatchTypeString,
		},
		Algo: -1,
		From: -1,
		To:   -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchString struct {
	*baseMatch
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

func (mString *MatchString) Short() string {
	return strings.Join(mString.ShortArgs(), " ")
}

func (mString *MatchString) ShortArgs() []string {
	args := make([]string, 0, 15)
	args = append(args, "-m", mString.matchType.String())
	if mString.Algo > -1 {
		args = append(args, "--algo", mString.Algo.String())
	}
	if mString.From > -1 {
		args = append(args, "--from", strconv.Itoa(mString.From))
	}
	if mString.To > -1 {
		args = append(args, "--to", strconv.Itoa(mString.To))
	}
	if mString.Pattern != "" {
		if mString.PatternInvert {
			args = append(args, "!")
		}
		args = append(args, "--string", mString.Pattern)
	}
	if mString.HexPattern != nil {
		if mString.HexPatternInvert {
			args = append(args, "!")
		}
		args = append(args, "--hex-string", string(mString.HexPattern))
	}
	if mString.IgnoreCase {
		args = append(args, "--icase")
	}
	return args
}

func (mString *MatchString) Long() string {
	return mString.Short()
}

func (mString *MatchString) LongArgs() []string {
	return mString.ShortArgs()
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
func WithMatchTCPSrcPort(invert bool, port ...int) OptionMatchTCP {
	return func(mTCP *MatchTCP) {
		switch len(port) {
		case 1:
			mTCP.SrcPortMin = port[0]
		case 2:
			mTCP.SrcPortMin = port[0]
			mTCP.SrcPortMax = port[1]
		}
		mTCP.SrcPortInvert = invert
	}
}

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchTCPDstPort(invert bool, port ...int) OptionMatchTCP {
	return func(mTCP *MatchTCP) {
		switch len(port) {
		case 1:
			mTCP.DstPortMin = port[0]
		case 2:
			mTCP.DstPortMin = port[0]
			mTCP.DstPortMax = port[1]
		}
		mTCP.DstPortInvert = invert
	}
}

// Match when the TCP flags are as specified.
func WithMatchTCPFlags(invert bool, mask network.TCPFlag, set network.TCPFlag) OptionMatchTCP {
	return func(mTCP *MatchTCP) {
		mTCP.FlagsMask = mask
		mTCP.FlagsSet = set
		mTCP.FlagsInvert = invert
	}
}

func WithMatchTCPSYN(invert bool) OptionMatchTCP {
	return func(mTCP *MatchTCP) {
		mTCP.FlagsMask |= network.TCPFlagSYN | network.TCPFlagRST |
			network.TCPFlagACK | network.TCPFlagFIN
		mTCP.FlagsSet = network.TCPFlagSYN
		mTCP.FlagsInvert = invert
	}
}

func WithMatchTCPOption(invert bool, option int) OptionMatchTCP {
	return func(mTCP *MatchTCP) {
		mTCP.Option = option
	}
}

func newMatchTCP(opts ...OptionMatchTCP) (*MatchTCP, error) {
	match := &MatchTCP{
		baseMatch: &baseMatch{
			matchType: MatchTypeTCP,
		},
		SrcPortMin: -1,
		SrcPortMax: -1,
		DstPortMin: -1,
		DstPortMax: -1,
		FlagsMask:  -1,
		FlagsSet:   -1,
		Option:     -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchTCP struct {
	*baseMatch
	SrcPortMin int
	SrcPortMax int
	DstPortMin int
	DstPortMax int
	FlagsMask  network.TCPFlag
	FlagsSet   network.TCPFlag
	Option     int
	// invert
	SrcPortInvert bool
	DstPortInvert bool
	FlagsInvert   bool
	OptionInvert  bool
}

func (mTCP *MatchTCP) Short() string {
	return strings.Join(mTCP.ShortArgs(), " ")
}

func (mTCP *MatchTCP) ShortArgs() []string {
	args := make([]string, 0, 17)
	args = append(args, "-m", mTCP.matchType.String())
	if mTCP.SrcPortMin > -1 {
		if mTCP.SrcPortInvert {
			args = append(args, "!")
		}
		args = append(args, "--sport", strconv.Itoa(mTCP.SrcPortMin))
		if mTCP.SrcPortMax > -1 {
			args = append(args, ":"+strconv.Itoa(mTCP.SrcPortMax))
		}
	}
	if mTCP.DstPortMin > -1 {
		if mTCP.DstPortInvert {
			args = append(args, "!")
		}
		args = append(args, "--dport", strconv.Itoa(mTCP.DstPortMin))
		if mTCP.DstPortMax > -1 {
			args = append(args, ":"+strconv.Itoa(mTCP.DstPortMax))
		}
	}
	if mTCP.FlagsMask > -1 && mTCP.FlagsSet > -1 {
		if mTCP.FlagsInvert {
			args = append(args, "!")
		}
		args = append(args, "--tcp-flags", mTCP.FlagsMask.String(), mTCP.FlagsSet.String())
	}
	if mTCP.Option > -1 {
		if mTCP.OptionInvert {
			args = append(args, "!")
		}
		args = append(args, "tcp-option", strconv.Itoa(mTCP.Option))
	}
	return args
}

func (mTCP *MatchTCP) Long() string {
	return strings.Join(mTCP.LongArgs(), " ")
}

func (mTCP *MatchTCP) LongArgs() []string {
	args := make([]string, 0, 17)
	args = append(args, "-m", mTCP.matchType.String())
	if mTCP.SrcPortMin > -1 {
		if mTCP.SrcPortInvert {
			args = append(args, "!")
		}
		args = append(args, "--source-port", strconv.Itoa(mTCP.SrcPortMin))
		if mTCP.SrcPortMax > -1 {
			args = append(args, ":"+strconv.Itoa(mTCP.SrcPortMax))
		}
	}
	if mTCP.DstPortMin > -1 {
		if mTCP.DstPortInvert {
			args = append(args, "!")
		}
		args = append(args, "--destination-port", strconv.Itoa(mTCP.DstPortMin))
		if mTCP.DstPortMax > -1 {
			args = append(args, ":"+strconv.Itoa(mTCP.DstPortMax))
		}
	}
	if mTCP.FlagsMask > -1 && mTCP.FlagsSet > -1 {
		if mTCP.FlagsInvert {
			args = append(args, "!")
		}
		args = append(args, "--tcp-flags", mTCP.FlagsMask.String(), mTCP.FlagsSet.String())
	}
	if mTCP.Option > -1 {
		if mTCP.OptionInvert {
			args = append(args, "!")
		}
		args = append(args, "tcp-option", strconv.Itoa(mTCP.Option))
	}
	return args
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
		mTCP.Option = option
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
		mTCP.FlagsMask = network.TCPFlag(mask)
		mTCP.FlagsSet = network.TCPFlag(set)
	}
	// non-numeric like: SYN,FIN/SYN
	if len(matches[27]) != 0 {
		flags := strings.Split(string(matches[27]), ",")
		for _, flag := range flags {
			f, ok := network.TCPFlags[flag]
			if !ok {
				return 0, false
			}
			mTCP.FlagsMask |= f
		}
		flags = strings.Split(string(matches[28]), ",")
		for _, flag := range flags {
			f, ok := network.TCPFlags[flag]
			if !ok {
				return 0, false
			}
			mTCP.FlagsSet |= f
		}
	}
	return len(matches[0]), true
}

// This option takes mostly 2 mss, (min) or (min, max)
func newMatchTCPMSS(invert bool, mss ...int) (*MatchTCPMSS, error) {
	match := &MatchTCPMSS{
		baseMatch: &baseMatch{
			matchType: MatchTypeTCPMSS,
			invert:    invert,
		},
		MSSMin: -1,
		MSSMax: -1,
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
	*baseMatch
	MSSMin int
	MSSMax int
}

func (mTCPMSS *MatchTCPMSS) Short() string {
	return strings.Join(mTCPMSS.ShortArgs(), " ")
}

func (mTCPMSS *MatchTCPMSS) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mTCPMSS.matchType.String())
	if mTCPMSS.MSSMin > -1 {
		if mTCPMSS.invert {
			args = append(args, "!")
		}
		if mTCPMSS.MSSMax > -1 {
			args = append(args, "--mss",
				strconv.Itoa(mTCPMSS.MSSMin)+":"+strconv.Itoa(mTCPMSS.MSSMax))
		} else {
			args = append(args, "--mss", strconv.Itoa(mTCPMSS.MSSMin))
		}
	}
	return args
}

func (mTCPMSS *MatchTCPMSS) Long() string {
	return mTCPMSS.Short()
}

func (mTCPMSS *MatchTCPMSS) LongArgs() []string {
	return mTCPMSS.ShortArgs()
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

func WithMatchTimeDateStart(start *xtables.Date) OptionMatchTime {
	return func(mTime *MatchTime) {
		mTime.DateStart = start
	}
}

func WithMatchTimeDateStop(top *xtables.Date) OptionMatchTime {
	return func(mTime *MatchTime) {
		mTime.DateStop = top
	}
}

func WithMatchTimeDaytimeStart(start *xtables.Daytime) OptionMatchTime {
	return func(mTime *MatchTime) {
		mTime.DaytimeStart = start
	}
}

func WithMatchTimeDaytimeStop(top *xtables.Daytime) OptionMatchTime {
	return func(mTime *MatchTime) {
		mTime.DaytimeStop = top
	}
}

// Match on the given days of the month.
func WithMatchTimeMonthdays(monthdays xtables.Monthday) OptionMatchTime {
	return func(mTime *MatchTime) {
		mTime.Monthdays = monthdays
	}
}

// Match not on the given days of the month.
func WithMatchTimeNotMonthdays(monthdays xtables.Monthday) OptionMatchTime {
	return func(mTime *MatchTime) {
		mTime.Monthdays = math.MaxInt32
		mTime.Monthdays ^= monthdays
	}
}

// Match on the given weekdays.
func WithMatchTimeWeekdays(weekdays xtables.Weekday) OptionMatchTime {
	return func(mTime *MatchTime) {
		mTime.Weekdays = weekdays
	}
}

// Match not on the given weekdays.
func WithMatchTimeNotWeekdays(weekdays xtables.Weekday) OptionMatchTime {
	return func(mTime *MatchTime) {
		mTime.Weekdays = math.MaxInt8
		mTime.Weekdays ^= weekdays
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

func newMatchTime(opts ...OptionMatchTime) (*MatchTime, error) {
	match := &MatchTime{
		baseMatch: &baseMatch{
			matchType: MatchTypeTime,
		},
		Weekdays:  -1,
		Monthdays: -1,
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchTime struct {
	*baseMatch
	DaytimeStart *xtables.Daytime
	DaytimeStop  *xtables.Daytime
	DateStart    *xtables.Date
	DateStop     *xtables.Date
	Weekdays     xtables.Weekday
	Monthdays    xtables.Monthday
	KernelTZ     bool
	Contiguous   bool
}

// There are bugs in iptables, the inverts of weekdays and monthdays weren't be printed.
func (mTime *MatchTime) ShortArgs() []string {
	args := []string{}
	if mTime.DateStart != nil {
		args = append(args, "--datestart", mTime.DateStart.String())
	}
	if mTime.DateStop != nil {
		args = append(args, "--datestop", mTime.DateStop.String())
	}
	if mTime.DaytimeStart != nil {
		args = append(args, "--timestart", mTime.DaytimeStart.String())
	}
	if mTime.DaytimeStop != nil {
		args = append(args, "--timestop", mTime.DaytimeStop.String())
	}
	if mTime.Monthdays > -1 {
		args = append(args, "--monthdays", mTime.Monthdays.String())
	}
	if mTime.Weekdays > -1 {
		args = append(args, "--weekdays", mTime.Weekdays.String())
	}
	if mTime.KernelTZ {
		args = append(args, "--kerneltz")
	}
	if mTime.Contiguous {
		args = append(args, "--contiguous")
	}
	return args
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
		start, err := xtables.ParseDaytime(string(matches[2]))
		if err != nil {
			return 0, false
		}
		top, err := xtables.ParseDaytime(string(matches[3]))
		if err != nil {
			return 0, false
		}
		mTime.DaytimeStart = start
		mTime.DaytimeStop = top
	}
	if len(matches[5]) != 0 {
		weekdays := strings.Split(string(matches[5]), ",")
		for _, weekday := range weekdays {
			wd, ok := xtables.Weekdays[weekday]
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
		de, err := xtables.ParseDate(string(matches[11]))
		if err != nil {
			return 0, false
		}
		mTime.DateStart = de
	}
	if len(matches[13]) != 0 {
		de, err := xtables.ParseDate(string(matches[13]))
		if err != nil {
			return 0, false
		}
		mTime.DateStop = de
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
func newMatchTOS(invert bool, tos ...network.TOS) (*MatchTOS, error) {
	match := &MatchTOS{
		baseMatch: &baseMatch{
			matchType: MatchTypeTOS,
		},
		Value: -1,
		Mask:  -1,
	}
	switch len(tos) {
	case 1:
		match.Value = tos[0]
	case 2:
		match.Value = tos[0]
		match.Mask = tos[1]
	}
	match.invert = invert
	return match, nil
}

type MatchTOS struct {
	*baseMatch
	Value network.TOS
	Mask  network.TOS
}

func (mTOS *MatchTOS) Short() string {
	return strings.Join(mTOS.ShortArgs(), " ")
}

func (mTOS *MatchTOS) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mTOS.matchType.String())
	if mTOS.invert {
		args = append(args, "!")
	}
	if mTOS.Mask > -1 {
		args = append(args, "--tos",
			strconv.Itoa(int(mTOS.Value))+"/"+strconv.Itoa(int(mTOS.Mask)))
	} else {
		args = append(args, "--tos", strconv.Itoa(int(mTOS.Value)))
	}
	return args
}

func (mTOS *MatchTOS) Long() string {
	return mTOS.Short()
}

func (mTOS *MatchTOS) LongArgs() []string {
	return mTOS.ShortArgs()
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
		tos, ok := network.TOSMap[string(matches[3])]
		if ok {
			mTOS.Value = tos
		}
		mTOS.Mask = network.TOS(0x3f)
	}
	if len(matches[5]) != 0 {
		value, err := strconv.ParseUint(string(matches[5]), 16, 8)
		if err != nil {
			return 0, false
		}
		mTOS.Value = network.TOS(value)
	}
	if len(matches[6]) != 0 {
		mask, err := strconv.ParseUint(string(matches[6]), 16, 8)
		if err != nil {
			return 0, false
		}
		mTOS.Mask = network.TOS(mask)
	}
	return len(matches[0]), true
}

type OptionMatchTTL func(*MatchTTL)

// Matches the given TTL value.
func WithMatchTTLEqual(ttl int) OptionMatchTTL {
	return func(mTTL *MatchTTL) {
		mTTL.Operator = xtables.OperatorEQ
		mTTL.Value = ttl
	}
}

// Doesn't match the given TTL value.
func WithMatchTTLNotEqual(ttl int) OptionMatchTTL {
	return func(mTTL *MatchTTL) {
		mTTL.Operator = xtables.OperatorNE
		mTTL.Value = ttl
	}
}

// Matches if TTL is greater than the given TTL value.
func WithMatchTTLGreaterThan(ttl int) OptionMatchTTL {
	return func(mTTL *MatchTTL) {
		mTTL.Operator = xtables.OperatorGT
		mTTL.Value = ttl
	}
}

// Matches if TTL is less than the given TTL value.
func WithMatchTTLLessThan(ttl int) OptionMatchTTL {
	return func(mTTL *MatchTTL) {
		mTTL.Operator = xtables.OperatorLT
		mTTL.Value = ttl
	}
}

func newMatchTTL(opts ...OptionMatchTTL) (*MatchTTL, error) {
	match := &MatchTTL{
		baseMatch: &baseMatch{
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
	*baseMatch
	Operator xtables.Operator
	Value    int
}

func (mTTL *MatchTTL) ShortArgs() []string {
	args := []string{}
	args = append(args, "-m", mTTL.matchType.String())
	switch mTTL.Operator {
	case xtables.OperatorEQ:
		if mTTL.invert {
			args = append(args, "!")
		}
		args = append(args, "--ttl-eq", strconv.Itoa(mTTL.Value))
	case xtables.OperatorGT:
		args = append(args, "--ttl-gt", strconv.Itoa(mTTL.Value))
	case xtables.OperatorLT:
		args = append(args, "--ttl-lt", strconv.Itoa(mTTL.Value))
	}
	return args
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
		mTTL.Operator = xtables.OperatorEQ
	case "!=":
		mTTL.Operator = xtables.OperatorNE
	case "<":
		mTTL.Operator = xtables.OperatorLT
	case ">":
		mTTL.Operator = xtables.OperatorGT
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

func newMatchU32(invert bool, tests string) (*MatchU32, error) {
	return &MatchU32{
		baseMatch: &baseMatch{
			matchType: MatchTypeU32,
			invert:    invert,
		},
		Tests: tests,
	}, nil
}

type MatchU32 struct {
	*baseMatch
	Tests string
}

func (mU32 *MatchU32) Short() string {
	return strings.Join(mU32.ShortArgs(), " ")
}

func (mU32 *MatchU32) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-m", mU32.matchType.String())
	if mU32.invert {
		args = append(args, "!")
	}
	args = append(args, "--u32", "\""+mU32.Tests, "\"")
	return args
}

func (mU32 *MatchU32) Long() string {
	return mU32.Short()
}

func (mU32 *MatchU32) LongArgs() []string {
	return mU32.ShortArgs()
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
func WithMatchUDPSrcPort(invert bool, port ...int) OptionMatchUDP {
	return func(mUDP *MatchUDP) {
		switch len(port) {
		case 1:
			mUDP.SrcPortMin = port[0]
		case 2:
			mUDP.SrcPortMin = port[0]
			mUDP.SrcPortMax = port[1]
		}
		mUDP.SrcPortInvert = invert
	}
}

// This option takes mostly 2 ports, (min) or (min, max)
func WithMatchUDPDstPort(invert bool, port ...int) OptionMatchUDP {
	return func(mUDP *MatchUDP) {
		switch len(port) {
		case 1:
			mUDP.DstPortMin = port[0]
		case 2:
			mUDP.DstPortMin = port[0]
			mUDP.DstPortMax = port[1]
		}
		mUDP.DstPortInvert = invert
	}
}

func newMatchUDP(opts ...OptionMatchUDP) (*MatchUDP, error) {
	match := &MatchUDP{
		baseMatch: &baseMatch{
			matchType: MatchTypeUDP,
		},
	}
	for _, opt := range opts {
		opt(match)
	}
	return match, nil
}

type MatchUDP struct {
	*baseMatch
	SrcPortMin int
	SrcPortMax int
	DstPortMin int
	DstPortMax int
	// invert
	SrcPortInvert bool
	DstPortInvert bool
}

func (mUDP *MatchUDP) Short() string {
	return strings.Join(mUDP.ShortArgs(), " ")
}

func (mUDP *MatchUDP) ShortArgs() []string {
	args := make([]string, 0, 17)
	args = append(args, "-m", mUDP.matchType.String())
	if mUDP.SrcPortMin > -1 {
		if mUDP.SrcPortInvert {
			args = append(args, "!")
		}
		args = append(args, "--sport", strconv.Itoa(mUDP.SrcPortMin))
		if mUDP.SrcPortMax > -1 {
			args = append(args, ":"+strconv.Itoa(mUDP.SrcPortMax))
		}
	}
	if mUDP.DstPortMin > -1 {
		if mUDP.DstPortInvert {
			args = append(args, "!")
		}
		args = append(args, "--dport", strconv.Itoa(mUDP.DstPortMin))
		if mUDP.DstPortMax > -1 {
			args = append(args, ":"+strconv.Itoa(mUDP.DstPortMax))
		}
	}
	return args
}

func (mUDP *MatchUDP) Long() string {
	return strings.Join(mUDP.LongArgs(), " ")
}

func (mUDP *MatchUDP) LongArgs() []string {
	args := make([]string, 0, 17)
	args = append(args, "-m", mUDP.matchType.String())
	if mUDP.SrcPortMin > -1 {
		if mUDP.SrcPortInvert {
			args = append(args, "!")
		}
		args = append(args, "--source-port", strconv.Itoa(mUDP.SrcPortMin))
		if mUDP.SrcPortMax > -1 {
			args = append(args, ":"+strconv.Itoa(mUDP.SrcPortMax))
		}
	}
	if mUDP.DstPortMin > -1 {
		if mUDP.DstPortInvert {
			args = append(args, "!")
		}
		args = append(args, "--destination-port", strconv.Itoa(mUDP.DstPortMin))
		if mUDP.DstPortMax > -1 {
			args = append(args, ":"+strconv.Itoa(mUDP.DstPortMax))
		}
	}
	return args
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

	matchTrie tree.Trie
)

func init() {
	matchTrie = tree.NewTrie()
	for prefix, typ := range matchPrefixes {
		matchTrie.Add(prefix, typ)
	}
}

// see https://git.netfilter.org/iptables/tree/extensions
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
		match := matchFactory(typ)
		if match != nil {
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
