/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package iptables

import (
	"fmt"
	"strconv"
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
	MatchTypeAH
	MatchTypeBPF
	MatchTypeCgroup
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
	MatchTypeDst
	MatchTypeECN
	MatchTypeESP
	MatchTypeEUI64
	MatchTypeFrag
	MatchTypeHashLimit
	MatchTypeHBH // Hop-by-Hop
	MatchTypeHelper
	MatchTypeHL // Hop Limit
	MatchTypeIcmp
	MatchTypeIcmp6
	MatchTypeInInterface // option
	MatchTypeIPRange
	MatchTypeIPv4
	MatchTypeIPv6
	MatchTypeIPv6Header
	MatchTypeIPVS
	MatchTypeLength
	MatchTypeLimit
	MatchTypeMAC
	MatchTypeMark
	MatchTypeMH
	MatchTypeMultiPort
	MatchTypeNFacct
	MatchTypeOSF
	MatchTypeOutInterface // option
	MatchTypeOwner
	MatchTypePhysDev
	MatchTypePktType
	MatchTypePolicy
	MatchTypeProtocol // option
	MatchTypeQuota
	MatchTypeRateEst
	MatchTypeRealm
	MatchTypeRecent
	MatchTypeRPFilter
	MatchTypeRT
	MatchTypeSCTP
	MatchTypeSet
	MatchTypeSocket
	MatchTypeSource // option
	MatchTypeState
	MatchTypeStatistic
	MatchTypeString
	MatchTypeTCP
)

type Match interface {
	Type() MatchType
	Short() string
	ShortArgs() []string
	Long() string
	LongArgs() []string
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

type baseMatch struct {
	matchType MatchType
	invert    bool
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
			matchType: MatchInInterface,
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
			matchType: MatchOutInterface,
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

const (
	_      AddrType = iota
	UNSPEC          // unspecified
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

type MatchAddrtype struct {
	baseMatch
	SrcType AddrType
	DstType AddrType
}

// see https://git.netfilter.org/iptables/tree/extensions
func ParseMatch(fields [][]byte) ([]Match, error) {
}
