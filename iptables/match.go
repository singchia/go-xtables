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
	Address *Address
}

func (mSrc *MatchSource) Short() string {
	if mSrc.invert {
		return fmt.Sprintf("! -s %s", mSrc.Address.String())
	}
	return fmt.Sprintf("-s %s", mSrc.Address.String())
}

func (mSrc *MatchSource) ShortArgs() []string {
	if mSrc.invert {
		return []string{"!", "-s", mSrc.Address.String()}
	}
	return []string{"-s", mSrc.Address.String()}
}

func (mSrc *MatchSource) Long() string {
	if mSrc.invert {
		return fmt.Sprintf("! --source %s", mSrc.Address.String())
	}
	return fmt.Sprintf("--source %s", mSrc.Address.String())
}

func (mSrc *MatchSource) LongArgs() []string {
	if mSrc.invert {
		return []string{"!", "--source", mSrc.Address.String()}
	}
	return []string{"--source", mSrc.Address.String()}
}

type MatchDestination struct {
	baseMatch
	Address *Address
}

func (mDst *MatchDestination) Short() string {
	if mDst.invert {
		return fmt.Sprintf("! -d %s", mDst.Address.String())
	}
	return fmt.Sprintf("-d %s", mDst.Address.String())
}

func (mDst *MatchDestination) ShortArgs() []string {
	if mDst.invert {
		return []string{"!", "-d", mDst.Address.String()}
	}
	return []string{"-d", mDst.Address.String()}
}

func (mDst *MatchDestination) Long() string {
	if mDst.invert {
		return fmt.Sprintf("! --destination %s", mDst.Address.String())
	}
	return fmt.Sprintf("--destination %s", mDst.Address.String())
}

func (mDst *MatchDestination) LongArgs() []string {
	if mDst.invert {
		return []string{"!", "--destination", mDst.Address.String()}
	}
	return []string{"--destination", mDst.Address.String()}
}

type MatchInInterface struct {
	baseMatch
	Interface string
}

func (mInIface *MatchInInterface) Short() string {
	if mInIface.invert {
		return fmt.Sprintf("! -i %s", mInIface.Interface)
	}
	return fmt.Sprintf("-i %s", mInIface.Interface)
}

func (mInIface *MatchInInterface) ShortArgs() []string {
	if mInIface.invert {
		return []string{"!", "-i", mInIface.Interface}
	}
	return []string{"-i", mInIface.Interface}
}

func (mInIface *MatchInInterface) Long() string {
	if mInIface.invert {
		return fmt.Sprintf("! --in-interface %s", mInIface.Interface)
	}
	return fmt.Sprintf("--in-interface %s", mInIface.Interface)
}

func (mInIface *MatchInInterface) LongArgs() []string {
	if mInIface.invert {
		return []string{"!", "--in-interface", mInIface.Interface}
	}
	return []string{"--in-interface", mInIface.Interface}
}

type MatchOutInterface struct {
	baseMatch
	Interface string
}

func (mOutIface *MatchOutInterface) Short() string {
	if mOutIface.invert {
		return fmt.Sprintf("! -o %s", mOutIface.Interface)
	}
	return fmt.Sprintf("-o %s", mOutIface.Interface)
}

func (mOutIface *MatchOutInterface) ShortArgs() []string {
	if mOutIface.invert {
		return []string{"!", "-o", mOutIface.Interface}
	}
	return []string{"-o", mOutIface.Interface}
}

func (mOutIface *MatchOutInterface) Long() string {
	if mOutIface.invert {
		return fmt.Sprintf("! --out-interface %s", mOutIface.Interface)
	}
	return fmt.Sprintf("--out-interface %s", mOutIface.Interface)
}

func (mOutIface *MatchOutInterface) LongArgs() []string {
	if mOutIface.invert {
		return []string{"!", "-o", mOutIface.Interface}
	}
	return []string{"-o", mOutIface.Interface}
}
