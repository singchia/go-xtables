/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package iptables

import "net"

func (iptables *IPTables) TableType(table TableType) *IPTables {
	iptables.statement.table = table
	return iptables
}

func (iptables *IPTables) ChainType(chain ChainType) *IPTables {
	iptables.statement.chain = chain
	return iptables
}

func (iptables *IPTables) UserDefinedChain(chain string) *IPTables {
	iptables.statement.chain = ChainTypeUserDefined
	iptables.statement.userDefinedChain = chain
	return iptables
}

func (iptables *IPTables) MatchIPv4() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	match := &MatchIPv4{
		baseMatch: baseMatch{
			matchType: MatchTypeIPv4,
		},
	}
	iptables.statement.addMatch(match)
	return iptables
}

func (iptables *IPTables) MatchIPv6() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	match := &MatchIPv6{
		baseMatch: baseMatch{
			matchType: MatchTypeIPv6,
		},
	}
	iptables.statement.addMatch(match)
	return iptables
}

func (iptables *IPTables) MatchProtocol(yes bool, protocol Protocol) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	match := &MatchProtocol{
		baseMatch: baseMatch{
			matchType: MatchTypeProtocol,
			invert:    !yes,
		},
	}
	iptables.statement.addMatch(match)
	return iptables
}

// address takes:
// 1. string for hostname, network or ip
// 2. *net.IPNet
// 3. net.IP
func (iptables *IPTables) MatchSource(yes bool, address interface{}) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	ads, err := ParseAddress(address)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	match := &MatchSource{
		baseMatch: baseMatch{
			matchType: MatchTypeSource,
			invert:    !yes,
		},
		address: ads,
	}
	iptables.statement.addMatch(match)
	return iptables
}

// address takes:
// 1. string for hostname or network or ip
// 2. *net.IPNet
// 3. net.IP
func (iptables *IPTables) MatchDestination(yes bool, address interface{}) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	ads, err := ParseAddress(address)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	match := &MatchDestination{
		baseMatch: baseMatch{
			matchType: MatchTypeDestination,
			invert:    !yes,
		},
		address: ads,
	}
	iptables.statement.addMatch(match)
	return iptables
}

func (iptables *IPTables) MatchInInterface(yes bool, iface string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	match := &MatchInInterface{
		baseMatch: baseMatch{
			matchType: MatchTypeInInterface,
			invert:    !yes,
		},
		iface: iface,
	}
	iptables.statement.addMatch(match)
	return iptables
}

func (iptables *IPTables) MatchOutInterface(yes bool, iface string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	match := &MatchOutInterface{
		baseMatch: baseMatch{
			matchType: MatchTypeOutInterface,
			invert:    !yes,
		},
		iface: iface,
	}
	iptables.statement.addMatch(match)
	return iptables
}

func (iptables *IPTables) MatchAddrType(opts ...OptionMatchAddrType) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mAddrType, err := NewMatchAddrType(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mAddrType)
	return iptables
}

func (iptables *IPTables) MatchAH(opts ...OptionMatchAH) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mAH, err := NewMatchAH(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mAH)
	return iptables
}

func (iptables *IPTables) MatchBPF(opts ...OptionMatchBPF) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mBPF, err := NewMatchBPF(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mBPF)
	return iptables
}

func (iptables *IPTables) MatchCGroup(opts ...OptionMatchCGroup) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mCGroup, err := NewMatchCGroup(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mCGroup)
	return iptables
}

func (iptables *IPTables) MatchCluster(opts ...OptionMatchCluster) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mCluster, err := NewMatchCluster(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mCluster)
	return iptables
}

func (iptables *IPTables) MatchComment(comment string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mComment, err := NewMatchComment(comment)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mComment)
	return iptables
}

func (iptables *IPTables) MatchConnBytes(opts ...OptionMatchConnBytes) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mConnBytes, err := NewMatchConnBytes(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mConnBytes)
	return iptables
}

func (iptables *IPTables) MatchConnLabel(opts ...OptionMatchConnLabel) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mConnLabel, err := NewMatchConnLabel(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mConnLabel)
	return iptables
}

func (iptables *IPTables) MatchConnLimit(opts ...OptionMatchConnLimit) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mConnLimit, err := NewMatchConnLimit(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mConnLimit)
	return iptables
}

func (iptables *IPTables) MatchConnMark(yes bool, value ...int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mConnMark, err := NewMatchConnMark(yes, value...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mConnMark)
	return iptables
}

func (iptables *IPTables) MatchConnTrack(opts ...OptionMatchConnTrack) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mConnTrack, err := NewMatchConnTrack(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mConnTrack)
	return iptables
}

func (iptables *IPTables) MatchCPU(yes bool, cpu int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mCPU, err := NewMatchCPU(yes, cpu)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mCPU)
	return iptables
}

func (iptables *IPTables) MatchDCCP(opts ...OptionMatchDCCP) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mDCCP, err := NewMatchDCCP(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mDCCP)
	return iptables
}

func (iptables *IPTables) MatchDevGroup(opts ...OptionMatchDevGroup) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mDevGroup, err := NewMatchDevGroup(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mDevGroup)
	return iptables
}

func (iptables *IPTables) MatchDSCP(opts ...OptionMatchDSCP) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mDSCP, err := NewMatchDSCP(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mDSCP)
	return iptables
}

func (iptables *IPTables) MatchDst(opts ...OptionMatchDst) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mDst, err := NewMatchDst(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mDst)
	return iptables
}

func (iptables *IPTables) MatchECN(opts ...OptionMatchECN) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mECN, err := NewMatchECN(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mECN)
	return iptables
}

func (iptables *IPTables) MatchESP(yes bool, spi ...int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mESP, err := NewMatchESP(yes, spi...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mESP)
	return iptables
}

func (iptables *IPTables) MatchEUI64() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mEUI64, err := NewMatchEUI64()
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mEUI64)
	return iptables
}

func (iptables *IPTables) MatchFrag(opts ...OptionMatchFrag) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mFrag, err := NewMatchFrag(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mFrag)
	return iptables
}

func (iptables *IPTables) MatchHBH(opts ...OptionMatchHBH) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mHBH, err := NewMatchHBH(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mHBH)
	return iptables
}

func (iptables *IPTables) MatchHelper(helper string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mHelper, err := NewMatchHelper(helper)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mHelper)
	return iptables
}

func (iptables *IPTables) MatchHL(operator Operator, value int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mHL, err := NewMatchHL(operator, value)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mHL)
	return iptables
}

func (iptables *IPTables) MatchICMP(yes bool, typ ICMPType,
	opts ...OptionMatchICMP) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mICMP, err := NewMatchICMP(yes, typ, opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mICMP)
	return iptables
}

func (iptables *IPTables) MatchIPRange(opts ...OptionMatchIPRange) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mIPRange, err := NewMatchIPRange(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mIPRange)
	return iptables
}

func (iptables *IPTables) MatchIPv6Header(opts ...OptionMatchIPv6Header) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mIPv6Header, err := NewMatchIPv6Header(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mIPv6Header)
	return iptables
}

func (iptables *IPTables) MatchIPVS(opts ...OptionMatchIPVS) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mIPVS, err := NewMatchIPVS(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mIPVS)
	return iptables
}

func (iptables *IPTables) MatchLength(yes bool, length ...int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mLength, err := NewMatchLength(yes, length...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mLength)
	return iptables
}

func (iptables *IPTables) MatchLimit(opts ...OptionMatchLimit) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mLimit, err := NewMatchLimit(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mLimit)
	return iptables
}

func (iptables *IPTables) MatchMAC(yes bool, mac net.HardwareAddr) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mMAC, err := NewMatchMAC(yes, mac)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mMAC)
	return iptables
}

func (iptables *IPTables) MatchMark(yes bool, value ...int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mMark, err := NewMatchMark(yes, value...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mMark)
	return iptables
}

func (iptables *IPTables) MatchMH(yes bool, typ ...MHType) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mMH, err := NewMatchMH(yes, typ...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mMH)
	return iptables
}

func (iptables *IPTables) MatchMultiPort(opts ...OptionMatchMultiPort) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mMultiPort, err := NewMatchMultiPort(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mMultiPort)
	return iptables
}

func (iptables *IPTables) MatchNFAcct(name string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mNFAcct, err := NewMatchNFAcct(name)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mNFAcct)
	return iptables
}

func (iptables *IPTables) MatchOSF(opts ...OptionMatchOSF) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mOSF, err := NewMatchOSF(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mOSF)
	return iptables
}

func (iptables *IPTables) MatchOwner(opts ...OptionMatchOwner) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mOwner, err := NewMatchOwner(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mOwner)
	return iptables
}

func (iptables *IPTables) MatchPhysDev(opts ...OptionMatchPhysDev) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mPhysDev, err := NewMatchPhysDev(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mPhysDev)
	return iptables
}

func (iptables *IPTables) MatchPktType(yes bool, pktType PktType) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mPktType, err := NewMatchPktType(yes, pktType)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mPktType)
	return iptables
}

func (iptables *IPTables) MatchPolicy(opts ...OptionMatchPolicy) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mPolicy, err := NewMatchPolicy(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mPolicy)
	return iptables
}

func (iptables *IPTables) MatchQuota(yes bool, quota int64) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mQuota, err := NewMatchQuota(yes, quota)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mQuota)
	return iptables
}

func (iptables *IPTables) MatchRateEst(opts ...OptionMatchRateEst) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mRateEst, err := NewMatchRateEst(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mRateEst)
	return iptables
}

func (iptables *IPTables) MatchRealm(yes bool, value ...int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mRealm, err := NewMatchRealm(yes, value...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mRealm)
	return iptables
}

func (iptables *IPTables) MatchRecent(opts ...OptionMatchRecent) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mRecent, err := NewMatchRecent(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mRecent)
	return iptables
}

func (iptables *IPTables) MatchRPFilter(opts ...OptionMatchRPFilter) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mRPFilter, err := NewMatchRPFilter(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mRPFilter)
	return iptables
}

func (iptables *IPTables) MatchRT(opts ...OptionMatchRT) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mRT, err := NewMatchRT(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mRT)
	return iptables
}

func (iptables *IPTables) MatchSCTP(opts ...OptionMatchSCTP) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mSCTP, err := NewMatchSCTP(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mSCTP)
	return iptables
}

func (iptables *IPTables) MatchSet(opts ...OptionMatchSet) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mSet, err := NewMatchSet(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mSet)
	return iptables
}

func (iptables *IPTables) MatchSocket(opts ...OptionMatchSocket) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mSocket, err := NewMatchSocket(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mSocket)
	return iptables
}

func (iptables *IPTables) MatchState(state ConnTrackState) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mState, err := NewMatchState(state)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mState)
	return iptables
}

func (iptables *IPTables) MatchStatistic(opts ...OptionMatchStatistic) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mStatistic, err := NewMatchStatistic(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mStatistic)
	return iptables
}

func (iptables *IPTables) MatchString(opts ...OptionMatchString) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mString, err := NewMatchString(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mString)
	return iptables
}

func (iptables *IPTables) MatchTCP(opts ...OptionMatchTCP) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mTCP, err := NewMatchTCP(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mTCP)
	return iptables
}

func (iptables *IPTables) MatchTCPMSS(yes bool, mss ...int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mTCPMSS, err := NewMatchTCPMSS(yes, mss...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mTCPMSS)
	return iptables
}

func (iptables *IPTables) MatchTime(opts ...OptionMatchTime) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mTime, err := NewMatchTime(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mTime)
	return iptables
}

func (iptables *IPTables) MatchTOS(yes bool, tos ...TOS) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mTOS, err := NewMatchTOS(yes, tos...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mTOS)
	return iptables
}

func (iptables *IPTables) MatchTTL(opts ...OptionMatchTTL) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mTTL, err := NewMatchTTL(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mTTL)
	return iptables
}

func (iptables *IPTables) MatchU32(yes bool, tests string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mU32, err := NewMatchU32(yes, tests)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mU32)
	return iptables
}

func (iptables *IPTables) MatchUDP(opts ...OptionMatchUDP) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mUDP, err := NewMatchUDP(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	iptables.statement.addMatch(mUDP)
	return iptables
}

// iptables OPTIONS
func (iptables *IPTables) OptionFragment(yes bool) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	option := &OptionFragment{
		baseOption: baseOption{
			optionType: OptionTypeFragment,
			invert:     !yes,
		},
	}
	iptables.statement.addOption(option)
	return iptables
}

func (iptables *IPTables) OptionSetCounters(packets, bytes uint64) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	option := &OptionSetCounters{
		baseOption: baseOption{
			optionType: OptionTypeSetCounters,
		},
		packets: packets,
		bytes:   bytes,
	}
	iptables.statement.addOption(option)
	return iptables
}

func (iptables *IPTables) OptionVerbose() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	option := &OptionVerbose{
		baseOption: baseOption{
			optionType: OptionTypeVerbose,
		},
	}
	iptables.statement.addOption(option)
	return iptables
}

// 0 means indefinitely
func (iptables *IPTables) OptionWait(seconds uint32) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	option := &OptionWait{
		baseOption: baseOption{
			optionType: OptionTypeWait,
		},
		seconds: seconds,
	}
	iptables.statement.addOption(option)
	return iptables
}

func (iptables *IPTables) OptionWaitInterval(microseconds uint64) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	option := &OptionWaitInterval{
		baseOption: baseOption{
			optionType: OptionTypeWaitInterval,
		},
		microseconds: microseconds,
	}
	iptables.statement.addOption(option)
	return iptables
}

func (iptables *IPTables) TargetAccetp() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target := &TargetAccept{
		baseTarget: baseTarget{
			targetType: TargetTypeAccept,
		},
	}
	iptables.statement.target = target
	return iptables
}

func (iptables *IPTables) TargetDrop() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target := &TargetAccept{
		baseTarget: baseTarget{
			targetType: TargetTypeDrop,
		},
	}
	iptables.statement.target = target
	return iptables
}

func (iptables *IPTables) TargetReturn() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target := &TargetAccept{
		baseTarget: baseTarget{
			targetType: TargetTypeReturn,
		},
	}
	iptables.statement.target = target
	return iptables
}

func (iptables *IPTables) TargetJumpChain(chain string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target := &TargetJumpChain{
		baseTarget: baseTarget{
			targetType: TargetTypeJumpChain,
		},
		chain: chain,
	}
	iptables.statement.chain = ChainTypeUserDefined
	iptables.statement.target = target
	return iptables
}

func (iptables *IPTables) TargetGotoChain() *IPTables {
	return nil
}

func (iptables *IPTables) TargetAudit() *IPTables {
	return nil
}

func (iptables *IPTables) TargetCheckSum() *IPTables {
	return nil
}

func (iptables *IPTables) TargetClassify() *IPTables {
	return nil
}

func (iptables *IPTables) TargetClusterIP() *IPTables {
	return nil
}

func (iptables *IPTables) TargetConnMark() *IPTables {
	return nil
}

func (iptables *IPTables) TargetConnSecMark() *IPTables {
	return nil
}

func (iptables *IPTables) TargetCT() *IPTables {
	return nil
}

func (iptables *IPTables) TargetDNAT() *IPTables {
	return nil
}

func (iptables *IPTables) TargetDNPT() *IPTables {
	return nil
}

func (iptables *IPTables) TargetDSCP() *IPTables {
	return nil
}

func (iptables *IPTables) TargetECN() *IPTables {
	return nil
}

func (iptables *IPTables) TargetHL() *IPTables {
	return nil
}

func (iptables *IPTables) TargetHMark() *IPTables {
	return nil
}

func (iptables *IPTables) TargetIdleTimer() *IPTables {
	return nil
}

func (iptables *IPTables) TargetLED() *IPTables {
	return nil
}

func (iptables *IPTables) TargetLog() *IPTables {
	return nil
}

func (iptables *IPTables) TargetMark() *IPTables {
	return nil
}

func (iptables *IPTables) TargetMasquerade() *IPTables {
	return nil
}

func (iptables *IPTables) TargetMirror() *IPTables {
	return nil
}

func (iptables *IPTables) TargetNetMap() *IPTables {
	return nil
}

func (iptables *IPTables) TargetNFLog() *IPTables {
	return nil
}

func (iptables *IPTables) TargetNFQueue() *IPTables {
	return nil
}

func (iptables *IPTables) TargetNoTrack() *IPTables {
	return nil
}

func (iptables *IPTables) TargetRateEst() *IPTables {
	return nil
}

func (iptables *IPTables) TargetRedirect() *IPTables {
	return nil
}

func (iptables *IPTables) TargetReject() *IPTables {
	return nil
}

func (iptables *IPTables) TargetSame() *IPTables {
	return nil
}

func (iptables *IPTables) TargetSecMark() *IPTables {
	return nil
}

func (iptables *IPTables) TargetSet() *IPTables {
	return nil
}

func (iptables *IPTables) TargetSNAT() *IPTables {
	return nil
}

func (iptables *IPTables) TargetSNPT() *IPTables {
	return nil
}

func (iptables *IPTables) TargetSynProxy() *IPTables {
	return nil
}

func (iptables *IPTables) TargetTCPMSS() *IPTables {
	return nil
}

func (iptables *IPTables) TargetTCPOptStrip() *IPTables {
	return nil
}

func (iptables *IPTables) TargetTEE() *IPTables {
	return nil
}

func (iptables *IPTables) TargetTOS() *IPTables {
	return nil
}

func (iptables *IPTables) TargetTProxy() *IPTables {
	return nil
}

func (iptables *IPTables) TargetTrace() *IPTables {
	return nil
}

func (iptables *IPTables) TargetTTL() *IPTables {
	return nil
}

func (iptables *IPTables) TargetULog() *IPTables {
	return nil
}
