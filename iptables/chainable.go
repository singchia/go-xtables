package iptables

import (
	"io"
	"net"

	"github.com/singchia/go-xtables"
	"github.com/singchia/go-xtables/pkg/network"
)

func (iptables *IPTables) Table(table TableType) *IPTables {
	newiptables := iptables.dump()
	newiptables.statement.table = table
	return newiptables
}

func (iptables *IPTables) Chain(chain ChainType) *IPTables {
	newiptables := iptables.dump()
	newiptables.statement.chain = chain
	return newiptables
}

func (iptables *IPTables) UserDefinedChain(chain string) *IPTables {
	newiptables := iptables.dump()
	newiptables.statement.chain = ChainTypeUserDefined
	newiptables.statement.userDefinedChain = chain
	return newiptables
}

func (iptables *IPTables) Dryrun(w io.Writer) *IPTables {
	newiptables := iptables.dump()
	newiptables.dr = true
	newiptables.drWriter = w
	return newiptables
}

// matches
func (iptables *IPTables) MatchIPv4() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	newiptables := iptables.dump()
	match := newMatchIPv4()
	newiptables.statement.addMatch(match)
	return newiptables
}

func (iptables *IPTables) MatchIPv6() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	newiptables := iptables.dump()
	match := newMatchIPv6()
	newiptables.statement.addMatch(match)
	return newiptables
}

func (iptables *IPTables) MatchProtocol(invert bool, protocol network.Protocol) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	newiptables := iptables.dump()
	match := newMatchProtocol(invert, protocol)
	newiptables.statement.addMatch(match)
	return newiptables
}

// address takes:
// 1. string for hostname, network or ip
// 2. *net.IPNet
// 3. net.IP
func (iptables *IPTables) MatchSource(invert bool, address interface{}) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	ads, err := network.ParseAddress(address)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	match, _ := newMatchSource(invert, ads)
	newiptables.statement.addMatch(match)
	return newiptables
}

// address takes:
// 1. string for hostname or network or ip
// 2. *net.IPNet
// 3. net.IP
func (iptables *IPTables) MatchDestination(invert bool, address interface{}) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	ads, err := network.ParseAddress(address)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	match, _ := newMatchDestination(invert, ads)
	newiptables.statement.addMatch(match)
	return newiptables
}

func (iptables *IPTables) MatchInInterface(invert bool, iface string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	newiptables := iptables.dump()
	match, _ := newMatchInInterface(invert, iface)
	newiptables.statement.addMatch(match)
	return newiptables
}

func (iptables *IPTables) MatchOutInterface(invert bool, iface string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	newiptables := iptables.dump()
	match, _ := newMatchOutInterface(invert, iface)
	newiptables.statement.addMatch(match)
	return newiptables
}

func (iptables *IPTables) MatchAddrType(opts ...OptionMatchAddrType) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mAddrType, err := newMatchAddrType(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mAddrType)
	return newiptables
}

func (iptables *IPTables) MatchAH(opts ...OptionMatchAH) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mAH, err := newMatchAH(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mAH)
	return newiptables
}

func (iptables *IPTables) MatchBPF(opts ...OptionMatchBPF) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mBPF, err := newMatchBPF(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mBPF)
	return newiptables
}

func (iptables *IPTables) MatchCGroup(opts ...OptionMatchCGroup) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mCGroup, err := newMatchCGroup(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mCGroup)
	return newiptables
}

func (iptables *IPTables) MatchCluster(opts ...OptionMatchCluster) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mCluster, err := newMatchCluster(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mCluster)
	return newiptables
}

func (iptables *IPTables) MatchComment(comment string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mComment, err := newMatchComment(comment)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mComment)
	return newiptables
}

func (iptables *IPTables) MatchConnBytes(opts ...OptionMatchConnBytes) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mConnBytes, err := newMatchConnBytes(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mConnBytes)
	return newiptables
}

func (iptables *IPTables) MatchConnLabel(opts ...OptionMatchConnLabel) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mConnLabel, err := newMatchConnLabel(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mConnLabel)
	return newiptables
}

func (iptables *IPTables) MatchConnLimit(opts ...OptionMatchConnLimit) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mConnLimit, err := newMatchConnLimit(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mConnLimit)
	return newiptables
}

func (iptables *IPTables) MatchConnMark(invert bool, value ...int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mConnMark, err := newMatchConnMark(invert, value...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mConnMark)
	return newiptables
}

func (iptables *IPTables) MatchConnTrack(opts ...OptionMatchConnTrack) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mConnTrack, err := newMatchConnTrack(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mConnTrack)
	return newiptables
}

func (iptables *IPTables) MatchCPU(invert bool, cpu int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mCPU, err := newMatchCPU(invert, cpu)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mCPU)
	return newiptables
}

func (iptables *IPTables) MatchDCCP(opts ...OptionMatchDCCP) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mDCCP, err := newMatchDCCP(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mDCCP)
	return newiptables
}

func (iptables *IPTables) MatchDevGroup(opts ...OptionMatchDevGroup) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mDevGroup, err := newMatchDevGroup(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mDevGroup)
	return newiptables
}

func (iptables *IPTables) MatchDSCP(opts ...OptionMatchDSCP) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mDSCP, err := newMatchDSCP(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mDSCP)
	return newiptables
}

func (iptables *IPTables) MatchDst(opts ...OptionMatchDst) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mDst, err := newMatchDst(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mDst)
	return newiptables
}

func (iptables *IPTables) MatchECN(opts ...OptionMatchECN) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mECN, err := newMatchECN(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mECN)
	return newiptables
}

func (iptables *IPTables) MatchESP(invert bool, spi ...int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mESP, err := newMatchESP(invert, spi...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mESP)
	return newiptables
}

func (iptables *IPTables) MatchEUI64() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mEUI64, err := newMatchEUI64()
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mEUI64)
	return newiptables
}

func (iptables *IPTables) MatchFrag(opts ...OptionMatchFrag) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mFrag, err := newMatchFrag(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mFrag)
	return newiptables
}

func (iptables *IPTables) MatchHBH(opts ...OptionMatchHBH) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mHBH, err := newMatchHBH(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mHBH)
	return newiptables
}

func (iptables *IPTables) MatchHelper(helper string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mHelper, err := newMatchHelper(helper)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mHelper)
	return newiptables
}

func (iptables *IPTables) MatchHL(operator xtables.Operator, value int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mHL, err := newMatchHL(operator, value)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mHL)
	return newiptables
}

func (iptables *IPTables) MatchICMP(invert bool, typ network.ICMPType,
	opts ...OptionMatchICMP) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mICMP, err := newMatchICMP(invert, typ, opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mICMP)
	return newiptables
}

func (iptables *IPTables) MatchIPRange(opts ...OptionMatchIPRange) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mIPRange, err := newMatchIPRange(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mIPRange)
	return newiptables
}

func (iptables *IPTables) MatchIPv6Header(opts ...OptionMatchIPv6Header) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mIPv6Header, err := newMatchIPv6Header(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mIPv6Header)
	return newiptables
}

func (iptables *IPTables) MatchIPVS(opts ...OptionMatchIPVS) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mIPVS, err := newMatchIPVS(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mIPVS)
	return newiptables
}

func (iptables *IPTables) MatchLength(invert bool, length ...int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mLength, err := newMatchLength(invert, length...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mLength)
	return newiptables
}

func (iptables *IPTables) MatchLimit(opts ...OptionMatchLimit) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mLimit, err := newMatchLimit(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mLimit)
	return newiptables
}

func (iptables *IPTables) MatchMAC(invert bool, mac net.HardwareAddr) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mMAC, err := newMatchMAC(invert, mac)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mMAC)
	return newiptables
}

func (iptables *IPTables) MatchMark(invert bool, value ...int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mMark, err := newMatchMark(invert, value...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mMark)
	return newiptables
}

func (iptables *IPTables) MatchMH(invert bool, typ ...MHType) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mMH, err := newMatchMH(invert, typ...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mMH)
	return newiptables
}

func (iptables *IPTables) MatchMultiPort(opts ...OptionMatchMultiPort) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mMultiPort, err := newMatchMultiPort(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mMultiPort)
	return newiptables
}

func (iptables *IPTables) MatchNFAcct(name string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mNFAcct, err := newMatchNFAcct(name)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mNFAcct)
	return newiptables
}

func (iptables *IPTables) MatchOSF(opts ...OptionMatchOSF) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mOSF, err := newMatchOSF(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mOSF)
	return newiptables
}

func (iptables *IPTables) MatchOwner(opts ...OptionMatchOwner) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mOwner, err := newMatchOwner(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mOwner)
	return newiptables
}

func (iptables *IPTables) MatchPhysDev(opts ...OptionMatchPhysDev) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mPhysDev, err := newMatchPhysDev(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mPhysDev)
	return newiptables
}

func (iptables *IPTables) MatchPktType(invert bool, pktType PktType) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mPktType, err := newMatchPktType(invert, pktType)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mPktType)
	return newiptables
}

func (iptables *IPTables) MatchPolicy(opts ...OptionMatchPolicy) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mPolicy, err := newMatchPolicy(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mPolicy)
	return newiptables
}

func (iptables *IPTables) MatchQuota(invert bool, quota int64) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mQuota, err := newMatchQuota(invert, quota)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mQuota)
	return newiptables
}

func (iptables *IPTables) MatchRateEst(opts ...OptionMatchRateEst) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mRateEst, err := newMatchRateEst(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mRateEst)
	return newiptables
}

func (iptables *IPTables) MatchRealm(invert bool, value ...int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mRealm, err := newMatchRealm(invert, value...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mRealm)
	return newiptables
}

func (iptables *IPTables) MatchRecent(opts ...OptionMatchRecent) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mRecent, err := newMatchRecent(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mRecent)
	return newiptables
}

func (iptables *IPTables) MatchRPFilter(opts ...OptionMatchRPFilter) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mRPFilter, err := newMatchRPFilter(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mRPFilter)
	return newiptables
}

func (iptables *IPTables) MatchRT(opts ...OptionMatchRT) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mRT, err := newMatchRT(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mRT)
	return newiptables
}

func (iptables *IPTables) MatchSCTP(opts ...OptionMatchSCTP) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mSCTP, err := newMatchSCTP(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mSCTP)
	return newiptables
}

func (iptables *IPTables) MatchSet(opts ...OptionMatchSet) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mSet, err := newMatchSet(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mSet)
	return newiptables
}

func (iptables *IPTables) MatchSocket(opts ...OptionMatchSocket) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mSocket, err := newMatchSocket(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mSocket)
	return newiptables
}

func (iptables *IPTables) MatchState(state ConnTrackState) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mState, err := newMatchState(state)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mState)
	return newiptables
}

func (iptables *IPTables) MatchStatistic(opts ...OptionMatchStatistic) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mStatistic, err := newMatchStatistic(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mStatistic)
	return newiptables
}

func (iptables *IPTables) MatchString(opts ...OptionMatchString) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mString, err := newMatchString(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mString)
	return newiptables
}

func (iptables *IPTables) MatchTCP(opts ...OptionMatchTCP) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mTCP, err := newMatchTCP(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mTCP)
	return newiptables
}

func (iptables *IPTables) MatchTCPMSS(invert bool, mss ...int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mTCPMSS, err := newMatchTCPMSS(invert, mss...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mTCPMSS)
	return newiptables
}

func (iptables *IPTables) MatchTime(opts ...OptionMatchTime) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mTime, err := newMatchTime(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mTime)
	return newiptables
}

func (iptables *IPTables) MatchTOS(invert bool, tos ...network.TOS) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mTOS, err := newMatchTOS(invert, tos...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mTOS)
	return newiptables
}

func (iptables *IPTables) MatchTTL(opts ...OptionMatchTTL) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mTTL, err := newMatchTTL(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mTTL)
	return newiptables
}

func (iptables *IPTables) MatchU32(invert bool, tests string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mU32, err := newMatchU32(invert, tests)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mU32)
	return newiptables
}

func (iptables *IPTables) MatchUDP(opts ...OptionMatchUDP) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	mUDP, err := newMatchUDP(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addMatch(mUDP)
	return newiptables
}

// iptables options
func (iptables *IPTables) OptionFragment(invert bool) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	option, err := newOptionFragment(invert)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addOption(option)
	return newiptables
}

func (iptables *IPTables) OptionSetCounters(packets, bytes uint64) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	option, err := newOptionCounters(packets, bytes)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addOption(option)
	return newiptables
}

func (iptables *IPTables) OptionVerbose() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	option, err := newOptionVerbose()
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addOption(option)
	return newiptables
}

// 0 means indefinitely
func (iptables *IPTables) OptionWait(seconds uint32) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	option, err := newOptionWait(seconds)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addOption(option)
	return newiptables
}

func (iptables *IPTables) OptionWaitInterval(microseconds uint64) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	option, err := newOptionWaitInterval(microseconds)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addOption(option)
	return newiptables
}

func (iptables *IPTables) OptionExact() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	option, err := newOptionExact()
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addOption(option)
	return newiptables
}

func (iptables *IPTables) OptionLineNumbers() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	option, err := newOptionLineNumbers()
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addOption(option)
	return newiptables
}

func (iptables *IPTables) OptionModprobe(command string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	option, err := newOptionModprobe(command)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.addOption(option)
	return newiptables
}

// targets
func (iptables *IPTables) TargetAccept() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	newiptables := iptables.dump()
	target := newTargetAccept()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetDrop() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	newiptables := iptables.dump()
	target := newTargetDrop()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetReturn() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	newiptables := iptables.dump()
	target := newTargetAccept()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetJumpChain(chain string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	newiptables := iptables.dump()
	target := newTargetJumpChain(chain)
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetGotoChain(chain string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	newiptables := iptables.dump()
	target := newTargetGotoChain(chain)
	newiptables.statement.chain = ChainTypeUserDefined
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetAudit(typ AuditType) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetAudit(typ)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetCheckSum() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetCheckSum()
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetClassify(major, minor int) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetClassify(major, minor)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetClusterIP(opts ...OptionTargetClusterIP) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetClusterIP(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetConnMark(opts ...OptionTargetConnMark) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetConnMark(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetConnSecMark(mode TargetConnSecMarkMode) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetConnSecMark(mode)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetCT(opts ...OptionTargetCT) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetCT(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetDNAT(opts ...OptionTargetDNAT) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetDNAT(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetDNPT(opts ...OptionTargetDNPT) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetDNPT(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetDSCP(opts ...OptionTargetDSCP) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetDSCP(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetECN(opts ...OptionTargetECN) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetECN(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetHL(opts ...OptionTargetHL) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetHL(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetHMark(opts ...OptionTargetHMark) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetHMark(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetIdleTimer(opts ...OptionTargetIdleTimer) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetIdleTimer(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetLED(opts ...OptionTargetLED) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetLED(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetLog(opts ...OptionTargetLog) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetLog(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetMark(opts ...OptionTargetMark) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetMark(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetMasquerade(opts ...OptionTargetMasquerade) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetMasquerade(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetNetMap(opts ...OptionTargetNetmap) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetNetmap(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetNFLog(opts ...OptionTargetNFLog) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetNFLog(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetNFQueue(opts ...OptionTargetNFQueue) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetNFQueue(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetRateEst(opts ...OptionTargetRateEst) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetRateEst(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetRedirect(opts ...OptionTargetRedirect) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetRedirect(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetReject(opts ...OptionTargetReject) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetReject(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetSame(opts ...OptionTargetSame) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetSame(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetSecMark(opts ...OptionTargetSecMark) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetSecMark(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetSet(opts ...OptionTargetSet) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetSet(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetSNAT(opts ...OptionTargetSNAT) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetSNAT(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetSNPT(opts ...OptionTargetSNPT) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetSNPT(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetSynProxy(opts ...OptionTargetSYNProxy) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetSYNProxy(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetTCPMSS(opts ...OptionTargetTCPMSS) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetTCPMSS(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetTCPOptStrip(opts ...OptionTargetTCPOptStrip) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetTCPOptStrip(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetTEE(gateway net.IP) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetTEE(gateway)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetTOS(opts ...OptionTargetTOS) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetTOS(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetTProxy(opts ...OptionTargetTProxy) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetTProxy(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetTrace() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetTrace()
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetTTL(opts ...OptionTargetTTL) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetTTL(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}

func (iptables *IPTables) TargetULog(opts ...OptionTargetULog) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	target, err := newTargetULog(opts...)
	if err != nil {
		iptables.statement.err = err
		return iptables
	}
	newiptables := iptables.dump()
	newiptables.statement.target = target
	return newiptables
}
