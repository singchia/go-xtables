package iptables

type matchType int

const (
	matchAddrType matchType = iota
	matchAH
	matchBPF
	matchCgroup
	matchCluster
	matchComment
	matchConnBytes
	matchConnLabel
	matchConnLimit
	matchConnMark
	matchConnTrack
	matchCPU
	matchDCCP
	matchDevGroup
	matchDSCP
	matchDst
	matchECN
	matchESP
	matchEUI64
	matchFrag
	matchHashLimit
	matchHBH // Hop-by-Hop
	matchHelper
	matchHL // Hop Limit
	matchIcmp
	matchIcmp6
	matchIPRange
	matchIPv4
	matchIPv6
	matchIPv6Header
	matchIPVS
	matchLength
	matchLimit
	matchMAC
	matchMark
	matchMH
	matchMultiPort
	matchNFacct
	matchOSF
	matchOwner
	matchPhysDev
	matchPktType
	matchPolicy
	matchQuota
	matchRateEst
	matchRealm
	matchRecent
	matchRPFilter
	matchRT
	matchSCTP
	matchSet
	matchSocket
	matchState
	matchStatistic
	matchString
	matchTcp
)

type match interface {
	typ() matchType
	short() string
	long() long
}

type baseMatch struct {
	matchType matchType
}

func (bm baseMatch) typ() matchType {
	return bm.matchType
}

func (bm baseMatch) short() string {
	return ""
}

type MatchIPv4 struct {
	baseMatch
}

func (mIPv4 *MatchIPv4) short() {
	return "-4"
}

func (mIPv4 *MatchIPv4) long() {
	return "--ipv4"
}

type MatchIPv6 struct {
	baseMatch
}

func (mIPv6 *MatchIPv6) short() {
	return "-6"
}

func (mIPv6 *MatchIPv6) long() {
	return "--ipv6"
}

type MatchProtocol struct {
	baseMatch
}
