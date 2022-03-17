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
	string() string
}

type baseMatch struct {
	matchType matchType
}

func (base baseMatch) typ() matchType {
	return base.matchType
}

func (base baseMatch) string() string {
	return ""
}

type MatchIPv4 struct {
	baseMatch
}

func (iptables *IPTables) MatchIPv4() *IPTables {
	match := &MatchIPv4{
		baseMatch: baseMatch{matchIPv4},
	}
	iptables.statement.addMatch()
}
