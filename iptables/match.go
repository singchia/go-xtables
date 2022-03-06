package iptables

type MatchType int

const (
	MatchAddrType MatchType = iota
	MatchAH
	MatchBPF
	MatchCgroup
	MatchCluster
	MatchComment
	MatchConnBytes
	MatchConnLabel
	MatchConnLimit
	MatchConnMark
	MatchConnTrack
	MatchCPU
	MatchDCCP
	MatchDevGroup
	MatchDSCP
	MatchDst
	MatchECN
	MatchESP
	MatchEUI64
	MatchFrag
	MatchHashLimit
	MatchHBH // Hop-by-Hop
	MatchHelper
	MatchHL // Hop Limit
	MatchIcmp
	MatchIcmp6
	MatchIPRange
	MatchIPv6Header
	MatchIPVS
	MatchLength
	MatchLimit
	MatchMAC
	MatchMark
	MatchMH
	MatchMultiPort
	MatchNFacct
	MatchOSF
	MatchOwner
	MatchPhysDev
	MatchPktType
	MatchPolicy
	MatchQuota
	MatchRateEst
	MatchRealm
	MatchRecent
	MatchRPFilter
	MatchRT
	MatchSCTP
	MatchSet
	MatchSocket
	MatchState
	MatchStatistic
	MatchString
	MatchTcp
)

type Match struct{}
