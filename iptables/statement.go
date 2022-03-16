package iptables

type Statement struct {
	matches map[MatchType]*Match
}
