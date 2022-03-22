/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package iptables

type Table string
type Chain string

const (
	TableFilter   Table = "filter"
	TableNat      Table = "nat"
	TableMangle   Table = "mangle"
	TableRaw      Table = "raw"
	TableSecutiry Table = "security"

	ChainPREROUTING  Chain = "PREROUTING"
	ChainINPUT       Chain = "INPUT"
	ChainFORWARD     Chain = "FORWARD"
	ChainOUTPUT      Chain = "OUTPUT"
	ChainPOSTROUTING Chain = "POSTROUTING"
)

func (iptables *IPTables) Table(table Table) *IPTables {
	iptables.statement.table = table
	return iptables
}

func (iptables *IPTables) Chain(chain Chain) *IPTables {
	iptables.statement.chain = chain
	return iptables
}

func (iptables *IPTables) MatchIPv4() *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	match := &MatchIPv4{
		baseMatch: baseMatch{
			matchType: matchIPv4,
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
			matchType: matchIPv6,
		},
	}
	iptables.statement.addMatch(match)
	return iptables
}

func (iptables *IPTables) MatchProtocol(protocol Protocol) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	match := &MatchProtocol{
		baseMatch: baseMatch{
			matchType: matchProtocol,
			invert:    false,
		},
	}
	iptables.statement.addMatch(match)
	return iptables
}

func (iptables *IPTables) NotMatchProtocol(protocol Protocol) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	match := &MatchProtocol{
		baseMatch: baseMatch{
			matchType: matchProtocol,
			invert:    true,
		},
	}
	iptables.statement.addMatch(match)
	return iptables
}

// address takes:
// 1. string for hostname or network or ip
// 2. *net.IPNet
// 3. net.IP
func (iptables *IPTables) MatchSource(address interface{}) *IPTables {
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
			matchType: matchSource,
			invert:    false,
		},
	}
	iptables.statement.addMatch(match)
	return iptables
}

// address takes:
// 1. string for hostname or network or ip
// 2. *net.IPNet
// 3. net.IP
func (iptables *IPTables) NotMatchSource(address interface{}) *IPTables {
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
			matchType: matchSource,
			invert:    true,
		},
	}
	iptables.statement.addMatch(match)
	return iptables
}

// address takes:
// 1. string for hostname or network or ip
// 2. *net.IPNet
// 3. net.IP
func (iptables *IPTables) MatchDestination(address interface{}) *IPTables {
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
			matchType: matchDestination,
			invert:    false,
		},
	}
	iptables.statement.addMatch(match)
	return iptables
}

// address takes:
// 1. string for hostname or network or ip
// 2. *net.IPNet
// 3. net.IP
func (iptables *IPTables) NotMatchDestination(address interface{}) *IPTables {
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
			matchType: matchDestination,
			invert:    true,
		},
	}
	iptables.statement.addMatch(match)
	return iptables
}
