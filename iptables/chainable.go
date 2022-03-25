/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package iptables

type TableType int

const (
	TableFilter   TableType = iota // filter
	TableNat                       // nat
	TableMangle                    // mangle
	TableRaw                       // raw
	TableSecutiry                  // security
)

func (iptables *IPTables) Table(table TableType) *IPTables {
	iptables.statement.table = table
	return iptables
}

func (iptables *IPTables) Chain(chain ChainType) *IPTables {
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

func (iptables *IPTables) MatchProtocol(not bool, protocol Protocol) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	match := &MatchProtocol{
		baseMatch: baseMatch{
			matchType: matchProtocol,
			invert:    not,
		},
	}
	iptables.statement.addMatch(match)
	return iptables
}

// address takes:
// 1. string for hostname or network or ip
// 2. *net.IPNet
// 3. net.IP
func (iptables *IPTables) MatchSource(not bool, address interface{}) *IPTables {
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
			invert:    not,
		},
	}
	iptables.statement.addMatch(match)
	return iptables
}

// address takes:
// 1. string for hostname or network or ip
// 2. *net.IPNet
// 3. net.IP
func (iptables *IPTables) MatchDestination(not bool, address interface{}) *IPTables {
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
			invert:    not,
		},
	}
	iptables.statement.addMatch(match)
	return iptables
}

func (iptables *IPTables) MatchInInterface(not bool, name string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	match := &MatchInInterface{
		baseMatch: baseMatch{
			matchType: matchInInterface,
			invert:    not,
		},
	}
	iptables.statement.addMatch(match)
	return iptables
}

func (iptables *IPTables) MatchOutInterface(not bool, name string) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	match := &MatchOutInterface{
		baseMatch: baseMatch{
			matchType: matchOutInterface,
			invert:    not,
		},
	}
	iptables.statement.addMatch(match)
	return iptables
}

func (iptables *IPTables) OptionFragment(not bool) *IPTables {
	if iptables.statement.err != nil {
		return iptables
	}
	option := &OptionFragment{
		baseOption: baseOption{
			optionType: optionFragment,
			invert:     not,
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
			optionType: optionSetCounters,
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
			optionType: optionVerbose,
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
			optionType: optionWait,
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
			optionType: optionWaitInterval,
		},
		microseconds: microseconds,
	}
	iptables.statement.addOption(option)
	return iptables
}
