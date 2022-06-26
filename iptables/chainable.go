/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package iptables

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
