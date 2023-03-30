package ebtables

import "github.com/singchia/go-xtables/pkg/network"

func (ebtables *EBTables) Table(table TableType) *EBTables {
	newebtables := ebtables.dump()
	newebtables.statement.table = table
	return newebtables
}

func (ebtables *EBTables) Chain(chain ChainType) *EBTables {
	newebtables := ebtables.dump()
	newebtables.statement.chain = chain
	return newebtables
}

func (ebtables *EBTables) UserDefinedChain(chain string) *EBTables {
	newebtables := ebtables.dump()
	newebtables.statement.chain = ChainTypeUserDefined
	newebtables.statement.chain.name = chain
	newebtables.statement.chain.userDefined = true
	return newebtables
}

// matches
func (ebtables *EBTables) Match802dot3(opts ...OptionMatch802dot3) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	match, err := newMatch802dot3(opts...)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addMatch(match)
	return newebtables
}

func (ebtables *EBTables) MatchAmong(opts ...OptionMatchAmong) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	match, err := newMatchAmong(opts...)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addMatch(match)
	return newebtables
}

func (ebtables *EBTables) MatchARP(opts ...OptionMatchARP) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	match, err := newMatchARP(opts...)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addMatch(match)
	return newebtables
}

func (ebtables *EBTables) MatchDestination(invert bool, addr network.Address) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	match, err := newMatchDestination(invert, addr)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
}

func (ebtables *EBTables) MatchInInterface(invert bool, name string) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	match, err := newMatchInInterface(invert, name)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addMatch(match)
	return newebtables
}

func (ebtables *EBTables) MatchIP(opts ...OptionMatchIP) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	match, err := newMatchIP(opts...)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addMatch(match)
	return newebtables
}

func (ebtables *EBTables) MatchIPv6(opts ...OptionMatchIPv6) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	match, err := newMatchIPv6(opts...)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addMatch(match)
	return newebtables
}

func (ebtables *EBTables) MatchLimit(opts ...OptionMatchLimit) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	match, err := newMatchLimit(opts...)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addMatch(match)
	return newebtables
}

func (ebtables *EBTables) MatchLogicalIn(invert bool, name string) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	match, err := newMatchLogicalIn(invert, name)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addMatch(match)
	return newebtables
}

func (ebtables *EBTables) MatchLogicalOut(invert bool, name string) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	match, err := newMatchLogicalOut(invert, name)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addMatch(match)
	return newebtables
}

func (ebtables *EBTables) MatchMark(invert bool, value, mask int) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	match, err := newMatchMark(invert, value, mask)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addMatch(match)
	return newebtables
}

func (ebtables *EBTables) MatchOutInterface(invert bool, name string) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	match, err := newMatchOutInterface(invert, name)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addMatch(match)
	return newebtables
}

func (ebtables *EBTables) MatchPktType(invert bool, pktType network.PktType) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	match, err := newMatchPktType(invert, pktType)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addMatch(match)
	return newebtables
}

func (ebtables *EBTables) MatchProtocol(invert bool, protocol network.EthernetType) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	match, err := newMatchProtocol(invert, protocol)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addMatch(match)
	return newebtables
}

func (ebtables *EBTables) MatchSource(invert bool, addr network.Address) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	match, err := newMatchSource(invert, addr)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addMatch(match)
	return newebtables
}

func (ebtables *EBTables) MatchSTP(opts ...OptionMatchSTP) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	match, err := newMatchSTP(opts...)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addMatch(match)
	return newebtables
}

func (ebtables *EBTables) MatchVLAN(opts ...OptionMatchVLAN) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	match, err := newMatchVLAN(opts...)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addMatch(match)
	return newebtables
}

// ebtables options
func (ebtables *EBTables) OptionConcurrent() *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	option, err := newOptionConcurrent()
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addOption(option)
	return newebtables
}

func (ebtables *EBTables) OptionListNumbers() *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	option, err := newOptionListNumbers()
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addOption(option)
	return newebtables
}

func (ebtables *EBTables) OptionModprobe(program string) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	option, err := newOptionModprobe(program)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addOption(option)
	return newebtables
}

func (ebtables *EBTables) OptionCounters(packets, bytes int64) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	option, err := newOptionCounters(packets, bytes)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addOption(option)
	return newebtables
}

func (ebtables *EBTables) OptionAtomicFile(path string) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	option, err := newOptionAtomicFile(path)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.addOption(option)
	return newebtables
}

// targets
func (ebtables *EBTables) TargetAccept() *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	target := newTargetAccept()
	newebtables.statement.target = target
	return newebtables
}

func (ebtables *EBTables) TargetDrop() *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	target := newTargetDrop()
	newebtables.statement.target = target
	return newebtables
}

func (ebtables *EBTables) TargetReturn() *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	target := newTargetReturn()
	newebtables.statement.target = target
	return newebtables
}

func (ebtables *EBTables) TargetJumpChain(chain string) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	target := newTargetJumpChain(chain)
	newebtables.statement.target = target
	return newebtables
}

func (ebtables *EBTables) TargetARPReply(opts ...OptionTargetARPReply) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	target, err := newTargetARPReply(opts...)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.target = target
	return newebtables
}

func (ebtables *EBTables) TargetDNAT(opts ...OptionTargetDNAT) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	target, err := newTargetDNAT(opts...)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.target = target
	return newebtables
}

func (ebtables *EBTables) TargetMark(opts ...OptionTargetMark) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	target, err := newTargetMark(opts...)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.target = target
	return newebtables
}

func (ebtables *EBTables) TargetRedirect(opts ...OptionTargetRedirect) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	target, err := newTargetRedirect(opts...)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.target = target
	return newebtables
}

func (ebtables *EBTables) TargetSNAT(opts ...OptionTargetSNAT) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	target, err := newTargetSNAT(opts...)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.target = target
	return newebtables
}

// ebtables watchers
func (ebtables *EBTables) WatcherLog(opts ...OptionWatcherLog) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	watcher, err := newWatcherLog(opts...)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.watchers[watcher.Type()] = watcher
	return newebtables
}

func (ebtables *EBTables) WatcherULog(opts ...OptionWatcherULog) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	watcher, err := newWatcherULog(opts...)
	if err != nil {
		newebtables.statement.err = err
		return ebtables
	}
	newebtables.statement.watchers[watcher.Type()] = watcher
	return newebtables
}

func (ebtables *EBTables) WatcherNFLog(opts ...OptionWatcherNFLog) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	newebtables := ebtables.dump()
	watcher, err := newWatcherNFLog(opts...)
	if err != nil {
		newebtables.statement.err = err
		return newebtables
	}
	newebtables.statement.watchers[watcher.Type()] = watcher
	return newebtables
}
