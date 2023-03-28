package ebtables

import "github.com/singchia/go-xtables/pkg/network"

func (ebtables *EBTables) Table(table TableType) *EBTables {
	ebtables.statement.table = table
	return ebtables
}

func (ebtables *EBTables) Chain(chain ChainType) *EBTables {
	ebtables.statement.chain = chain
	return ebtables
}

func (ebtables *EBTables) UserDefinedChain(chain string) *EBTables {
	ebtables.statement.chain = ChainTypeUserDefined
	ebtables.statement.chain.name = chain
	ebtables.statement.chain.userDefined = true
	return ebtables
}

// matches
func (ebtables *EBTables) Match802dot3(opts ...OptionMatch802dot3) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	match, err := newMatch802dot3(opts...)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
}

func (ebtables *EBTables) MatchAmong(opts ...OptionMatchAmong) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	match, err := newMatchAmong(opts...)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
}

func (ebtables *EBTables) MatchARP(opts ...OptionMatchARP) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	match, err := newMatchARP(opts...)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
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
	match, err := newMatchInInterface(invert, name)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
}

func (ebtables *EBTables) MatchIP(opts ...OptionMatchIP) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	match, err := newMatchIP(opts...)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
}

func (ebtables *EBTables) MatchIPv6(opts ...OptionMatchIPv6) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	match, err := newMatchIPv6(opts...)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
}

func (ebtables *EBTables) MatchLimit(opts ...OptionMatchLimit) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	match, err := newMatchLimit(opts...)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
}

func (ebtables *EBTables) MatchLogicalIn(invert bool, name string) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	match, err := newMatchLogicalIn(invert, name)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
}

func (ebtables *EBTables) MatchLogicalOut(invert bool, name string) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	match, err := newMatchLogicalOut(invert, name)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
}

func (ebtables *EBTables) MatchMark(invert bool, value, mask int) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	match, err := newMatchMark(invert, value, mask)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
}

func (ebtables *EBTables) MatchOutInterface(invert bool, name string) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	match, err := newMatchOutInterface(invert, name)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
}

func (ebtables *EBTables) MatchPktType(invert bool, pktType network.PktType) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	match, err := newMatchPktType(invert, pktType)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
}

func (ebtables *EBTables) MatchProtocol(invert bool, protocol network.EthernetType) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	match, err := newMatchProtocol(invert, protocol)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
}

func (ebtables *EBTables) MatchSource(invert bool, addr network.Address) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	match, err := newMatchSource(invert, addr)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
}

func (ebtables *EBTables) MatchSTP(opts ...OptionMatchSTP) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	match, err := newMatchSTP(opts...)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
}

func (ebtables *EBTables) MatchVLAN(opts ...OptionMatchVLAN) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	match, err := newMatchVLAN(opts...)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addMatch(match)
	return ebtables
}

// ebtables options
func (ebtables *EBTables) OptionConcurrent() *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	option, err := newOptionConcurrent()
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addOption(option)
	return ebtables
}

func (ebtables *EBTables) OptionListNumbers() *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	option, err := newOptionListNumbers()
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addOption(option)
	return ebtables
}

func (ebtables *EBTables) OptionModprobe(program string) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	option, err := newOptionModprobe(program)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addOption(option)
	return ebtables
}

func (ebtables *EBTables) OptionCounters(packets, bytes int64) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	option, err := newOptionCounters(packets, bytes)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addOption(option)
	return ebtables
}

func (ebtables *EBTables) OptionAtomicFile(path string) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	option, err := newOptionAtomicFile(path)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.addOption(option)
	return ebtables
}

// targets
func (ebtables *EBTables) TargetAccept() *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	target := newTargetAccept()
	ebtables.statement.target = target
	return ebtables
}

func (ebtables *EBTables) TargetDrop() *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	target := newTargetDrop()
	ebtables.statement.target = target
	return ebtables
}

func (ebtables *EBTables) TargetReturn() *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	target := newTargetReturn()
	ebtables.statement.target = target
	return ebtables
}

func (ebtables *EBTables) TargetJumpChain(chain string) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	target := newTargetJumpChain(chain)
	ebtables.statement.target = target
	return ebtables
}

func (ebtables *EBTables) TargetARPReply(opts ...OptionTargetARPReply) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	target, err := newTargetARPReply(opts...)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.target = target
	return ebtables
}

func (ebtables *EBTables) TargetDNAT(opts ...OptionTargetDNAT) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	target, err := newTargetDNAT(opts...)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.target = target
	return ebtables
}

func (ebtables *EBTables) TargetMark(opts ...OptionTargetMark) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	target, err := newTargetMark(opts...)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.target = target
	return ebtables
}

func (ebtables *EBTables) TargetRedirect(opts ...OptionTargetRedirect) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	target, err := newTargetRedirect(opts...)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.target = target
	return ebtables
}

func (ebtables *EBTables) TargetSNAT(opts ...OptionTargetSNAT) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	target, err := newTargetSNAT(opts...)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.target = target
	return ebtables
}

// ebtables watchers
func (ebtables *EBTables) WatcherLog(opts ...OptionWatcherLog) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	watcher, err := newWatcherLog(opts...)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.watchers[watcher.Type()] = watcher
	return ebtables
}

func (ebtables *EBTables) WatcherULog(opts ...OptionWatcherULog) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	watcher, err := newWatcherULog(opts...)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.watchers[watcher.Type()] = watcher
	return ebtables
}

func (ebtables *EBTables) WatcherNFLog(opts ...OptionWatcherNFLog) *EBTables {
	if ebtables.statement.err != nil {
		return ebtables
	}
	watcher, err := newWatcherNFLog(opts...)
	if err != nil {
		ebtables.statement.err = err
		return ebtables
	}
	ebtables.statement.watchers[watcher.Type()] = watcher
	return ebtables
}
