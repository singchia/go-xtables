package ebtables

type Rule struct {
	tableType TableType
	// chain info
	chain *Chain

	// line number
	lineNumber int

	// matches
	matches  []Match
	matchMap map[MatchType]Match

	// watchers
	watchers   []Watcher
	watcherMap map[WatcherType]Watcher

	// options
	options   []Option
	optionMap map[OptionType]Option

	// target
	target Target

	packets int64
	bytes   int64
	//prot    network.Protocol
}

func (rule *Rule) TableType() TableType {
	return rule.tableType
}

func (rule *Rule) ChainType() ChainType {
	return rule.chain.chainType
}

func (rule *Rule) Matches() []Match {
	return rule.matches
}

func (rule *Rule) Options() []Option {
	return rule.options
}
