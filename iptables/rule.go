package iptables

type Rule struct {
	tableType TableType

	// chain info
	chain *Chain

	// matches
	matches  []Match
	matchMap map[MatchType]Match

	// options
	options   []Option
	optionMap map[OptionType]Option

	// target
	target Target

	packets int64
	bytes   int64
	prot    Protocol
	opt     string
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
