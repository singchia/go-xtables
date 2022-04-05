package iptables

type Rule struct {
	tableType TableType
	chain     *Chain
	matches   []Match
	options   []Option
	target    Target
	packets   int64
	bytes     int64
	prot      string
	opt       string
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
