package iptables

type Rule struct {
	tableType TableType
	chainType ChainType
	matches   []Match
	options   []Option
	target    Target
}

func (rule *Rule) TableType() TableType {
	return rule.tableType
}

func (rule *Rule) ChainType() ChainType {
	return rule.chainType
}

func (rule *Rule) Matches() []Match {
	return rule.matches
}

func (rule *Rule) Options() []Option {
	return rule.options
}
