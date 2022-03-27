package iptables

type Rule struct {
	tableType TableType
	chain     Chain
	matches   []Match
	options   []Option
	target    Target
}

func (rule *Rule) Table() Table {
	return rule.table
}

func (rule *Rule) Chain() Chain {
	return rule.chain
}

func (rule *Rule) Matches() []Match {
	return rule.matches
}

func (rule *Rule) Options() []Option {
	return rule.options
}
