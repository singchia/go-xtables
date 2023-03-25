package iptables

import "github.com/singchia/go-xtables/pkg/network"

type Rule struct {
	tableType TableType
	// chain info
	chain *Chain

	// line number
	lineNumber int

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
	prot    network.Protocol
	opt     string
}

func (rule *Rule) Table() TableType {
	return rule.tableType
}

func (rule *Rule) Chain() ChainType {
	return rule.chain.chainType
}

func (rule *Rule) Target() Target {
	return rule.target
}

func (rule *Rule) Matches() []Match {
	return rule.matches
}

func (rule *Rule) Options() []Option {
	return rule.options
}

func (rule *Rule) Protocol() network.Protocol {
	return rule.prot
}
