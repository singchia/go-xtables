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

func (rule *Rule) HasAllOptions(options map[OptionType]Option) bool {
OUTER:
	for _, opt := range options {
		for _, v := range rule.optionMap {
			ok := opt.Equal(v)
			if ok {
				continue OUTER
			}
		}
		// unmatched
		return false
	}
	return true
}

func (rule *Rule) HasAllMatches(matches map[MatchType]Match) bool {
OUTER:
	for _, mth := range matches {
		for _, v := range rule.matchMap {
			ok := mth.Equal(v)
			if ok {
				continue OUTER
			}
		}
		// unmatched
		return false
	}
	return true
}

func (rule *Rule) HasTarget(target Target) bool {
	if target == nil {
		return true
	} else if rule.target == nil {
		return false
	}
	return rule.target.Equal(target)
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
