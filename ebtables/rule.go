package ebtables

import (
	"strings"
)

type Rule struct {
	tableType TableType
	// chain info
	chain *Chain

	// line number
	lineNumber int

	// matches
	matchMap map[MatchType]Match

	// watchers
	watcherMap map[WatcherType]Watcher

	// options
	optionMap map[OptionType]Option

	// target
	target Target

	// counters
	packetCounter int64
	byteCounter   int64
}

func (rule *Rule) String() string {
	elems := []string{}
	// table
	elems = append(elems, "-t", rule.tableType.String())

	// chain
	elems = append(elems, rule.chain.chainType.String())

	// options
	for _, option := range rule.optionMap {
		args := option.ShortArgs()
		if args != nil {
			elems = append(elems, args...)
		}
	}

	// matches
	for _, match := range rule.matchMap {
		args := match.ShortArgs()
		if args != nil {
			elems = append(elems, args...)
		}
	}

	// watches
	for _, watcher := range rule.watcherMap {
		args := watcher.ShortArgs()
		if args != nil {
			elems = append(elems, args...)
		}
	}

	// target
	elems = append(elems, rule.target.ShortArgs()...)
	return strings.Join(elems, " ")
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

func (rule *Rule) HasAllMatchers(matches map[MatchType]Match) bool {
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

func (rule *Rule) HasAllWatchers(watchers map[WatcherType]Watcher) bool {
OUTER:
	for _, wth := range watchers {
		for _, v := range rule.watcherMap {
			ok := wth.Equal(v)
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

func (rule *Rule) TableType() TableType {
	return rule.tableType
}

func (rule *Rule) ChainType() ChainType {
	return rule.chain.chainType
}
