/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package iptables

type Statement struct {
	table   Table
	chain   Chain
	err     error
	matches map[MatchType]Match
	options map[OptionType]Option
}

func NewStatement() *Statement {
	return &Statement{
		table:   TableFilter,
		matches: make(map[MatchType]Match),
		options: make(map[OptionType]Option),
	}
}

func (statement *Statement) addMatch(match Match) {
	statement.matches[match.typ()] = match
}

func (statement *Statement) addOption(option Option) {
	statement.options[option.typ()] = option
}
