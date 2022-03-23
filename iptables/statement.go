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
	matches map[matchType]match
	options map[optionType]option
}

func NewStatement() *Statement {
	return &Statement{
		table:   TableFilter,
		matches: make(map[matchType]match),
		options: make(map[optionType]option),
	}
}

func (statement *Statement) addMatch(match match) {
	statement.matches[match.typ()] = match
}

func (statement *Statement) addOption(option option) {
	statement.options[option.typ()] = option
}
