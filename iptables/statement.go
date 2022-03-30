/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package iptables

type Statement struct {
	table            TableType
	chain            ChainType
	userDefinedChain string
	err              error
	matches          map[MatchType]Match
	options          map[OptionType]Option
	target           Target
	command          Command
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

func (statement *Statement) Elems() ([]string, error) {
	elems := []string{}
	tableName, chainName := "-t filter", ""
	switch statement.table {
	case TableNat:
		tableName = "-t nat"
	case TableMangle:
		tableName = "-t mangle"
	case TableRaw:
		tableName = "-t raw"
	case TableSecurity:
		tableName = "-t security"
	}
	elems = append(elems, tableName)

	if chainName == "" {
		return nil, ErrNoChain
	}
	switch statement.chain {
	case ChainTypePREROUTING:
		chainName = "PREROUTING"
	case ChainTypeINPUT:
		chainName = "INPUT"
	case ChainTypeFORWARD:
		chainName = "FORWARD"
	case ChainTypeOUTPUT:
		chainName = "OUTPUT"
	case ChainTypePOSTROUTING:
		chainName = "POSTROUTING"
	case ChainTypeUserDefined:
		chainName = statement.userDefinedChain
	}
	elems = append(elems, chainName)

	options := ""
	for _, option := range statement.options {
		options += option.Short()
	}
	if options != "" {
		elems = append(elems, options)
	}

	matches := ""
	for _, match := range statement.matches {
		matches += match.Short()
	}
	if options != "" {
		elems = append(elems, matches)
	}

	if statement.target != nil {
		target := statement.target.String()
		elems = append(elems, target)
	}
	return elems, nil
}
