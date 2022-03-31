/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package iptables

import (
	"strconv"
	"strings"
)

type Statement struct {
	table            TableType
	chain            ChainType
	userDefinedChain string
	err              error
	matches          map[MatchType]Match
	options          map[OptionType]Option
	target           Target
	command          Command
	dump             bool
}

func NewStatement() *Statement {
	return &Statement{
		table:   TableTypeFilter,
		matches: make(map[MatchType]Match),
		options: make(map[OptionType]Option),
	}
}

func (statement *Statement) addMatch(match Match) {
	statement.matches[match.Type()] = match
}

func (statement *Statement) addOption(option Option) {
	statement.options[option.Type()] = option
}

func (statement *Statement) Elems() ([]string, error) {
	// table
	elems := []string{}
	tableName, chainName := "-t filter", ""
	switch statement.table {
	case TableTypeNat:
		tableName = "-t nat"
	case TableTypeMangle:
		tableName = "-t mangle"
	case TableTypeRaw:
		tableName = "-t raw"
	case TableTypeSecurity:
		tableName = "-t security"
	}
	elems = append(elems, tableName)

	// command
	if statement.command == nil {
		return nil, ErrCommandRequired
	}
	elems = append(elems, statement.command.Short())

	// chain
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
	if chainName == "" {
		return nil, ErrChainRequired
	}

	elems = append(elems, chainName)

	// rulenum
	hasRulenum, ok := statement.command.(HasRulenum)
	if ok && hasRulenum.Rulenum() != 0 {
		elems = append(elems, strconv.Itoa(int(hasRulenum.Rulenum())))
	}

	// options
	for _, option := range statement.options {
		args := option.ShortArgs()
		if args != nil {
			elems = append(elems, args...)
		}
	}

	// matches
	for _, match := range statement.matches {
		args := match.ShortArgs()
		if args != nil {
			elems = append(elems, args...)
		}
	}

	// target
	if statement.target != nil {
		args := statement.target.Args()
		if args != nil {
			elems = append(elems, args...)
		}
	}
	return elems, nil
}

func (statement *Statement) String() (string, error) {
	elems, err := statement.Elems()
	if err != nil {
		return "", err
	}
	return strings.Join(elems, " "), nil
}
