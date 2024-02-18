package iptables

import (
	"fmt"
	"strings"

	"github.com/singchia/go-xtables"
	"github.com/singchia/go-xtables/pkg/constraint"
)

type Statement struct {
	err              error
	table            TableType
	chain            ChainType
	userDefinedChain string
	matches          map[MatchType]Match
	matchTypeOrder   []MatchType
	options          map[OptionType]Option
	optionTypeOrder  []OptionType
	target           Target
	command          Command
	dump             bool

	// TODO
	constraints *constraint.Constraints
}

func NewStatement() *Statement {
	state := &Statement{
		table:       TableTypeNull,
		matches:     make(map[MatchType]Match),
		options:     make(map[OptionType]Option),
		constraints: constraint.NewConstraints(),
	}
	return state
}

func (statement *Statement) addMatch(match Match) {
	if _, ok := statement.matches[match.Type()]; !ok {
		statement.matchTypeOrder = append(statement.matchTypeOrder, match.Type())
	}
	statement.matches[match.Type()] = match
}

func (statement *Statement) addOption(option Option) {
	if _, ok := statement.options[option.Type()]; !ok {
		statement.optionTypeOrder = append(statement.optionTypeOrder, option.Type())
	}
	statement.options[option.Type()] = option
}

func (statement *Statement) Elems() ([]string, error) {
	// table
	elems := []string{}
	elems = append(elems, "-t")
	tableName := ""
	switch statement.table {
	case TableTypeFilter:
		tableName = "filter"
	case TableTypeNat:
		tableName = "nat"
	case TableTypeMangle:
		tableName = "mangle"
	case TableTypeRaw:
		tableName = "raw"
	case TableTypeSecurity:
		tableName = "security"
	}
	elems = append(elems, tableName)

	// command
	if statement.command == nil {
		return nil, xtables.ErrCommandRequired
	}

	// chain
	statement.command.SetChainType(statement.chain)
	elems = append(elems, statement.command.ShortArgs()...)

	// coammnd tails
	switch statement.command.Type() {
	case CommandTypeList, CommandTypeListChains, CommandTypeListRules, CommandTypeFind:
		// default with -n --line-numbers -x -v
		numeric, ok := statement.options[OptionTypeNumeric]
		if ok {
			elems = append(elems, numeric.ShortArgs()...)
			delete(statement.options, OptionTypeNumeric)
		}
		ln, ok := statement.options[OptionTypeLineNumbers]
		if ok {
			elems = append(elems, ln.ShortArgs()...)
			delete(statement.options, OptionTypeLineNumbers)
		}
		exact, ok := statement.options[OptionTypeExact]
		if ok {
			elems = append(elems, exact.ShortArgs()...)
			delete(statement.options, OptionTypeExact)
		}
		verbose, ok := statement.options[OptionTypeVerbose]
		if ok {
			elems = append(elems, verbose.ShortArgs()...)
			delete(statement.options, OptionTypeVerbose)
		}
	case CommandTypeDumpRules:
		verbose, ok := statement.options[OptionTypeVerbose]
		if ok {
			elems = append(elems, verbose.ShortArgs()...)
			delete(statement.options, OptionTypeVerbose)
		}
	}

	// options
	for _, optionType := range statement.optionTypeOrder {
		option, ok := statement.options[optionType]
		if !ok {
			continue
		}

		args := option.ShortArgs()
		if args != nil {
			if option.Type() != OptionTypeNumeric ||
				(option.Type() == OptionTypeNumeric &&
					statement.command.Type() == CommandTypeListRules) {
				elems = append(elems, args...)
			}
		}
		if option.Type() == OptionTypeNotNumeric {
			delete(statement.options, OptionTypeNumeric)
		}
	}

	// matches
	for _, matchType := range statement.matchTypeOrder {
		match, ok := statement.matches[matchType]
		if !ok {
			continue
		}
		args := match.ShortArgs()
		if args != nil {
			elems = append(elems, args...)
		}
	}

	// target
	if statement.target != nil {
		args := statement.target.ShortArgs()
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

func (statement *Statement) Conflict() error {
	constraints := statement.constraints
	// table-chain
	conflict := constraints.Conflict(
		statement.table.Type(),
		statement.table.Value(),
		statement.chain.Type(),
		statement.chain.Value(),
	)
	if conflict {
		return fmt.Errorf("table %s conflict with chain %s",
			statement.table.Value(),
			statement.chain.Value(),
		)
	}
	return nil
}
