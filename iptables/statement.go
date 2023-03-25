package iptables

import (
	"fmt"
	"strconv"
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
	options          map[OptionType]Option
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
	option, err := newOptionNumeric()
	if err != nil {
		state.err = err
	} else {
		state.addOption(option)
	}
	return state
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
	elems = append(elems, "-t")
	tableName, chainName := "", ""
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
	if chainName != "" {
		elems = append(elems, chainName)
	}

	// command policy and rename specific
	switch statement.command.Type() {
	case CommandTypePolicy:
		elems = append(elems, statement.command.(*Policy).targetType.String())
	case CommandTypeRenameChain:
		elems = append(elems, statement.command.(*RenameChain).newChain)
	}

	// rulenum
	hasRulenum, ok := statement.command.(HasRulenum)
	if ok && hasRulenum.Rulenum() != 0 {
		elems = append(elems, strconv.Itoa(int(hasRulenum.Rulenum())))
	}

	// options
	for _, option := range statement.options {
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
	for _, match := range statement.matches {
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
