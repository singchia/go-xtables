package ebtables

import (
	"strings"

	"github.com/singchia/go-xtables"
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
	watcher          Watcher

	// TODO
	// constraints *constraints
}

func NewStatement() *Statement {
	state := &Statement{
		table:   TableTypeNull,
		chain:   ChainTypeNull,
		matches: make(map[MatchType]Match),
		options: make(map[OptionType]Option),
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
	tableName, chainName := "filter", ""
	switch statement.table {
	case TableTypeNat:
		tableName = "nat"
	case TableTypeBRoute:
		tableName = "broute"
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
	case ChainTypeBROUTING:
		chainName = "BROUTING"
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
		elems = append(elems,
			statement.command.(*Policy).targetType.String())
	case CommandTypeRenameChain:
		elems = append(elems, statement.command.(*RenameChain).newname)
	case CommandTypeListRules, CommandTypeListChains:
		ln, ok := statement.options[OptionTypeListNumbers]
		if ok {
			elems = append(elems, ln.ShortArgs()...)
			delete(statement.options, OptionTypeListNumbers)
		}
		lc, ok := statement.options[OptionTypeListCounters]
		if ok {
			elems = append(elems, lc.ShortArgs()...)
			delete(statement.options, OptionTypeListCounters)
		}
		lmac2, ok := statement.options[OptionTypeListMACSameLength]
		if ok {
			elems = append(elems, lmac2.ShortArgs()...)
			delete(statement.options, OptionTypeListMACSameLength)
		}
	}

	/*
		// rulenum
		hasRulenum, ok := statement.command.(HasRulenum)
		if ok && hasRulenum.Rulenum() != 0 {
			elems = append(elems, strconv.Itoa(int(hasRulenum.Rulenum())))
		}
	*/

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
