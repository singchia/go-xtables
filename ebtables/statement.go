package ebtables

import (
	"strings"

	"github.com/singchia/go-xtables"
)

type Statement struct {
	err      error
	table    TableType
	chain    ChainType
	matches  map[MatchType]Match
	options  map[OptionType]Option
	watchers map[WatcherType]Watcher
	target   Target
	command  Command

	// TODO
	// constraints *constraints
}

func NewStatement() *Statement {
	state := &Statement{
		table:    TableTypeNull,
		chain:    ChainTypeNull,
		matches:  make(map[MatchType]Match),
		options:  make(map[OptionType]Option),
		watchers: make(map[WatcherType]Watcher),
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
	tableName := "filter"
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
	// chain
	if statement.command.Type() != CommandTypeAtomicInit &&
		statement.command.Type() != CommandTypeAtomicSave &&
		statement.command.Type() != CommandTypeAtomicCommit {

		statement.command.SetChainType(statement.chain)
		elems = append(elems, statement.command.ShortArgs()...)
	}

	// command tails
	switch statement.command.Type() {
	case CommandTypeList, CommandTypeListRules, CommandTypeListChains:
		// default with --Ln --Lc --Lmac2
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

	case CommandTypeDump:
		// default with --Lx
		lx, ok := statement.options[OptionTypeListChange]
		if ok {
			elems = append(elems, lx.ShortArgs()...)
			delete(statement.options, OptionTypeListChange)
		}
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

	// watcher
	for _, watcher := range statement.watchers {
		args := watcher.ShortArgs()
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

	// atomic-xxx command
	if statement.command.Type() == CommandTypeAtomicInit ||
		statement.command.Type() == CommandTypeAtomicSave ||
		statement.command.Type() == CommandTypeAtomicCommit {
		elems = append(elems, statement.command.ShortArgs()...)
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
