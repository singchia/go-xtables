package ebtables

import (
	"github.com/singchia/go-xtables"
	"github.com/singchia/go-xtables/pkg/cmd"
)

func (ebtables *EBTables) exec() ([]byte, error) {
	elems, err := ebtables.statement.Elems()
	if err != nil {
		return nil, err
	}
	infoO, infoE, err := cmd.Cmd(ebtables.cmdName, elems...)
	if err != nil {
		return infoE, err
	}
	return infoO, nil
}

func (ebtables *EBTables) Append() error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	command := newAppend(ChainTypeNull)
	ebtables.statement.command = command
	data, err := ebtables.exec()
	if err != nil {
		return xtables.ErrAndStdErr(err, data)
	}
	return nil
}

func (ebtables *EBTables) ChangeCounters(opts ...OptionCommandChangeCounters) error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	command := newChangeCounters(ChainTypeNull, opts...)
	ebtables.statement.command = command
	data, err := ebtables.exec()
	if err != nil {
		return xtables.ErrAndStdErr(err, data)
	}
	return nil
}

func (ebtables *EBTables) Delete(opts ...OptionCommandDelete) error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	command := newDelete(ChainTypeNull, opts...)
	ebtables.statement.command = command
	data, err := ebtables.exec()
	if err != nil {
		return xtables.ErrAndStdErr(err, data)
	}
	return nil
}

func (ebtables *EBTables) DeleteAll(opts ...OptionCommandDelete) error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	command := newDelete(ChainTypeNull, opts...)
	ebtables.statement.command = command
	for {
		data, err := ebtables.exec()
		if err == nil {
			continue
		}
		ce := xtables.ErrAndStdErr(err, data)
		if ce.(*xtables.CommandError).IsRuleNotExistError() {
			break
		}
		return err
	}
	return nil
}

func (ebtables *EBTables) Insert(opts ...OptionCommandInsert) error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	command := newInsert(ChainTypeNull, opts...)
	ebtables.statement.command = command
	data, err := ebtables.exec()
	if err != nil {
		return xtables.ErrAndStdErr(err, data)
	}
	return nil
}

func (ebtables *EBTables) FindChains() ([]*Chain, error) {
	if ebtables.statement.err != nil {
		return nil, ebtables.statement.err
	}
	chainType := ebtables.statement.chain
	ebtables.statement.chain = ChainTypeNull

	command := newList(ChainTypeNull)
	ebtables.statement.command = command

	data, err := ebtables.exec()
	if err != nil {
		return nil, xtables.ErrAndStdErr(err, data)
	}

	chains, _, err := parse(data, parseTable, parseChain, nil)
	if err != nil {
		return nil, err
	}
	foundChains := []*Chain{}
	for _, chain := range chains {
		if chain.chainType.chainType == chainTypeUserDefined &&
			chain.chainType.name != chainType.name {
			continue
		}
		if chain.chainType.chainType == chainTypeUserDefined &&
			chain.chainType.name == chainType.name {
			foundChains = append(foundChains, chain)
			continue
		}
		if chain.chainType == chainType {
			foundChains = append(foundChains, chain)
		}
	}
	return foundChains, nil
}

func (ebtables *EBTables) FindRules() ([]*Rule, error) {
	if ebtables.statement.err != nil {
		return nil, ebtables.statement.err
	}
	optionsMap := ebtables.statement.options
	matchesMap := ebtables.statement.matches
	watchersMap := ebtables.statement.watchers
	target := ebtables.statement.target
	ebtables.statement.options = make(map[OptionType]Option)
	ebtables.statement.matches = make(map[MatchType]Match)
	ebtables.statement.watchers = make(map[WatcherType]Watcher)
	ebtables.statement.target = nil

	// search with table or chain
	command := newList(ChainTypeNull)
	ebtables.statement.command = command
	ebtables.statement.options[OptionTypeListNumbers], _ = newOptionListNumbers()
	ebtables.statement.options[OptionTypeListCounters], _ = newOptionListCounters()
	ebtables.statement.options[OptionTypeListMACSameLength], _ = newOptionListMACSameLength()

	data, err := ebtables.exec()
	if err != nil {
		return nil, xtables.ErrAndStdErr(err, data)
	}
	_, rules, err := parse(data, parseTable, parseChain, parseRule)
	if err != nil {
		return nil, err
	}
	foundRules := []*Rule{}
	for _, rule := range rules {
		yes := rule.HasAllOptions(optionsMap)
		if !yes {
			continue
		}
		yes = rule.HasAllMatchers(matchesMap)
		if !yes {
			continue
		}
		yes = rule.HasAllWatchers(watchersMap)
		if !yes {
			continue
		}
		yes = rule.HasTarget(target)
		if !yes {
			continue
		}
		foundRules = append(foundRules, rule)
	}
	return foundRules, nil
}

// ListRules can't be chained with matched, options and targets.
func (ebtables *EBTables) ListRules() ([]*Rule, error) {
	if ebtables.statement.err != nil {
		return nil, ebtables.statement.err
	}
	command := newListRules(ChainTypeNull)
	ebtables.statement.command = command
	ebtables.statement.options[OptionTypeListNumbers], _ = newOptionListNumbers()
	ebtables.statement.options[OptionTypeListCounters], _ = newOptionListCounters()
	ebtables.statement.options[OptionTypeListMACSameLength], _ = newOptionListMACSameLength()
	data, err := ebtables.exec()
	if err != nil {
		return nil, xtables.ErrAndStdErr(err, data)
	}
	_, rules, err := parse(data, parseTable, parseChain, parseRule)
	return rules, err
}

// ListChains can't be chained with matched, options and targets.
func (ebtables *EBTables) ListChains() ([]*Chain, error) {
	if ebtables.statement.err != nil {
		return nil, ebtables.statement.err
	}
	command := newListChains(ChainTypeNull)
	ebtables.statement.command = command
	ebtables.statement.options[OptionTypeListNumbers], _ = newOptionListNumbers()
	ebtables.statement.options[OptionTypeListCounters], _ = newOptionListCounters()
	ebtables.statement.options[OptionTypeListMACSameLength], _ = newOptionListMACSameLength()
	data, err := ebtables.exec()
	if err != nil {
		return nil, xtables.ErrAndStdErr(err, data)
	}
	chains, _, err := parse(data, parseTable, parseChain, parseRule)
	return chains, err
}

func (ebtables *EBTables) Dump() ([]string, error) {
	if ebtables.statement.err != nil {
		return nil, ebtables.statement.err
	}
	command := newDump(ChainTypeNull)
	ebtables.statement.command = command
	ebtables.statement.options[OptionTypeListChange], _ = newOptionListChange()
	data, err := ebtables.exec()
	if err != nil {
		return nil, xtables.ErrAndStdErr(err, data)
	}
	return dump(data)
}

// If no table specified, the delete-chain will be applied to all tables
func (ebtables *EBTables) DeleteChain() error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	var tables []TableType
	if ebtables.statement.table == TableTypeNull {
		tables = []TableType{TableTypeFilter, TableTypeNat, TableTypeBRoute}
	} else {
		tables = []TableType{ebtables.statement.table}
	}

	for _, table := range tables {
		ebtables.Table(table)
		command := newDeleteChain()
		ebtables.statement.command = command
		data, err := ebtables.exec()
		if err != nil {
			return xtables.ErrAndStdErr(err, data)
		}
	}
	return nil
}

func (ebtables *EBTables) RenameChain(name string) error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	command := newRenameChain(ChainTypeNull, name)
	ebtables.statement.command = command
	data, err := ebtables.exec()
	if err != nil {
		return xtables.ErrAndStdErr(err, data)
	}
	return nil
}

// if no table specified, the flush will be applied to all tables
func (ebtables *EBTables) Flush() error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	var tables []TableType
	if ebtables.statement.table == TableTypeNull {
		tables = []TableType{TableTypeFilter, TableTypeNat, TableTypeBRoute}
	} else {
		tables = []TableType{ebtables.statement.table}
	}

	for _, table := range tables {
		ebtables.Table(table)
		command := newFlush(ChainTypeNull)
		ebtables.statement.command = command
		data, err := ebtables.exec()
		if err != nil {
			return xtables.ErrAndStdErr(err, data)
		}
	}
	return nil
}

// If no table specified, the delete-chain will be applied to all tables
// If no chain specified, the policy will be applied to all build-in chains.
func (ebtables *EBTables) Policy(target TargetType) error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	if target != TargetTypeAccept &&
		target != TargetTypeDrop &&
		target != TargetTypeReturn {
		return xtables.ErrIllegalTargetType
	}
	var tables []TableType
	if ebtables.statement.table == TableTypeNull {
		tables = []TableType{TableTypeFilter, TableTypeNat, TableTypeBRoute}
	} else {
		tables = []TableType{ebtables.statement.table}
	}

	if ebtables.statement.chain == ChainTypeNull {
		for _, table := range tables {
			for _, chain := range TableChains[table] {
				newebtables := ebtables.Table(table).Chain(chain)
				newebtables.statement.command = newPolicy(ChainTypeNull, target)
				data, err := newebtables.exec()
				if err != nil {
					return xtables.ErrAndStdErr(err, data)
				}
			}
		}
		return nil
	} else {
		for _, table := range tables {
			newebtables := ebtables.Table(table)
			newebtables.statement.command = newPolicy(ChainTypeNull, target)
			data, err := newebtables.exec()
			if err != nil {
				return xtables.ErrAndStdErr(err, data)
			}
		}
		return nil
	}
}

func (ebtables *EBTables) Zero() error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	command := newZero(ChainTypeNull)
	ebtables.statement.command = command
	data, err := ebtables.exec()
	if err != nil {
		return xtables.ErrAndStdErr(err, data)
	}
	return nil
}

func (ebtables *EBTables) NewChain(chainName string) error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	command := newNewChain(chainName)
	ebtables.statement.command = command
	data, err := ebtables.exec()
	if err != nil {
		return xtables.ErrAndStdErr(err, data)
	}
	return nil
}

func (ebtables *EBTables) InitTable() error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	command := newInitTable()
	ebtables.statement.command = command
	data, err := ebtables.exec()
	if err != nil {
		return xtables.ErrAndStdErr(err, data)
	}
	return nil
}

func (ebtables *EBTables) AtomicInit() error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	command := newAtomicInit()
	ebtables.statement.command = command
	data, err := ebtables.exec()
	if err != nil {
		return xtables.ErrAndStdErr(err, data)
	}
	return nil
}

func (ebtables *EBTables) AtomicSave() error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	command := newAtomicSave()
	ebtables.statement.command = command
	data, err := ebtables.exec()
	if err != nil {
		return xtables.ErrAndStdErr(err, data)
	}
	return nil
}

func (ebtables *EBTables) AtomicCommit() error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	command := newAtomicCommit()
	ebtables.statement.command = command
	data, err := ebtables.exec()
	if err != nil {
		return xtables.ErrAndStdErr(err, data)
	}
	return nil
}
