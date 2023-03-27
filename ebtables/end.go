package ebtables

import (
	"errors"
	"fmt"

	"github.com/singchia/go-xtables"
	"github.com/singchia/go-xtables/internal/xutil"
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
		return xutil.ErrAndStdErr(err, data)
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
		return xutil.ErrAndStdErr(err, data)
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
		return errors.New(string(data))
	}
	return nil
}

// 0 means ignoring
func (ebtables *EBTables) Insert(opts ...OptionCommandInsert) error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	command := newInsert(ChainTypeNull, opts...)
	ebtables.statement.command = command
	data, err := ebtables.exec()
	if err != nil {
		return errors.New(string(data))
	}
	return nil
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
		return nil, err
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
		return nil, err
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
		return nil, err
	}
	fmt.Println(string(data))
	return nil, nil
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
			return xutil.ErrAndStdErr(err, data)
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
		return xutil.ErrAndStdErr(err, data)
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
			return xutil.ErrAndStdErr(err, data)
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
				ebtables.Table(table).Chain(chain)
				command := newPolicy(ChainTypeNull, target)
				ebtables.statement.command = command
				data, err := ebtables.exec()
				if err != nil {
					return xutil.ErrAndStdErr(err, data)
				}
			}
		}
		return nil
	} else {
		for _, table := range tables {
			ebtables.Table(table)
			command := newPolicy(ChainTypeNull, target)
			ebtables.statement.command = command
			data, err := ebtables.exec()
			if err != nil {
				return xutil.ErrAndStdErr(err, data)
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
		return errors.New(string(data))
	}
	return nil
}
