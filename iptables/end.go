package iptables

import (
	"bufio"
	"bytes"
	"errors"

	"github.com/singchia/go-xtables"
	"github.com/singchia/go-xtables/pkg/cmd"
)

func (iptables *IPTables) exec() ([]byte, error) {
	elems, err := iptables.statement.Elems()
	if err != nil {
		return nil, err
	}
	infoO, infoE, err := cmd.Cmd(iptables.cmdName, elems...)
	if err != nil {
		return infoE, err
	}
	return infoO, nil
}

func (iptables *IPTables) Append() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := newAppend()
	iptables.statement.command = command
	data, err := iptables.exec()
	if err != nil {
		return errors.New(string(data))
	}
	return nil
}

func (iptables *IPTables) Check() (bool, error) {
	if iptables.statement.err != nil {
		return false, iptables.statement.err
	}
	command := newCheck()
	iptables.statement.command = command
	data, err := iptables.exec()
	if err != nil {
		return false, errors.New(string(data))
	}
	return true, nil
}

// 0 means ignoring
func (iptables *IPTables) Delete(rulenum uint32) error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := newDelete(rulenum)
	iptables.statement.command = command
	// delete doesn't need a target
	iptables.statement.target = nil
	data, err := iptables.exec()
	if err != nil {
		return errors.New(string(data))
	}
	return nil
}

// 0 means ignoring
func (iptables *IPTables) Insert(rulenum uint32) error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := newInsert(rulenum)
	iptables.statement.command = command
	data, err := iptables.exec()
	if err != nil {
		return errors.New(string(data))
	}
	return nil
}

// rulenum mustn't be 0
func (iptables *IPTables) Replace(rulenum uint32) error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	if rulenum == 0 {
		return xtables.ErrRulenumMustNot0
	}
	command := newReplace(rulenum)
	iptables.statement.command = command
	data, err := iptables.exec()
	if err != nil {
		return errors.New(string(data))
	}
	return nil
}

// ListRules can't be chained with matched, options and targets.
func (iptables *IPTables) ListRules() ([]*Rule, error) {
	if iptables.statement.err != nil {
		return nil, iptables.statement.err
	}
	command := newListRules()
	iptables.statement.command = command
	data, err := iptables.exec()
	if err != nil {
		return nil, err
	}
	_, rules, err := parse(data, iptables.statement.table, parseChain, parseRule)
	return rules, err
}

// ListChains can't be chained with matched, options and targets.
func (iptables *IPTables) ListChains() ([]*Chain, error) {
	if iptables.statement.err != nil {
		return nil, iptables.statement.err
	}
	command := newListChains()
	iptables.statement.command = command
	data, err := iptables.exec()
	if err != nil {
		return nil, err
	}
	chains, _, err := parse(data, iptables.statement.table, parseChain, parseRule)
	return chains, err
}

// -S
func (iptables *IPTables) DumpRules() ([]string, error) {
	if iptables.statement.err != nil {
		return nil, iptables.statement.err
	}
	command := newDumpRules()
	iptables.statement.command = command
	iptables.statement.dump = true
	data, err := iptables.exec()
	if err != nil {
		return nil, err
	}
	lines := []string{}
	buf := bytes.NewBuffer(data)
	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
	}
	return lines, err
}

// if no table specified, the flush will be applied to all tables
func (iptables *IPTables) Flush() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	var tables []TableType
	if iptables.statement.table == TableTypeNull {
		tables = []TableType{TableTypeFilter, TableTypeNat,
			TableTypeMangle, TableTypeRaw, TableTypeSecurity}
	} else {
		tables = []TableType{iptables.statement.table}
	}

	for _, table := range tables {
		iptables.Table(table)
		command := newFlush()
		iptables.statement.command = command
		data, err := iptables.exec()
		if err != nil {
			return errors.New(string(data))
		}
	}
	return nil
}

// 0 means ignoring
func (iptables *IPTables) Zero(rulenum uint32) error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := newZero(rulenum)
	iptables.statement.command = command
	data, err := iptables.exec()
	if err != nil {
		return errors.New(string(data))
	}
	return nil
}

func (iptables *IPTables) NewChain() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := newNewChain()
	iptables.statement.command = command
	data, err := iptables.exec()
	if err != nil {
		return errors.New(string(data))
	}
	return nil
}

// If no table specified, the delete-chain will be applied to all tables
func (iptables *IPTables) DeleteChain() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	var tables []TableType
	if iptables.statement.table == TableTypeNull {
		tables = []TableType{TableTypeFilter, TableTypeNat,
			TableTypeMangle, TableTypeRaw, TableTypeSecurity}
	} else {
		tables = []TableType{iptables.statement.table}
	}

	for _, table := range tables {
		iptables.Table(table)
		command := newDeleteChain()
		iptables.statement.command = command
		data, err := iptables.exec()
		if err != nil {
			return errors.New(string(data))
		}
	}
	return nil
}

// If no table specified, the delete-chain will be applied to all tables
// If no chain specified, the policy will be applied to all build-in chains.
func (iptables *IPTables) Policy(target TargetType) error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	if target != TargetTypeAccept &&
		target != TargetTypeDrop &&
		target != TargetTypeReturn {
		return xtables.ErrIllegalTargetType
	}
	var tables []TableType
	if iptables.statement.table == TableTypeNull {
		tables = []TableType{TableTypeFilter, TableTypeNat,
			TableTypeMangle, TableTypeRaw, TableTypeSecurity}
	} else {
		tables = []TableType{iptables.statement.table}
	}

	if iptables.statement.chain == ChainTypeNull {
		for _, table := range tables {
			for _, chain := range TableChains[table] {
				iptables.Table(table)
				iptables.Chain(chain)
				command := newPolicy(target)
				iptables.statement.command = command
				data, err := iptables.exec()
				if err != nil {
					return errors.New(string(data))
				}
			}
		}
		return nil
	} else {
		for _, table := range tables {
			iptables.Table(table)
			command := newPolicy(target)
			iptables.statement.command = command
			data, err := iptables.exec()
			if err != nil {
				return errors.New(string(data))
			}
		}
		return nil
	}
}

func (iptables *IPTables) RenameChain(newChain string) error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := newRenameChain(newChain)
	iptables.statement.command = command
	data, err := iptables.exec()
	if err != nil {
		return errors.New(string(data))
	}
	return nil
}
