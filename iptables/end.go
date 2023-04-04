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
	newiptables := iptables.dump()
	command := newAppend()
	newiptables.statement.command = command
	data, err := newiptables.exec()
	if err != nil {
		return errors.New(string(data))
	}
	return nil
}

func (iptables *IPTables) Check() (bool, error) {
	if iptables.statement.err != nil {
		return false, iptables.statement.err
	}
	newiptables := iptables.dump()
	command := newCheck()
	newiptables.statement.command = command
	data, err := newiptables.exec()
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
	newiptables := iptables.dump()
	command := newDelete(rulenum)
	newiptables.statement.command = command
	// delete doesn't need a target
	newiptables.statement.target = nil
	data, err := newiptables.exec()
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
	newiptables := iptables.dump()
	command := newInsert(rulenum)
	newiptables.statement.command = command
	data, err := newiptables.exec()
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
	newiptables := iptables.dump()
	command := newReplace(rulenum)
	newiptables.statement.command = command
	data, err := newiptables.exec()
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
	newiptables := iptables.dump()
	command := newListRules()
	newiptables.statement.command = command
	data, err := newiptables.exec()
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
	newiptables := iptables.dump()
	command := newListChains()
	newiptables.statement.command = command
	data, err := newiptables.exec()
	if err != nil {
		return nil, err
	}
	chains, _, err := parse(data, iptables.statement.table, parseChain, nil)
	return chains, err
}

// -S
func (iptables *IPTables) DumpRules() ([]string, error) {
	if iptables.statement.err != nil {
		return nil, iptables.statement.err
	}
	newiptables := iptables.dump()
	command := newDumpRules()
	newiptables.statement.command = command
	newiptables.statement.dump = true
	data, err := newiptables.exec()
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
	newiptables := iptables.dump()
	var tables []TableType
	if newiptables.statement.table == TableTypeNull {
		tables = []TableType{TableTypeFilter, TableTypeNat,
			TableTypeMangle, TableTypeRaw, TableTypeSecurity}
	} else {
		tables = []TableType{newiptables.statement.table}
	}

	for _, table := range tables {
		newiptables.Table(table)
		command := newFlush()
		newiptables.statement.command = command
		data, err := newiptables.exec()
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
	newiptables := iptables.dump()
	command := newZero(rulenum)
	newiptables.statement.command = command
	data, err := newiptables.exec()
	if err != nil {
		return errors.New(string(data))
	}
	return nil
}

func (iptables *IPTables) NewChain() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	newiptables := iptables.dump()
	command := newNewChain()
	newiptables.statement.command = command
	data, err := newiptables.exec()
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
	newiptables := iptables.dump()
	var tables []TableType
	if newiptables.statement.table == TableTypeNull {
		tables = []TableType{TableTypeFilter, TableTypeNat,
			TableTypeMangle, TableTypeRaw, TableTypeSecurity}
	} else {
		tables = []TableType{newiptables.statement.table}
	}

	for _, table := range tables {
		newiptables.Table(table)
		command := newDeleteChain()
		newiptables.statement.command = command
		data, err := newiptables.exec()
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
	newiptables := iptables.dump()
	var tables []TableType
	if newiptables.statement.table == TableTypeNull {
		tables = []TableType{TableTypeFilter, TableTypeNat,
			TableTypeMangle, TableTypeRaw, TableTypeSecurity}
	} else {
		tables = []TableType{newiptables.statement.table}
	}

	if newiptables.statement.chain == ChainTypeNull {
		for _, table := range tables {
			for _, chain := range TableChains[table] {
				newiptables.Table(table)
				newiptables.Chain(chain)
				command := newPolicy(target)
				newiptables.statement.command = command
				data, err := newiptables.exec()
				if err != nil {
					return errors.New(string(data))
				}
			}
		}
		return nil
	} else {
		for _, table := range tables {
			newiptables.Table(table)
			command := newPolicy(target)
			newiptables.statement.command = command
			data, err := newiptables.exec()
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
	newiptables := iptables.dump()
	command := newRenameChain(newChain)
	newiptables.statement.command = command
	data, err := newiptables.exec()
	if err != nil {
		return errors.New(string(data))
	}
	return nil
}

func (iptables *IPTables) FindChains() ([]*Chain, error) {
	if iptables.statement.err != nil {
		return nil, iptables.statement.err
	}
	newiptables := iptables.dump()
	chainType := newiptables.statement.chain
	name := newiptables.statement.userDefinedChain
	newiptables.statement.chain = ChainTypeNull

	command := newListChains()
	newiptables.statement.command = command

	data, err := newiptables.exec()
	if err != nil {
		return nil, xtables.ErrAndStdErr(err, data)
	}

	chains, _, err := parse(data, newiptables.statement.table, parseChain, nil)
	if err != nil {
		return nil, err
	}
	foundChains := []*Chain{}
	for _, chain := range chains {
		if chain.chainType == ChainTypeUserDefined &&
			chain.name != name {
			continue
		}
		if chain.chainType == ChainTypeUserDefined &&
			chain.name == name {
			foundChains = append(foundChains, chain)
			continue
		}
		if chain.chainType == chainType {
			foundChains = append(foundChains, chain)
		}
	}
	return foundChains, nil
}

func (iptables *IPTables) FindRules() ([]*Rule, error) {
	if iptables.statement.err != nil {
		return nil, iptables.statement.err
	}
	newiptables := iptables.dump()
	optionsMap := newiptables.statement.options
	matchesMap := newiptables.statement.matches
	target := newiptables.statement.target

	newiptables.statement.options = make(map[OptionType]Option)
	newiptables.statement.matches = make(map[MatchType]Match)
	newiptables.statement.target = nil

	// search with table or chain
	command := newFind()
	newiptables.statement.command = command
	newiptables.statement.options[OptionTypeLineNumbers], _ = newOptionLineNumbers()
	newiptables.statement.options[OptionTypeNumeric], _ = newOptionNumeric()
	newiptables.statement.options[OptionTypeVerbose], _ = newOptionVerbose()

	data, err := newiptables.exec()
	if err != nil {
		return nil, xtables.ErrAndStdErr(err, data)
	}
	_, rules, err := parse(data, iptables.statement.table, parseChain, parseRule)
	if err != nil {
		return nil, err
	}
	foundRules := []*Rule{}
	for _, rule := range rules {
		yes := rule.HasAllOptions(optionsMap)
		if !yes {
			continue
		}
		yes = rule.HasAllMatches(matchesMap)
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
