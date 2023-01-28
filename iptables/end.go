package iptables

import "github.com/singchia/go-xtables/internal/xerror"

func (iptables *IPTables) Append() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := NewAppend()
	iptables.statement.command = command
	_, err := iptables.exec()
	return err
}

func (iptables *IPTables) Check() (bool, error) {
	if iptables.statement.err != nil {
		return false, iptables.statement.err
	}
	command := NewCheck()
	iptables.statement.command = command
	return false, nil
}

// 0 means ignoring
func (iptables *IPTables) Delete(rulenum uint32) error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := NewDelete(rulenum)
	iptables.statement.command = command
	_, err := iptables.exec()
	return err
}

// 0 means ignoring
func (iptables *IPTables) Insert(rulenum uint32) error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := NewInsert(rulenum)
	iptables.statement.command = command
	_, err := iptables.exec()
	return err
}

// rulenum mustn't be 0
func (iptables *IPTables) Replace(rulenum uint32) error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	if rulenum == 0 {
		return xerror.ErrRulenumMustNot0
	}
	command := NewReplace(rulenum)
	iptables.statement.command = command
	_, err := iptables.exec()
	return err
}

func (iptables *IPTables) List() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := NewList()
	iptables.statement.command = command
	_, err := iptables.exec()
	if err != nil {
		return err
	}
	return nil
}

func (iptables *IPTables) ListRules() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := NewListRules()
	iptables.statement.command = command
	iptables.statement.dump = true
	return nil
}

func (iptables *IPTables) Flush() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := NewFlush()
	iptables.statement.command = command
	return nil
}

// 0 means ignoring
func (iptables *IPTables) Zero(rulenum uint32) error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := NewZero(rulenum)
	iptables.statement.command = command
	return nil
}

func (iptables *IPTables) NewChain() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := NewNewChain()
	iptables.statement.command = command
	return nil
}

func (iptables *IPTables) DeleteChain() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := NewDeleteChain()
	iptables.statement.command = command
	return nil
}

func (iptables *IPTables) Policy(target TargetType) error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	if target != TargetTypeAccept &&
		target != TargetTypeDrop &&
		target != TargetTypeReturn {
		return xerror.ErrIllegalTargetType
	}
	command := NewPolicy()
	iptables.statement.command = command
	return nil
}

func (iptables *IPTables) RenameChain(newChain string) error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := NewRenameChain(newChain)
	iptables.statement.command = command
	return nil
}
