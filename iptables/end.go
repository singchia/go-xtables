package iptables

func (iptables *IPTables) Find() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := &Find{
		List: List{
			baseCommand: baseCommand{
				commandType: CommandTypeFind,
			},
		},
	}
	iptables.statement.command = command
	return nil
}

func (iptables *IPTables) Append() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := &Append{
		baseCommand: baseCommand{
			commandType: CommandTypeAppend,
		},
	}
	iptables.statement.command = command
	return nil
}

func (iptables *IPTables) Check() (bool, error) {
	if iptables.statement.err != nil {
		return false, iptables.statement.err
	}
	command := &Check{
		baseCommand: baseCommand{
			commandType: CommandTypeCheck,
		},
	}
	iptables.statement.command = command
	return false, nil
}

// 0 means ignoring
func (iptables *IPTables) Delete(rulenum uint32) error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := &Delete{
		baseCommand: baseCommand{
			commandType: CommandTypeDelete,
		},
		rnum: rulenum,
	}
	iptables.statement.command = command
	return nil
}

// 0 means ignoring
func (iptables *IPTables) Insert(rulenum uint32) error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := &Insert{
		baseCommand: baseCommand{
			commandType: CommandTypeInsert,
		},
		rnum: rulenum,
	}
	iptables.statement.command = command
	return nil
}

// rulenum mustn't be 0
func (iptables *IPTables) Replace(rulenum uint32) error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	if rulenum == 0 {
		return ErrRulenumMustnot0
	}
	command := &Replace{
		baseCommand: baseCommand{
			commandType: CommandTypeReplace,
		},
	}
	iptables.statement.command = command
	return nil
}

func (iptables *IPTables) List() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := &List{
		baseCommand: baseCommand{
			commandType: CommandTypeList,
		},
	}
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
	command := &ListRules{
		baseCommand: baseCommand{
			commandType: CommandTypeListRules,
		},
	}
	iptables.statement.command = command
	iptables.statement.dump = true
	return nil
}

func (iptables *IPTables) Flush() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := &Flush{
		baseCommand: baseCommand{
			commandType: CommandTypeFlush,
		},
	}
	iptables.statement.command = command
	return nil
}

// 0 means ignoring
func (iptables *IPTables) Zero(rulenum uint32) error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := &Zero{
		baseCommand: baseCommand{
			commandType: CommandTypeZero,
		},
		rnum: rulenum,
	}
	iptables.statement.command = command
	return nil
}

func (iptables *IPTables) NewChain() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := &NewChain{
		baseCommand: baseCommand{
			commandType: CommandTypeNewChain,
		},
	}
	iptables.statement.command = command
	return nil
}

func (iptables *IPTables) DeleteChain() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := &DeleteChain{
		baseCommand: baseCommand{
			commandType: CommandTypeDeleteChain,
		},
	}
	iptables.statement.command = command
	return nil
}

func (iptables *IPTables) Policy() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := &Policy{
		baseCommand: baseCommand{
			commandType: CommandTypePolicy,
		},
	}
	iptables.statement.command = command
	return nil
}

func (iptables *IPTables) RenameChain() error {
	if iptables.statement.err != nil {
		return iptables.statement.err
	}
	command := &RenameChain{
		baseCommand: baseCommand{
			commandType: CommandTypeRenameChain,
		},
	}
	iptables.statement.command = command
	return nil
}
