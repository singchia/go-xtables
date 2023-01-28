package ebtables

func (ebtables *EBTables) Append() error {
	if ebtables.statement.err != nil {
		return ebtables.statement.err
	}
	command := NewAppend()
	ebtables.statement.command = command
	_, err := ebtables.exec()
	return err
}
