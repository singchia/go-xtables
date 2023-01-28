package ebtables

import "github.com/singchia/go-xtables/pkg/cmd"

type EBTables struct {
	statement *Statement
	cmdName   string
}

func NewEBTables() *EBTables {
	tables := &EBTables{
		statement: NewStatement(),
		cmdName:   "ebtables",
	}
	return tables
}

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
