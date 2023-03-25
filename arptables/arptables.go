package arptables

import "github.com/singchia/go-xtables/pkg/cmd"

type ARPTables struct {
	statement *Statement
	cmdName   string
}

func NewARPTables() *ARPTables {
	tables := &ARPTables{
		statement: NewStatement(),
		cmdName:   "arptables",
	}
	return tables
}

func (arptables *ARPTables) exec() ([]byte, error) {
	elems, err := arptables.statement.Elems()
	if err != nil {
		return nil, err
	}
	infoO, infoE, err := cmd.Cmd(arptables.cmdName, elems...)
	if err != nil {
		return infoE, err
	}
	return infoO, nil
}
