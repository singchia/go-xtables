package iptables

type IPTables struct {
	statement *Statement
}

func NewIPTables() *IPTables {
	tables := &IPTables{
		statement: NewStatement(),
	}
	return tables
}
