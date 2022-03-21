/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
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
