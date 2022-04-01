/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package iptables

import (
	"github.com/singchia/go-xtables/pkg/cmd"
)

type IPTables struct {
	statement *Statement
	cmdName   string
}

func NewIPTables() *IPTables {
	tables := &IPTables{
		statement: NewStatement(),
		//cmdName:   "iptables",
		cmdName: "/usr/sbin/iptables",
	}
	return tables
}

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
