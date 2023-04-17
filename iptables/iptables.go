/*
Copyright (c) 2022-2025 Austin Zhai.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package iptables

import "github.com/singchia/go-xtables/pkg/log"

type IPTablesOption func(*IPTables)

func OptionIPTablesLogger(logger log.Logger) IPTablesOption {
	return func(iptables *IPTables) {
		iptables.log = logger
	}
}

type IPTables struct {
	statement *Statement
	cmdName   string
	log       log.Logger
}

func NewIPTables(opts ...IPTablesOption) *IPTables {
	tables := &IPTables{
		statement: NewStatement(),
		cmdName:   "iptables",
	}
	for _, opt := range opts {
		opt(tables)
	}
	if tables.log == nil {
		tables.log = log.DefaultLog
	}
	return tables
}

func (iptables *IPTables) dump() *IPTables {
	newiptables := &IPTables{
		statement: &Statement{
			err:     iptables.statement.err,
			table:   iptables.statement.table,
			chain:   iptables.statement.chain,
			matches: make(map[MatchType]Match),
			options: make(map[OptionType]Option),
			target:  iptables.statement.target,
			command: iptables.statement.command,
		},
		cmdName: iptables.cmdName,
	}
	for k, v := range iptables.statement.matches {
		newiptables.statement.matches[k] = v
	}
	for k, v := range iptables.statement.options {
		newiptables.statement.options[k] = v
	}
	return newiptables
}
