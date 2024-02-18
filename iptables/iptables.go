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

import (
	"io"

	"github.com/singchia/go-xtables/pkg/log"
)

type IPTablesOption func(*IPTables)

func OptionIPTablesLogger(logger log.Logger) IPTablesOption {
	return func(iptables *IPTables) {
		iptables.log = logger
	}
}

// like "/usr/sbin/iptables"
func OptionIPTablesCmdPath(path string) IPTablesOption {
	return func(iptables *IPTables) {
		iptables.cmdName = path
	}
}

type IPTables struct {
	statement *Statement
	cmdName   string
	log       log.Logger

	dr       bool
	drWriter io.Writer
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
			err:             iptables.statement.err,
			table:           iptables.statement.table,
			chain:           iptables.statement.chain,
			matches:         make(map[MatchType]Match),
			matchTypeOrder:  make([]MatchType, 0),
			options:         make(map[OptionType]Option),
			optionTypeOrder: make([]OptionType, 0),
			target:          iptables.statement.target,
			command:         iptables.statement.command,
		},
		cmdName:  iptables.cmdName,
		log:      iptables.log,
		dr:       iptables.dr,
		drWriter: iptables.drWriter,
	}

	for _, k := range iptables.statement.matchTypeOrder {
		newiptables.statement.matchTypeOrder = append(newiptables.statement.matchTypeOrder, k)
	}
	for k, v := range iptables.statement.matches {
		newiptables.statement.matches[k] = v
	}

	for _, k := range iptables.statement.optionTypeOrder {
		newiptables.statement.optionTypeOrder = append(newiptables.statement.optionTypeOrder, k)
	}
	for k, v := range iptables.statement.options {
		newiptables.statement.options[k] = v
	}

	return newiptables
}
