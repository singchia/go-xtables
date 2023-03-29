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
package ebtables

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

func (ebtables *EBTables) dump() *EBTables {
	newebtables := &EBTables{
		statement: &Statement{
			err:      ebtables.statement.err,
			table:    ebtables.statement.table,
			chain:    ebtables.statement.chain,
			matches:  make(map[MatchType]Match),
			options:  make(map[OptionType]Option),
			watchers: make(map[WatcherType]Watcher),
			target:   ebtables.statement.target,
			command:  ebtables.statement.command,
		},
		cmdName: ebtables.cmdName,
	}
	for k, v := range ebtables.statement.matches {
		newebtables.statement.matches[k] = v
	}
	for k, v := range ebtables.statement.options {
		newebtables.statement.options[k] = v
	}
	for k, v := range ebtables.statement.watchers {
		newebtables.statement.watchers[k] = v
	}
	return newebtables
}
