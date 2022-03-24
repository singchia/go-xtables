/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package iptables

type CommandType int

const (
	CommandAppend      CommandType = iota // append
	CommandCheck                          // check
	CommandDelete                         // delete
	CommandInsert                         // insert
	CommandReplace                        // replace
	CommandList                           // list
	CommandListRules                      // list_rules
	CommandFlush                          // flush
	CommandZero                           // zero
	CommandNewChain                       // new_chain
	CommandDeleteChain                    // delete_chain
	CommandPolicy                         // policy
	CommandRenameChain                    // rename_chain
)

type hasRulenum interface {
	rulenum() uint32
}

type command interface {
	typ() CommandType
	short() string
	long() string
}

type baseCommand struct {
	commandType CommandType
}

func (bc baseCommand) typ() CommandType {
	return bc.commandType
}

func (bc baseCommand) short() string {
	return ""
}

func (bc baseCommand) long() string {
	return ""
}

type Append struct {
	baseCommand
}

func (apd *Append) short() string {
	return "-A"
}

func (apd *Append) long() string {
	return "--append"
}

type Check struct {
	baseCommand
}

func (check *Check) short() string {
	return "-C"
}

func (check *Check) long() string {
	return "--check"
}

type Delete struct {
	baseCommand
	rnum uint32
}

func (del *Delete) rulenum() uint32 {
	return del.rnum
}

func (del *Delete) short() string {
	return "-D"
}

func (del *Delete) long() string {
	return "--delete"
}

type Insert struct {
	baseCommand
	rnum uint32
}

func (insert *Insert) rulenum() uint32 {
	return insert.rnum
}

func (insert *Insert) short() string {
	return "-I"
}

func (insert *Insert) long() string {
	return "--insert"
}

type Replace struct {
	baseCommand
	rnum uint32
}

func (replace *Replace) rulenum() uint32 {
	return replace.rnum
}

func (replace *Replace) short() string {
	return "-R"
}

func (replace *Replace) long() string {
	return "--replace"
}

type List struct {
	baseCommand
}

func (list *List) short() string {
	return "-L"
}

func (list *List) long() string {
	return "--list"
}

type ListRules struct {
	baseCommand
}

func (listRules *ListRules) short() string {
	return "-S"
}

func (listRules *ListRules) long() string {
	return "--list-rules"
}

type Flush struct {
	baseCommand
}

func (flush *Flush) short() string {
	return "-F"
}

func (flush *Flush) long() string {
	return "--flush"
}

type Zero struct {
	baseCommand
	rnum uint32
}

func (zero *Zero) rulenum() uint32 {
	return zero.rnum
}

func (zero *Zero) short() string {
	return "-Z"
}

func (zero *Zero) long() string {
	return "--zero"
}

type NewChain struct {
	baseCommand
}

func (nc *NewChain) short() string {
	return "-N"
}

func (nc *NewChain) long() string {
	return "--new-chain"
}

type DeleteChain struct {
	baseCommand
}

func (dc *DeleteChain) short() string {
	return "-X"
}

func (dc *DeleteChain) long() string {
	return "--delete-chain"
}

type Policy struct {
	baseCommand
}

func (policy *Policy) short() string {
	return "-P"
}

func (policy *Policy) long() string {
	return "--policy"
}

type RenameChain struct {
	baseCommand
}

func (renameChain *RenameChain) short() string {
	return "-E"
}

func (renameChain *RenameChain) long() string {
	return "--rename-chain"
}
