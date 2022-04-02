/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package iptables

type CommandType int

const (
	_                      CommandType = iota
	CommandTypeAppend                  // append
	CommandTypeCheck                   // check
	CommandTypeDelete                  // delete
	CommandTypeInsert                  // insert
	CommandTypeReplace                 // replace
	CommandTypeList                    // list
	CommandTypeListRules               // list_rules
	CommandTypeFlush                   // flush
	CommandTypeZero                    // zero
	CommandTypeNewChain                // new_chain
	CommandTypeDeleteChain             // delete_chain
	CommandTypePolicy                  // policy
	CommandTypeRenameChain             // rename_chain
	CommandTypeChain                   // go-xtables support
	CommandTypeFind                    // go-xtables support
)

type HasRulenum interface {
	Rulenum() uint32
}

type Command interface {
	Type() CommandType
	Short() string
	Long() string
}

type baseCommand struct {
	commandType CommandType
}

func (bc baseCommand) Type() CommandType {
	return bc.commandType
}

func (bc baseCommand) Short() string {
	return ""
}

func (bc baseCommand) Long() string {
	return ""
}

type Find struct {
	List
}

type Append struct {
	baseCommand
}

func (apd *Append) Short() string {
	return "-A"
}

func (apd *Append) Long() string {
	return "--append"
}

type Check struct {
	baseCommand
}

func (check *Check) Short() string {
	return "-C"
}

func (check *Check) Long() string {
	return "--check"
}

type Delete struct {
	baseCommand
	rnum uint32
}

func (del *Delete) Rulenum() uint32 {
	return del.rnum
}

func (del *Delete) Short() string {
	return "-D"
}

func (del *Delete) Long() string {
	return "--delete"
}

type Insert struct {
	baseCommand
	rnum uint32
}

func (insert *Insert) Rulenum() uint32 {
	return insert.rnum
}

func (insert *Insert) Short() string {
	return "-I"
}

func (insert *Insert) Long() string {
	return "--insert"
}

type Replace struct {
	baseCommand
	rnum uint32
}

func (replace *Replace) Rulenum() uint32 {
	return replace.rnum
}

func (replace *Replace) Short() string {
	return "-R"
}

func (replace *Replace) Long() string {
	return "--replace"
}

type List struct {
	baseCommand
}

func (list *List) Short() string {
	return "-L"
}

func (list *List) Long() string {
	return "--list"
}

type ListRules struct {
	baseCommand
}

func (listRules *ListRules) Short() string {
	return "-S"
}

func (listRules *ListRules) Long() string {
	return "--list-rules"
}

type Flush struct {
	baseCommand
}

func (flush *Flush) Short() string {
	return "-F"
}

func (flush *Flush) Long() string {
	return "--flush"
}

type Zero struct {
	baseCommand
	rnum uint32
}

func (zero *Zero) Rulenum() uint32 {
	return zero.rnum
}

func (zero *Zero) Short() string {
	return "-Z"
}

func (zero *Zero) Long() string {
	return "--zero"
}

type NewChain struct {
	baseCommand
}

func (nc *NewChain) Short() string {
	return "-N"
}

func (nc *NewChain) Long() string {
	return "--new-chain"
}

type DeleteChain struct {
	baseCommand
}

func (dc *DeleteChain) Short() string {
	return "-X"
}

func (dc *DeleteChain) Long() string {
	return "--delete-chain"
}

type Policy struct {
	baseCommand
}

func (policy *Policy) Short() string {
	return "-P"
}

func (policy *Policy) Long() string {
	return "--policy"
}

type RenameChain struct {
	baseCommand
}

func (renameChain *RenameChain) Short() string {
	return "-E"
}

func (renameChain *RenameChain) Long() string {
	return "--rename-chain"
}
