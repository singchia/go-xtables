package iptables

import (
	"strconv"
	"strings"
)

type CommandType int

func (ct CommandType) Type() string {
	return "CommandType"
}

func (ct CommandType) Value() string {
	return strconv.Itoa(int(ct))
}

const (
	_                      CommandType = iota
	CommandTypeAppend                  // append
	CommandTypeCheck                   // check
	CommandTypeDelete                  // delete
	CommandTypeInsert                  // insert
	CommandTypeReplace                 // replace
	CommandTypeList                    // list
	CommandTypeListRules               // go-xtables support
	CommandTypeDumpRules               // as iptables list_rules
	CommandTypeFlush                   // flush
	CommandTypeZero                    // zero
	CommandTypeNewChain                // new_chain
	CommandTypeDeleteChain             // delete_chain
	CommandTypePolicy                  // policy
	CommandTypeRenameChain             // rename_chain
	CommandTypeListChains              // go-xtables support
	CommandTypeFind                    // go-xtables support
)

type HasRulenum interface {
	Rulenum() uint32
}

type Command interface {
	Type() CommandType
	Short() string
	Long() string
	ShortArgs() []string
	LongArgs() []string
	SetChainType(chain ChainType)
}

type baseCommand struct {
	commandType CommandType
	child       Command
	chain       ChainType
}

func (bc *baseCommand) setChild(child Command) {
	bc.child = child
}

func (bc *baseCommand) Type() CommandType {
	return bc.commandType
}

func (bc *baseCommand) Short() string {
	if bc.child != nil {
		return bc.child.Short()
	}
	return ""
}

func (bc *baseCommand) ShortArgs() []string {
	if bc.child != nil {
		return bc.child.ShortArgs()
	}
	return nil
}

func (bc *baseCommand) Long() string {
	if bc.child != nil {
		return bc.child.Long()
	}
	return bc.Short()
}

func (bc *baseCommand) LongArgs() []string {
	if bc.child != nil {
		return bc.child.ShortArgs()
	}
	return bc.ShortArgs()
}

func (bc *baseCommand) SetChainType(chain ChainType) {
	bc.chain = chain
}

func newAppend(chain ChainType) *Append {
	command := &Append{
		baseCommand: &baseCommand{
			commandType: CommandTypeAppend,
			chain:       chain,
		},
	}
	command.setChild(command)
	return command
}

type Append struct {
	*baseCommand
}

func (cmd *Append) ShortArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "-A", cmd.chain.String())
	return args
}

func (cmd *Append) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *Append) LongArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "--append", cmd.chain.String())
	return args
}

func (cmd *Append) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

func newCheck(chain ChainType) *Check {
	command := &Check{
		baseCommand: &baseCommand{
			commandType: CommandTypeCheck,
			chain:       chain,
		},
	}
	command.setChild(command)
	return command
}

type Check struct {
	*baseCommand
}

func (cmd *Check) ShortArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "-C", cmd.chain.String())
	return args
}

func (cmd *Check) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *Check) LongArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "--check", cmd.chain.String())
	return args
}

func (cmd *Check) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

type OptionCommandDelete func(*Delete)

func WithCommandDeleteRuleNumber(num int) OptionCommandDelete {
	return func(cmd *Delete) {
		cmd.ruleNum = num
		cmd.hasRuleNum = true
	}
}

func newDelete(chain ChainType, opts ...OptionCommandDelete) *Delete {
	command := &Delete{
		baseCommand: &baseCommand{
			commandType: CommandTypeDelete,
			chain:       chain,
		},
	}
	command.setChild(command)
	for _, opt := range opts {
		opt(command)
	}
	return command
}

type Delete struct {
	*baseCommand
	ruleNum    int
	hasRuleNum bool
}

func (cmd *Delete) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-D", cmd.chain.String())
	if cmd.hasRuleNum {
		args = append(args, strconv.Itoa(cmd.ruleNum))
	}
	return args
}

func (cmd *Delete) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *Delete) LongArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--delete", cmd.chain.String())
	if cmd.hasRuleNum {
		args = append(args, strconv.Itoa(cmd.ruleNum))
	}
	return args
}

func (cmd *Delete) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

type OptionCommandInsert func(*Insert)

func WithCommandInsertRuleNumber(num int) OptionCommandInsert {
	return func(cmd *Insert) {
		cmd.ruleNum = num
		cmd.hasRuleNum = true
	}
}

func newInsert(chain ChainType, opts ...OptionCommandInsert) *Insert {
	command := &Insert{
		baseCommand: &baseCommand{
			commandType: CommandTypeInsert,
			chain:       chain,
		},
	}
	command.setChild(command)
	for _, opt := range opts {
		opt(command)
	}
	return command
}

type Insert struct {
	*baseCommand
	ruleNum    int
	hasRuleNum bool
}

func (cmd *Insert) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-I", cmd.chain.String())
	if cmd.hasRuleNum {
		args = append(args, strconv.Itoa(cmd.ruleNum))
	}
	return args
}

func (cmd *Insert) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *Insert) LongArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--insert", cmd.chain.String())
	if cmd.hasRuleNum {
		args = append(args, strconv.Itoa(cmd.ruleNum))
	}
	return args
}

func (cmd *Insert) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

// Replace a rule in the selected chain.
func newReplace(chain ChainType, num int) *Replace {
	command := &Replace{
		baseCommand: &baseCommand{
			commandType: CommandTypeReplace,
			chain:       chain,
		},
		ruleNum: num,
	}
	command.setChild(command)
	return command
}

type Replace struct {
	*baseCommand
	ruleNum int
}

func (cmd *Replace) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-R", cmd.chain.String(), strconv.Itoa(cmd.ruleNum))
	return args
}

func (cmd *Replace) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *Replace) LongArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--replace", cmd.chain.String(), strconv.Itoa(cmd.ruleNum))
	return args
}

func (cmd *Replace) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

func newList(chain ChainType) *List {
	command := &List{
		baseCommand: &baseCommand{
			commandType: CommandTypeList,
			chain:       chain,
		},
	}
	command.setChild(command)
	return command
}

type List struct {
	*baseCommand
}

func (cmd *List) ShortArgs() []string {
	args := make([]string, 0, 2)
	if cmd.chain != ChainTypeNull {
		args = append(args, "-L", cmd.chain.String())
	} else {
		args = append(args, "-L")
	}
	return args
}

func (cmd *List) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *List) LongArgs() []string {
	args := make([]string, 0, 2)
	if cmd.chain != ChainTypeNull {
		args = append(args, "--list", cmd.chain.String())
	} else {
		args = append(args, "--list")
	}
	return args
}

func (cmd *List) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

func newListRules(chain ChainType) *ListRules {
	command := &ListRules{
		List: &List{
			baseCommand: &baseCommand{
				commandType: CommandTypeListRules,
				chain:       chain,
			},
		},
	}
	command.setChild(command)
	return command
}

type ListRules struct {
	*List
}

func newListChains(chain ChainType) *ListChains {
	command := &ListChains{
		List: &List{
			baseCommand: &baseCommand{
				commandType: CommandTypeListChains,
				chain:       chain,
			},
		},
	}
	command.setChild(command)
	return command
}

type ListChains struct {
	*List
}

func newFind(chain ChainType) *Find {
	command := &Find{
		List: &List{
			baseCommand: &baseCommand{
				commandType: CommandTypeFind,
				chain:       chain,
			},
		},
	}
	command.setChild(command)
	return command
}

type Find struct {
	*List
}

func newDumpRules(chain ChainType) *DumpRules {
	command := &DumpRules{
		baseCommand: &baseCommand{
			commandType: CommandTypeDumpRules,
			chain:       chain,
		},
	}
	command.setChild(command)
	return command
}

type DumpRules struct {
	*baseCommand
}

func (cmd *DumpRules) ShortArgs() []string {
	args := make([]string, 0, 2)
	if cmd.chain != ChainTypeNull {
		args = append(args, "-S", cmd.chain.String())
	} else {
		args = append(args, "-S")
	}
	return args
}

func (cmd *DumpRules) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *DumpRules) LongArgs() []string {
	args := make([]string, 0, 2)
	if cmd.chain != ChainTypeNull {
		args = append(args, "--list-rules", cmd.chain.String())
	} else {
		args = append(args, "--list-rules")
	}
	return args
}

func (cmd *DumpRules) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

func newFlush() *Flush {
	command := &Flush{
		baseCommand: &baseCommand{
			commandType: CommandTypeFlush,
		},
	}
	command.setChild(command)
	return command
}

type Flush struct {
	*baseCommand
}

func (cmd *Flush) ShortArgs() []string {
	args := make([]string, 0, 2)
	if cmd.chain != ChainTypeNull {
		args = append(args, "-F", cmd.chain.String())
	} else {
		args = append(args, "-F")
	}
	return args
}

func (cmd *Flush) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *Flush) LongArgs() []string {
	args := make([]string, 0, 2)
	if cmd.chain != ChainTypeNull {
		args = append(args, "--flush", cmd.chain.String())
	} else {
		args = append(args, "--flush")
	}
	return args
}

func (cmd *Flush) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

type OptionCommandZero func(*Zero)

func WithCommandZeroRuleNumber(num int) OptionCommandZero {
	return func(cmd *Zero) {
		cmd.ruleNum = num
		cmd.hasRuleNum = true
	}
}

func newZero(chain ChainType, opts ...OptionCommandZero) *Zero {
	command := &Zero{
		baseCommand: &baseCommand{
			commandType: CommandTypeZero,
			chain:       chain,
		},
	}
	command.setChild(command)
	for _, opt := range opts {
		opt(command)
	}
	return command
}

type Zero struct {
	*baseCommand
	ruleNum    int
	hasRuleNum bool
}

func (cmd *Zero) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-Z")
	if cmd.chain != ChainTypeNull {
		args = append(args, cmd.chain.String())
	}
	if cmd.hasRuleNum {
		args = append(args, strconv.Itoa(cmd.ruleNum))
	}
	return args
}

func (cmd *Zero) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *Zero) LongArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--zero")
	if cmd.chain != ChainTypeNull {
		args = append(args, cmd.chain.String())
	}
	if cmd.hasRuleNum {
		args = append(args, strconv.Itoa(cmd.ruleNum))
	}
	return args
}

func (cmd *Zero) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

func newNewChain(chainName string) *NewChain {
	command := &NewChain{
		baseCommand: &baseCommand{
			commandType: CommandTypeNewChain,
		},
		chainName: chainName,
	}
	command.setChild(command)
	return command
}

type NewChain struct {
	*baseCommand
	chainName string
}

func (cmd *NewChain) ShortArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "-N", cmd.chainName)
	return args
}

func (cmd *NewChain) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *NewChain) LongArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "--new-chain", cmd.chainName)
	return args
}

func (cmd *NewChain) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

func newDeleteChain(chain ChainType) *DeleteChain {
	command := &DeleteChain{
		baseCommand: &baseCommand{
			commandType: CommandTypeDeleteChain,
			chain:       chain,
		},
	}
	command.setChild(command)
	return command
}

type DeleteChain struct {
	*baseCommand
}

func (cmd *DeleteChain) ShortArgs() []string {
	args := make([]string, 0, 2)
	if cmd.chain != ChainTypeNull {
		args = append(args, "-X", cmd.chain.String())
	} else {
		args = append(args, "-X")
	}
	return args
}

func (cmd *DeleteChain) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *DeleteChain) LongArgs() []string {
	args := make([]string, 0, 2)
	if cmd.chain != ChainTypeNull {
		args = append(args, "--delete-chain", cmd.chain.String())
	} else {
		args = append(args, "--delete-chain")
	}
	return args
}

func (cmd *DeleteChain) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

func newPolicy(chain ChainType, target TargetType) *Policy {
	command := &Policy{
		baseCommand: &baseCommand{
			commandType: CommandTypePolicy,
			chain:       chain,
		},
		targetType: target,
	}
	command.setChild(command)
	return command
}

type Policy struct {
	*baseCommand
	targetType TargetType
}

func (cmd *Policy) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-P", cmd.chain.String(), cmd.targetType.String())
	return args
}

func (cmd *Policy) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *Policy) LongArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--policy", cmd.chain.String(), cmd.targetType.String())
	return args
}

func (cmd *Policy) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

func newRenameChain(chain ChainType, newChain string) *RenameChain {
	command := &RenameChain{
		baseCommand: &baseCommand{
			commandType: CommandTypeRenameChain,
			chain:       chain,
		},
		newChain: newChain,
	}
	command.setChild(command)
	return command
}

type RenameChain struct {
	*baseCommand
	newChain string // user supplied name.
}

func (cmd *RenameChain) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-E", cmd.chain.String(), cmd.newChain)
	return args
}

func (cmd *RenameChain) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *RenameChain) LongArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--rename-chain", cmd.chain.String(), cmd.newChain)
	return args
}

func (cmd *RenameChain) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}
