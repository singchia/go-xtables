package ebtables

import (
	"strconv"
	"strings"

	"github.com/singchia/go-xtables"
)

type CommandType int

func (ct CommandType) Type() string {
	return "CommandType"
}

func (ct CommandType) Value() string {
	return strconv.Itoa(int(ct))
}

const (
	_                         CommandType = iota // default
	CommandTypeAppend                            // append
	CommandTypeChangeCounters                    // change counters
	CommandTypeDelete                            // delete
	CommandTypeInsert                            // insert
	CommandTypeFlush                             // flush
	CommandTypePolicy                            // policy
	CommandTypeFind                              // find
	CommandTypeListRules                         // list
	CommandTypeZero                              // zero
	CommandTypeList                              // list
	CommandTypeDump                              // list with --Lx
	CommandTypeNewChain                          // new_chain
	CommandTypeDeleteChain                       // delete_chain
	CommandTypeRenameChain                       // rename_chain
	CommandTypeListChains                        // go-xtables support
	CommandTypeInitTable                         // init_table
	CommandTypeAtomicInit                        // atomic_init
	CommandTypeAtomicSave                        // atomic_save
	CommandTypeAtomicCommit                      // atomic_commit
)

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
		return bc.child.Short()
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

// Warpper of List for rule searching.
type Find struct {
	*List
}

func NewFind() *Find {
	command := &Find{
		List: &List{
			baseCommand: &baseCommand{
				commandType: CommandTypeFind,
			},
		},
	}
	command.setChild(command)
	return command
}

func newAppend(chain ChainType) *Append {
	command := &Append{
		baseCommand: baseCommand{
			commandType: CommandTypeAppend,
			chain:       chain,
		},
	}
	command.setChild(command)
	return command
}

type Append struct {
	baseCommand
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

type OptionCommandChangeCounters func(*ChangeCounters)

func WithCommandChangeCountersRuleNumber(num int) OptionCommandChangeCounters {
	return func(cmd *ChangeCounters) {
		cmd.ruleNum = num
		cmd.hasRuleNum = true
	}
}

func WithCommandChangeCountersStartRuleNumber(num int) OptionCommandChangeCounters {
	return func(cmd *ChangeCounters) {
		cmd.startRuleNum = num
		cmd.hasStartRuleNum = true
	}
}

func WithCommandChangeCountersEndNumber(num int) OptionCommandChangeCounters {
	return func(cmd *ChangeCounters) {
		cmd.endRuleNum = num
		cmd.hasEndRuleNum = true
	}
}

func WithCommandChangeCountersPacketCount(count int, operator xtables.Operator) OptionCommandChangeCounters {
	return func(cmd *ChangeCounters) {
		cmd.packetCnt = count
		cmd.hasPacketCnt = true
		cmd.packetOperator = operator
	}
}

func WithCommandChangeCountersByteCount(count int, operator xtables.Operator) OptionCommandChangeCounters {
	return func(cmd *ChangeCounters) {
		cmd.byteCnt = count
		cmd.hasByteCnt = true
		cmd.byteOperator = operator
	}
}

type ChangeCounters struct {
	baseCommand
	// specific rule num, mutually exclusive with start_nr and end_nr
	ruleNum    int
	hasRuleNum bool

	// start_nr: if no end_nr
	startRuleNum    int
	hasStartRuleNum bool

	// start_nr:end_nr
	endRuleNum    int
	hasEndRuleNum bool

	packetCnt      int
	hasPacketCnt   bool
	packetOperator xtables.Operator // + -

	byteCnt      int
	hasByteCnt   bool
	byteOperator xtables.Operator // + -
}

func newChangeCounters(chain ChainType, opts ...OptionCommandChangeCounters) *ChangeCounters {
	command := &ChangeCounters{
		baseCommand: baseCommand{
			commandType: CommandTypeChangeCounters,
			chain:       chain,
		},
	}
	command.setChild(command)
	for _, opt := range opts {
		opt(command)
	}
	return command
}

func (cmd *ChangeCounters) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-C", cmd.chain.String())
	if cmd.hasRuleNum {
		args = append(args, strconv.Itoa(cmd.ruleNum))
	} else {
		if cmd.hasStartRuleNum {
			if cmd.hasEndRuleNum {
				args = append(args, strconv.Itoa(cmd.startRuleNum)+":")
			} else {
				args = append(args, strconv.Itoa(cmd.startRuleNum)+":"+strconv.Itoa(cmd.endRuleNum))
			}
		}
	}

	if cmd.hasPacketCnt {
		packetCnt := strconv.Itoa(cmd.packetCnt)
		if cmd.packetOperator != xtables.OperatorNull {
			packetCnt = cmd.packetOperator.String() + packetCnt
		}
		args = append(args, packetCnt)
	}
	if cmd.hasByteCnt {
		byteCnt := strconv.Itoa(cmd.byteCnt)
		if cmd.byteOperator != xtables.OperatorNull {
			byteCnt = cmd.packetOperator.String() + byteCnt
		}
		args = append(args, byteCnt)
	}
	return args
}

func (cmd *ChangeCounters) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *ChangeCounters) LongArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "--change-counters", cmd.chain.String())
	if cmd.hasRuleNum {
		args = append(args, strconv.Itoa(cmd.ruleNum))
	} else {
		if cmd.hasStartRuleNum {
			if cmd.hasEndRuleNum {
				args = append(args, strconv.Itoa(cmd.startRuleNum)+":")
			} else {
				args = append(args, strconv.Itoa(cmd.startRuleNum)+":"+strconv.Itoa(cmd.endRuleNum))
			}
		}
	}

	if cmd.hasPacketCnt {
		args = append(args, strconv.Itoa(cmd.packetCnt))
	}
	if cmd.hasByteCnt {
		args = append(args, strconv.Itoa(cmd.byteCnt))
	}
	return args
}

func (cmd *ChangeCounters) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

type OptionCommandDelete func(*Delete)

func WithCommandDeleteStartRuleNumber(num int) OptionCommandDelete {
	return func(cmd *Delete) {
		cmd.startRuleNum = num
		cmd.hasStartRuleNum = true

	}
}

func WithCommandDeleteEndRuleNumber(num int) OptionCommandDelete {
	return func(cmd *Delete) {
		cmd.endRuleNum = num
		cmd.hasEndRuleNum = true
	}
}

type Delete struct {
	baseCommand
	startRuleNum    int
	hasStartRuleNum bool

	endRuleNum    int
	hasEndRuleNum bool
}

func newDelete(chain ChainType, opts ...OptionCommandDelete) *Delete {
	command := &Delete{
		baseCommand: baseCommand{
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

func (cmd *Delete) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-D", cmd.chain.String())
	if cmd.hasStartRuleNum {
		if cmd.hasEndRuleNum {
			args = append(args, strconv.Itoa(cmd.startRuleNum)+":")
		} else {
			args = append(args, strconv.Itoa(cmd.startRuleNum)+":"+strconv.Itoa(cmd.endRuleNum))
		}
	}
	return args
}

func (cmd *Delete) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *Delete) LongArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--delete", cmd.chain.String())
	if cmd.hasStartRuleNum {
		if cmd.hasEndRuleNum {
			args = append(args, strconv.Itoa(cmd.startRuleNum)+":")
		} else {
			args = append(args, strconv.Itoa(cmd.startRuleNum)+":"+strconv.Itoa(cmd.endRuleNum))
		}
	}
	return args
}

func (cmd *Delete) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

type OptionCommandInsert func(*Insert)

func WithCommandInsertRuleNumber(ruleNum int) OptionCommandInsert {
	return func(cmd *Insert) {
		cmd.ruleNum = ruleNum
		cmd.hasRuleNum = true
	}
}

type Insert struct {
	baseCommand
	ruleNum    int
	hasRuleNum bool
}

func newInsert(chain ChainType, opts ...OptionCommandInsert) *Insert {
	command := &Insert{
		baseCommand: baseCommand{
			commandType: CommandTypeInsert,
			chain:       chain,
		},
	}
	command.setChild(command)
	return command
}

func (cmd *Insert) ShortArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "-I", cmd.chain.String())
	return args
}

func (cmd *Insert) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *Insert) LongArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "--insert", cmd.chain.String())
	return args
}

func (cmd *Insert) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

// If no chain is selected, then every chain will be listed.
type List struct {
	*baseCommand
	chain ChainType
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

// -L --Lx
type Dump struct {
	*List
}

func newDump(chain ChainType) *Dump {
	command := &Dump{
		List: &List{
			baseCommand: &baseCommand{
				commandType: CommandTypeDump,
				chain:       chain,
			},
		},
	}
	command.setChild(command)
	return command
}

// If no chain is selected, then every chain will be flushed.
type Flush struct {
	baseCommand
}

func newFlush(chain ChainType) *Flush {
	command := &Flush{
		baseCommand: baseCommand{
			commandType: CommandTypeFlush,
			chain:       chain,
		},
	}
	command.setChild(command)
	return command
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

// Set the policy for the chain to the given target. The policy can be ACCEPT, DROP or RETURN.
type Policy struct {
	*baseCommand
	targetType TargetType
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

// Set the counters of the selected chain to zero. If no chain is selected, all the counters are set to zero.
type Zero struct {
	*baseCommand
	rnum uint32
}

func newZero(chain ChainType) *Zero {
	command := &Zero{
		baseCommand: &baseCommand{
			commandType: CommandTypeZero,
			chain:       chain,
		},
	}
	command.setChild(command)
	return command
}

func (cmd *Zero) ShortArgs() []string {
	args := make([]string, 0, 2)
	if cmd.chain != ChainTypeNull {
		args = append(args, "-Z", cmd.chain.String())
	} else {
		args = append(args, "-Z")
	}
	return args
}

func (cmd *Zero) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *Zero) LongArgs() []string {
	args := make([]string, 0, 2)
	if cmd.chain != ChainTypeNull {
		args = append(args, "--zero", cmd.chain.String())
	} else {
		args = append(args, "--zero")
	}
	return args
}

func (cmd *Zero) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

// Create a new user-defined chain with the given name.
type NewChain struct {
	*baseCommand
	chainName string
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

// Delete the specified user-defined chain. There must be no remaining references (jumps) to the specified chain.
type DeleteChain struct {
	*baseCommand
	chainName string
}

func newDeleteChain() *DeleteChain {
	command := &DeleteChain{
		baseCommand: &baseCommand{
			commandType: CommandTypeDeleteChain,
		},
	}
	command.setChild(command)
	return command
}

func (cmd *DeleteChain) ShortArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "-X", cmd.chainName)
	return args
}

func (cmd *DeleteChain) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *DeleteChain) LongArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "--delete-chain", cmd.chainName)
	return args
}

func (cmd *DeleteChain) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

// Wrapper of List for list rules.
type ListRules struct {
	*List
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

// Wrapper of List for list chains.
type ListChains struct {
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

// Rename the specified chain to a new name.
type RenameChain struct {
	*baseCommand
	newname string // user supplied name.
}

func newRenameChain(chain ChainType, newname string) *RenameChain {
	command := &RenameChain{
		baseCommand: &baseCommand{
			commandType: CommandTypeRenameChain,
			chain:       chain,
		},
		newname: newname,
	}
	command.setChild(command)
	return command
}

func (cmd *RenameChain) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-E", cmd.chain.String(), cmd.newname)
	return args
}

func (cmd *RenameChain) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

func (cmd *RenameChain) LongArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "--rename-chain", cmd.chain.String(), cmd.newname)
	return args
}

func (cmd *RenameChain) Long() string {
	return strings.Join(cmd.LongArgs(), " ")
}

// Replace the current table data by the initial table data.
type InitTable struct {
	*baseCommand
}

func newInitTable() *InitTable {
	command := &InitTable{
		baseCommand: &baseCommand{
			commandType: CommandTypeInitTable,
		},
	}
	command.setChild(command)
	return command
}

func (cmd *InitTable) ShortArgs() []string {
	args := make([]string, 0, 1)
	args = append(args, "--init-table")
	return args
}

func (cmd *InitTable) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

// Copy the kernel's initial data of the table to the specified file.
type AtomicInit struct {
	*baseCommand
}

func newAtomicInit() *AtomicInit {
	command := &AtomicInit{
		baseCommand: &baseCommand{
			commandType: CommandTypeAtomicInit,
		},
	}
	command.setChild(command)
	return command
}

func (cmd *AtomicInit) ShortArgs() []string {
	args := make([]string, 0, 1)
	args = append(args, "--atomic-init")
	return args
}

func (cmd *AtomicInit) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

// Copy the kernel's current data of the table to the specified file.
type AtomicSave struct {
	*baseCommand
}

func newAtomicSave() *AtomicSave {
	command := &AtomicSave{
		baseCommand: &baseCommand{
			commandType: CommandTypeAtomicSave,
		},
	}
	command.setChild(command)
	return command
}

func (cmd *AtomicSave) ShortArgs() []string {
	args := make([]string, 0, 1)
	args = append(args, "--atomic-save")
	return args
}

func (cmd *AtomicSave) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}

type AtomicCommit struct {
	*baseCommand
}

// Replace the kernel table data with the data contained in the specified file.
func newAtomicCommit() *AtomicCommit {
	command := &AtomicCommit{
		baseCommand: &baseCommand{
			commandType: CommandTypeAtomicCommit,
		},
	}
	command.setChild(command)
	return command
}

func (cmd *AtomicCommit) ShortArgs() []string {
	args := make([]string, 0, 1)
	args = append(args, "--atomic-commit")
	return args
}

func (cmd *AtomicCommit) Short() string {
	return strings.Join(cmd.ShortArgs(), " ")
}
