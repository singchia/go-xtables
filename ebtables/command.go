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
	_                         CommandType = iota
	CommandTypeAppend                     // append
	CommandTypeChangeCounters             // change counters
	CommandTypeDelete                     // delete
	CommandTypeInsert                     // insert
	CommandTypeFlush                      // flush
	CommandTypePolicy                     // policy
	CommandTypeListRules                  // list
	CommandTypeZero                       // zero
	//CommandTypeList                       // list
	CommandTypeDump         // list with --Lx
	CommandTypeNewChain     // new_chain
	CommandTypeDeleteChain  // delete_chain
	CommandTypeRenameChain  // rename_chain
	CommandTypeListChains   // go-xtables support
	CommandTypeInitTable    // init_table
	CommandTypeAtomicInit   // atomic_init
	CommandTypeAtomicSave   // atomic_save
	CommandTypeAtomicCommit // atomic_commit
)

type Command interface {
	Type() CommandType
	Short() string
	Long() string
	SetChainType(chain ChainType)
}

type baseCommand struct {
	commandType CommandType
	child       Command
	chain       ChainType
}

func (bc baseCommand) setChild(child Command) {
	bc.child = child
}

func (bc baseCommand) Type() CommandType {
	return bc.commandType
}

func (bc baseCommand) Short() string {
	if bc.child != nil {
		return bc.child.Short()
	}
	return ""
}

func (bc baseCommand) ShortArgs() []string {
	if bm.child != nil {
		return bm.child.ShortArgs()
	}
	return nil
}

func (bc baseCommand) Long() string {
	if bc.child != nil {
		return bc.child.Long()
	}
	return bc.Short()
}

func (bc baseCommand) LongArgs() []string {
	if bm.child != nil {
		return bm.child.LongArgs()
	}
	return nil
}

func (bc baseCommand) SetChainType(chain ChainType) {
	if bc.chain != nil {
		return bc.child.SetChainType(chain)
	}
	bc.chain = chain
}

/*
func NewFind() *Find {
	command := &Find{
		List: &List{
			baseCommand: baseCommand{
				commandType: CommandTypeFind,
			},
		},
	}
	command.setChild(command)
	return command
}

type Find struct {
	*List
}
*/

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
	}
}

func WithCommandChangeCountersStartRuleNumber(num int) OptionCommandChangeCounters {
	return func(cmd *ChangeCounters) {
		cmd.startRuleNum = num
	}
}

func WithCommandChangeCountersEndNumber(num int) OptionCommandChangeCounters {
	return func(cmd *ChangeCounters) {
		cmd.endRuleNum = num
	}
}

func WithCommandChangeCountersPacketCount(count int) OptionCommandChangeCounters {
	return func(cmd *ChangeCounters) {
		cmd.packetCnt = count
	}
}

func WithCommandChangeCountersByteCount(count int) OptionCommandChangeCounters {
	return func(cmd *ChangeCounters) {
		cmd.byteCnt = count
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
				args = append(args, strconv.Itoa(cmd.startRuleNum))
			} else {
				args = append(args, strconv.Itoa(cmd.startRuleNum)+":"+strconv.Itoa(cmd.endRuleNum))
			}
		}
	}
}

func (cmd *ChangeCounters) Short() string {
	return "-C"
}

func (cmd *ChangeCounters) Long() string {
	return "--change-counters"
}

type OptionCommandDelete func(*Delete)

func WithCommandDeleteStartRuleNumber(num int) OptionCommandDelete {
	return func(del *Delete) {
		del.startRuleNum = num
	}
}

func WithCommandDeleteEndRuleNumber(num int) OptionCommandDelete {
	return func(del *Delete) {
		del.endRuleNum = num
	}
}

type Delete struct {
	baseCommand
	startRuleNum int
	endRuleNum   int
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

func (del *Delete) Short() string {
	return "-D"
}

func (del *Delete) Long() string {
	return "--delete"
}

type OptionCommandInsert func(*Insert)

func WithCommandInsertRuleNumber(ruleNum int) OptionCommandInsert {
	return func(irt *Insert) {
		irt.ruleNum = ruleNum
	}
}

type Insert struct {
	baseCommand
	ruleNum int
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

func (insert *Insert) Short() string {
	return "-I"
}

func (insert *Insert) Long() string {
	return "--insert"
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

func newDump(chain ChainType) *Dump {
	command := &Dump{
		List: &List{
			baseCommand: baseCommand{
				commandType: CommandTypeDump,
				chain:       chain,
			},
		},
	}
	command.setChild(command)
	return command
}

// -L --Lx
type Dump struct {
	*List
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

type Flush struct {
	baseCommand
}

func (flush *Flush) Short() string {
	return "-F"
}

func (flush *Flush) Long() string {
	return "--flush"
}

func newPolicy(chain ChainType, target TargetType) *Policy {
	command := &Policy{
		baseCommand: baseCommand{
			commandType: CommandTypePolicy,
			chain:       chain,
		},
		targetType: target,
	}
	command.setChild(command)
	return command
}

type Policy struct {
	baseCommand
	targetType TargetType
}

func (policy *Policy) Short() string {
	return "-P"
}

func (policy *Policy) Long() string {
	return "--policy"
}

func newZero(chain ChainType) *Zero {
	command := &Zero{
		baseCommand: baseCommand{
			commandType: CommandTypeZero,
			chain:       chain,
		},
	}
	command.setChild(command)
	return command
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
	chainName string
}

func newNewChain() *NewChain {
	command := &NewChain{
		baseCommand: baseCommand{
			commandType: CommandTypeNewChain,
		},
	}
	command.setChild(command)
	return command
}

func (nc *NewChain) Short() string {
	return "-N"
}

func (nc *NewChain) Long() string {
	return "--new-chain"
}

func newDeleteChain() *DeleteChain {
	command := &DeleteChain{
		baseCommand: baseCommand{
			commandType: CommandTypeDeleteChain,
		},
	}
	command.setChild(command)
	return command
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

func newListRules() *ListRules {
	command := &ListRules{
		baseCommand: baseCommand{
			commandType: CommandTypeListRules,
		},
	}
	command.setChild(command)
	return command
}

type ListRules struct {
	baseCommand
}

func (list *ListRules) Short() string {
	return "-L"
}

func (list *ListRules) Long() string {
	return "--list"
}

func newListChains() *ListChains {
	command := &ListChains{
		ListRules: &ListRules{
			baseCommand: baseCommand{
				commandType: CommandTypeListChains,
			},
		},
	}
	command.setChild(command)
	return command
}

type ListChains struct {
	*ListRules
}

type RenameChain struct {
	baseCommand
	newname string // user supplied name.
}

func newRenameChain(chain ChainType, newname string) *RenameChain {
	command := &RenameChain{
		baseCommand: baseCommand{
			commandType: CommandTypeRenameChain,
			chain:       chain,
		},
		newname: newname,
	}
	command.setChild(command)
	return command
}

func (renameChain *RenameChain) Short() string {
	return "-E"
}

func (renameChain *RenameChain) Long() string {
	return "--rename-chain"
}

func newInitTable() *InitTable {
	command := &InitTable{
		baseCommand: baseCommand{
			commandType: CommandTypeInitTable,
		},
	}
	command.setChild(command)
	return command
}

type InitTable struct {
	baseCommand
}

func (initTable *InitTable) Short() string {
	return "--init-table"
}

func newAtomicInit() *AtomicInit {
	command := &AtomicInit{
		baseCommand: baseCommand{
			commandType: CommandTypeAtomicInit,
		},
	}
	command.setChild(command)
	return command
}

type AtomicInit struct {
	baseCommand
}

func (atomicInit *AtomicInit) Short() string {
	return "--atomic-init"
}

func newAtomicSave() *AtomicSave {
	command := &AtomicSave{
		baseCommand: baseCommand{
			commandType: CommandTypeAtomicSave,
		},
	}
	command.setChild(command)
	return command
}

type AtomicSave struct {
	baseCommand
}

func (atomicSave *AtomicSave) Short() string {
	return "--atomic-save"
}

func newAtomicCommit() *AtomicCommit {
	command := &AtomicCommit{
		baseCommand: baseCommand{
			commandType: CommandTypeAtomicCommit,
		},
	}
	command.setChild(command)
	return command
}

type AtomicCommit struct {
	baseCommand
}

func (atomicCommit *AtomicCommit) Short() string {
	return "--atomic-commit"
}
