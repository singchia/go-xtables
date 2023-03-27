package ebtables

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/singchia/go-hammer/tree"
	"github.com/singchia/go-xtables"
)

type TargetType int

const (
	TargetTypeUnknown TargetType = iota
	TargetTypeAccept
	TargetTypeContinue
	TargetTypeDrop
	TargetTypeReturn
	TargetTypeJumpChain // jump chain
	TargetTypeARPReply
	TargetTypeDNAT
	TargetTypeMark
	TargetTypeRedirect
	TargetTypeSNAT
	TargetTypeEmpty
)

var (
	TargetTypeValue = map[TargetType]string{
		TargetTypeAccept:    "ACCEPT",
		TargetTypeContinue:  "CONTINUE",
		TargetTypeDrop:      "DROP",
		TargetTypeReturn:    "RETURN",
		TargetTypeJumpChain: "JUMP",
		TargetTypeARPReply:  "arpreply",
		TargetTypeDNAT:      "dnat",
		TargetTypeMark:      "mark",
		TargetTypeRedirect:  "redirect",
		TargetTypeSNAT:      "snat",
	}

	TargetValueType = map[string]TargetType{
		"ACCEPT":   TargetTypeAccept,
		"CONTINUE": TargetTypeContinue,
		"DROP":     TargetTypeDrop,
		"RETURN":   TargetTypeReturn,
		"JUMP":     TargetTypeJumpChain,
		"arpreply": TargetTypeARPReply,
		"dnat":     TargetTypeDNAT,
		"mark":     TargetTypeMark,
		"redirect": TargetTypeRedirect,
		"snat":     TargetTypeSNAT,
	}
)

func (tt TargetType) Type() string {
	return "TargetType"
}

func (tt TargetType) Value() string {
	return strconv.Itoa(int(tt))
}

func (tt TargetType) String() string {
	switch tt {
	case TargetTypeAccept:
		return "ACCEPT"
	case TargetTypeContinue:
		return "CONTINUE"
	case TargetTypeDrop:
		return "DROP"
	case TargetTypeReturn:
		return "RETURN"
	case TargetTypeJumpChain:
		return "JUMP"
	case TargetTypeARPReply:
		return "arpreply"
	case TargetTypeDNAT:
		return "dnat"
	case TargetTypeMark:
		return "mark"
	case TargetTypeRedirect:
		return "redirect"
	case TargetTypeSNAT:
		return "snat"
	default:
		return ""
	}
}

type Target interface {
	Type() TargetType
	Short() string
	Long() string
	ShortArgs() []string
	LongArgs() []string
	Parse([]byte) (int, bool)
}

func TargetFactory(targetType TargetType) Target {
	switch targetType {
	case TargetTypeAccept:
		target := newTargetAccept()
		return target
	case TargetTypeDrop:
		target := newTargetDrop()
		return target
	case TargetTypeReturn:
		target := newTargetReturn()
		return target
	case TargetTypeJumpChain:
		target := newTargetJumpChain("")
		return target
	case TargetTypeARPReply:
		target, _ := newTargetARPReply()
		return target
	case TargetTypeDNAT:
		target, _ := newTargetDNAT()
		return target
	case TargetTypeMark:
		target, _ := newTargetMark()
		return target
	case TargetTypeRedirect:
		target, _ := newTargetRedirect()
		return target
	case TargetTypeSNAT:
		target, _ := newTargetSNAT()
		return target
	}
	return nil
}

type baseTarget struct {
	targetType TargetType
	child      Target
}

func (bt baseTarget) setChild(child Target) {
	bt.child = child
}

func (bt baseTarget) Type() TargetType {
	return bt.targetType
}

func (bt baseTarget) Short() string {
	if bt.child != nil {
		return bt.child.Short()
	}
	return ""
}

func (bt baseTarget) ShortArgs() []string {
	if bt.child != nil {
		return bt.child.ShortArgs()
	}
	return nil
}

func (bt baseTarget) Long() string {
	return bt.Short()
}

func (bt baseTarget) LongArgs() []string {
	return bt.ShortArgs()
}

func (bt baseTarget) Parse([]byte) (int, bool) {
	return 0, false
}

type TargetEmpty struct {
	baseTarget
}

func newTargetEmpty() (*TargetEmpty, error) {
	return &TargetEmpty{
		baseTarget: baseTarget{
			targetType: TargetTypeEmpty,
		},
	}, nil
}

type TargetUnknown struct {
	baseTarget
	unknown string
}

func newTargetUnknown(unknown string) *TargetUnknown {
	return &TargetUnknown{
		baseTarget: baseTarget{
			targetType: TargetTypeUnknown,
		},
		unknown: unknown,
	}
}

func (tu *TargetUnknown) Unknown() string {
	return tu.unknown
}

type TargetAccept struct {
	baseTarget
}

func newTargetAccept() *TargetAccept {
	target := &TargetAccept{
		baseTarget: baseTarget{
			targetType: TargetTypeAccept,
		},
	}
	target.setChild(target)
	return target
}

func (ta *TargetAccept) Short() string {
	return "-j ACCEPT"
}

func (ta *TargetAccept) ShortArgs() []string {
	return []string{"-j", "ACCEPT"}
}

func (ta *TargetAccept) Long() string {
	return "--jump ACCEPT"
}

func (ta *TargetAccept) LongArgs() []string {
	return []string{"--jump", "ACCEPT"}
}

func (ta *TargetAccept) Parse(main []byte) (int, bool) {
	pattern := `-j ACCEPT *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 1 {
		return 0, false
	}
	return len(matches[0]), true
}

type TargetContinue struct {
	baseTarget
}

func newTargetContinue() *TargetContinue {
	target := &TargetContinue{
		baseTarget: baseTarget{
			targetType: TargetTypeContinue,
		},
	}
	target.setChild(target)
	return target
}

func (tc *TargetContinue) Short() string {
	return "-j CONTINUE"
}

func (tc *TargetContinue) ShortArgs() []string {
	return []string{"-j", "CONTINUE"}
}

func (tc *TargetContinue) Long() string {
	return "--jump CONTINUE"
}

func (tc *TargetContinue) LongArgs() []string {
	return []string{"--jump", "CONTINUE"}
}

func (tc *TargetContinue) Parse(main []byte) (int, bool) {
	pattern := `-j CONTINUE *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 1 {
		return 0, false
	}
	return len(matches[0]), true
}

type TargetDrop struct {
	baseTarget
}

func newTargetDrop() *TargetDrop {
	target := &TargetDrop{
		baseTarget: baseTarget{
			targetType: TargetTypeDrop,
		},
	}
	target.setChild(target)
	return target
}

func (td *TargetDrop) Short() string {
	return "-j DROP"
}

func (td *TargetDrop) ShortArgs() []string {
	return []string{"-j", "ACCEPT"}
}

func (td *TargetDrop) Long() string {
	return "--jump DROP"
}

func (td *TargetDrop) LongArgs() []string {
	return []string{"--jump", "DROP"}
}

func (td *TargetDrop) Parse(main []byte) (int, bool) {
	pattern := `-j DROP *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 1 {
		return 0, false
	}
	return len(matches[0]), true
}

type TargetReturn struct {
	baseTarget
}

func newTargetReturn() *TargetReturn {
	target := &TargetReturn{
		baseTarget: baseTarget{
			targetType: TargetTypeReturn,
		},
	}
	target.setChild(target)
	return target
}

func (tr *TargetReturn) Short() string {
	return "-j RETURN"
}

func (tr *TargetReturn) ShortArgs() []string {
	return []string{"-j", "RETURN"}
}

func (tr *TargetReturn) Long() string {
	return "--jump RETURN"
}

func (tr *TargetReturn) LongArgs() []string {
	return []string{"--jump", "RETURN"}
}

func (tr *TargetReturn) Parse(main []byte) (int, bool) {
	pattern := `-j RETURN *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 1 {
		return 0, false
	}
	return len(matches[0]), true
}

type TargetJumpChain struct {
	baseTarget
	chain string
}

func newTargetJumpChain(chain string) *TargetJumpChain {
	target := &TargetJumpChain{
		baseTarget: baseTarget{
			targetType: TargetTypeJumpChain,
		},
		chain: chain,
	}
	target.setChild(target)
	return target
}

func (tj *TargetJumpChain) Short() string {
	return fmt.Sprintf("-j %s", tj.chain)
}

func (tj *TargetJumpChain) ShortArgs() []string {
	return []string{"-j", tj.chain}
}

func (tj *TargetJumpChain) Long() string {
	return fmt.Sprintf("--jump %s", tj.chain)
}

func (tj *TargetJumpChain) LongArgs() []string {
	return []string{"--jump", tj.chain}
}

func (tj *TargetJumpChain) Parse(main []byte) (int, bool) {
	pattern := `-j ([[:graph:]]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 2 {
		return 0, false
	}
	tj.chain = string(matches[1])
	return len(matches[0]), true
}

type OptionTargetARPReply func(*TargetARPReply)

// Specifies the MAC address to reply with: the Ethernet source MAC and the
// ARP payload  source  MAC  will  be filled in with this address.
func WithTargetARPReplyMAC(mac net.HardwareAddr) OptionTargetARPReply {
	return func(ta *TargetARPReply) {
		ta.ARPReplyMAC = mac
	}
}

// Specifies the standard target. After sending the ARP reply, the rule still has to
// give a standard target so ebtables knows what to do with the ARP request.
// The default target is DROP.
func WithTargetARPReplyTarget(typ TargetType) OptionTargetARPReply {
	return func(ta *TargetARPReply) {
		ta.ARPReplyTarget = typ
	}
}

func newTargetARPReply(opts ...OptionTargetARPReply) (*TargetARPReply, error) {
	target := &TargetARPReply{
		baseTarget: baseTarget{
			targetType: TargetTypeARPReply,
		},
		ARPReplyMAC:    nil,
		ARPReplyTarget: TargetTypeDrop,
	}
	target.setChild(target)
	for _, opt := range opts {
		opt(target)
	}
	return target, nil
}

type TargetARPReply struct {
	baseTarget
	ARPReplyMAC    net.HardwareAddr
	ARPReplyTarget TargetType
}

func (ta *TargetARPReply) Short() string {
	return strings.Join(ta.ShortArgs(), " ")
}

func (ta *TargetARPReply) ShortArgs() []string {
	args := make([]string, 0, 6)
	args = append(args, "-j", ta.targetType.String())
	if ta.ARPReplyMAC != nil {
		args = append(args, "--arpreply-mac", ta.ARPReplyMAC.String())
	}
	if ta.ARPReplyTarget != TargetTypeUnknown {
		args = append(args, "--arpreply-target", ta.ARPReplyTarget.String())
	}
	return args
}

func (ta *TargetARPReply) Parse(main []byte) (int, bool) {
	// 1. "-j arpreply"
	// 2. "( --arpreply-mac ([[:graph:]]+))?" #1 #2
	// 3. "( --arpreply-target (ACCEPT|CONTINUE|DROP|RETURN))? *" #3 #4
	pattern := `-j arpreply` +
		`( --arpreply-mac ([[:graph:]]+))?` +
		`( --arpreply-target (ACCEPT|CONTINUE|DROP|RETURN))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		mac, err := parseMAC(main)
		if err != nil {
			return 0, false
		}
		ta.ARPReplyMAC = mac
	}
	if len(matches[4]) != 0 {
		switch string(matches[4]) {
		case "ACCEPT":
			ta.targetType = TargetTypeAccept
		case "CONTINUE":
			ta.targetType = TargetTypeContinue
		case "DROP":
			ta.targetType = TargetTypeDrop
		case "RETURN":
			ta.targetType = TargetTypeReturn
		}
	}
	return len(matches[0]), true
}

type OptionTargetDNAT func(*TargetDNAT)

// Change the destination MAC address to the specified address.
func WithTargetDNATToDestination(mac net.HardwareAddr) OptionTargetDNAT {
	return func(td *TargetDNAT) {
		td.ToDestination = mac
	}
}

// Specifies the standard target. After doing the dnat, the rule still
// has to give a standard target so  ebtables  knows  what to do with the dnated frame.
func WithTargetDNATTarget(typ TargetType) OptionTargetDNAT {
	return func(td *TargetDNAT) {
		td.DNATTarget = typ
	}
}

func newTargetDNAT(opts ...OptionTargetDNAT) (*TargetDNAT, error) {
	target := &TargetDNAT{
		baseTarget: baseTarget{
			targetType: TargetTypeDNAT,
		},
		ToDestination: nil,
		DNATTarget:    TargetTypeAccept,
	}
	target.setChild(target)
	for _, opt := range opts {
		opt(target)
	}
	return target, nil
}

type TargetDNAT struct {
	baseTarget
	ToDestination net.HardwareAddr
	DNATTarget    TargetType
}

func (td *TargetDNAT) Short() string {
	return strings.Join(td.ShortArgs(), " ")
}

func (td *TargetDNAT) ShortArgs() []string {
	args := make([]string, 0, 6)
	args = append(args, "-j", td.targetType.String())
	if td.ToDestination != nil {
		args = append(args, "--to-destination", td.ToDestination.String())
	}
	if td.DNATTarget != TargetTypeUnknown {
		args = append(args, "--dnat-target", td.DNATTarget.String())
	}
	return args
}

func (td *TargetDNAT) Parse(main []byte) (int, bool) {
	// 1. "-j dnat"
	// 2. "( --to-destination ([[:graph:]]+))?" #1 #2
	// 3. "( --dnat-target (ACCEPT|CONTINUE|DROP|RETURN))? *" #3 #4
	pattern := `-j dnat` +
		`( --to-destination ([[:graph:]]+))?` +
		`( --arpreply-target (ACCEPT|CONTINUE|DROP|RETURN))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		mac, err := parseMAC(main)
		if err != nil {
			return 0, false
		}
		td.ToDestination = mac
	}
	if len(matches[4]) != 0 {
		switch string(matches[4]) {
		case "ACCEPT":
			td.DNATTarget = TargetTypeAccept
		case "CONTINUE":
			td.DNATTarget = TargetTypeContinue
		case "DROP":
			td.DNATTarget = TargetTypeDrop
		case "RETURN":
			td.DNATTarget = TargetTypeReturn
		}
	}
	return len(matches[0]), true
}

type OptionTargetMark func(*TargetMark)

func WithTargetMarkSet(mark int) OptionTargetMark {
	return func(tm *TargetMark) {
		tm.Operator = xtables.OperatorSET
		tm.Mark = mark
	}
}

func WithTargetMarkOr(mark int) OptionTargetMark {
	return func(tm *TargetMark) {
		tm.Operator = xtables.OperatorOR
		tm.Mark = mark
	}
}

func WithTargetMarkAnd(mark int) OptionTargetMark {
	return func(tm *TargetMark) {
		tm.Operator = xtables.OperatorAND
		tm.Mark = mark
	}
}

func WithTargetMarkXor(mark int) OptionTargetMark {
	return func(tm *TargetMark) {
		tm.Operator = xtables.OperatorXOR
		tm.Mark = mark
	}
}

// Specifies the standard target. After marking the frame, the rule still
// has to give a standard target so ebtables knows what to do.
// The default target is ACCEPT. Making it CONTINUE could let you do other
// things with the frame in subsequent rules of the chain.
func WithTargetMarkTarget(typ TargetType) OptionTargetMark {
	return func(tm *TargetMark) {
		tm.MarkTarget = typ
	}
}

func newTargetMark(opts ...OptionTargetMark) (*TargetMark, error) {
	target := &TargetMark{
		baseTarget: baseTarget{
			targetType: TargetTypeMark,
		},
		MarkTarget: TargetTypeAccept,
	}
	target.setChild(target)
	for _, opt := range opts {
		opt(target)
	}
	return target, nil
}

// The mark target can be used in every chain of every table. It is possible to use
// the marking of a frame/packet in both  ebtables  and  iptables,
// if the bridge-nf code is compiled into the kernel. Both put the marking at the same
// place. This allows for a form of communication between ebtables and iptables.
type TargetMark struct {
	baseTarget
	Operator   xtables.Operator
	Mark       int
	MarkTarget TargetType
}

func (tm *TargetMark) Short() string {
	return strings.Join(tm.ShortArgs(), " ")
}

func (tm *TargetMark) ShortArgs() []string {
	args := make([]string, 0, 12)
	args = append(args, "-j", tm.targetType.String())
	switch tm.Operator {
	case xtables.OperatorSET:
		args = append(args, "--mark-set", strconv.Itoa(tm.Mark))
	case xtables.OperatorOR:
		args = append(args, "--mark-or", strconv.Itoa(tm.Mark))
	case xtables.OperatorAND:
		args = append(args, "--mark-and", strconv.Itoa(tm.Mark))
	case xtables.OperatorXOR:
		args = append(args, "--mark-xor", strconv.Itoa(tm.Mark))
	}
	if tm.MarkTarget != TargetTypeUnknown {
		args = append(args, "--mark-target", tm.MarkTarget.String())
	}
	return args
}

func (tm *TargetMark) Parse(main []byte) (int, bool) {
	// 1. "-j mark"
	// 2. "(--mark-(set|or|and|xor) ([0-9]+))?" #1 #2 #3
	// 3. "( --mark-target (ACCEPT|CONTINUE|DROP|RETURN))? *" #4 #5
	pattern := `-j mark` +
		`( --mark-(set|or|and|xor) ([0-9]+))?` +
		`( --mark-target (ACCEPT|CONTINUE|DROP|RETURN))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 6 {
		return 0, false
	}
	value, err := strconv.Atoi(string(matches[3]))
	if err != nil {
		return 0, false
	}
	tm.Mark = value
	switch string(matches[2]) {
	case "set":
		tm.Operator = xtables.OperatorSET
	case "or":
		tm.Operator = xtables.OperatorOR
	case "and":
		tm.Operator = xtables.OperatorAND
	case "xor":
		tm.Operator = xtables.OperatorXOR
	}
	if len(matches[5]) != 0 {
		switch string(matches[5]) {
		case "ACCEPT":
			tm.MarkTarget = TargetTypeAccept
		case "CONTINUE":
			tm.MarkTarget = TargetTypeContinue
		case "DROP":
			tm.MarkTarget = TargetTypeDrop
		case "RETURN":
			tm.MarkTarget = TargetTypeReturn
		}
	}
	return len(matches[0]), true
}

type OptionTargetRedirect func(*TargetRedirect)

// Specifies the standard target. After doing the MAC redirect, the rule still
// has to give a standard target so ebtables knows what to do.
// The default target is ACCEPT. Making it CONTINUE could let you use multiple
// target extensions on the same frame. Making it DROP in the BROUTING chain will
// let the grames be routed. RETURN is also allowed. Note that using RETURN in a
// base chian is not allowed.
func WithTargetRedirectTarget(typ TargetType) OptionTargetRedirect {
	return func(tr *TargetRedirect) {
		tr.RedirectTarget = typ
	}
}

func newTargetRedirect(opts ...OptionTargetRedirect) (*TargetRedirect, error) {
	target := &TargetRedirect{
		baseTarget: baseTarget{
			targetType: TargetTypeRedirect,
		},
		RedirectTarget: TargetTypeAccept,
	}
	target.setChild(target)
	for _, opt := range opts {
		opt(target)
	}
	return target, nil
}

// The redirect target will change the MAC target address to that of the bridge
// device the frame arrived on. This target can only be used in the PREROUTING
// chain of the nat table. The MAC address of the bridge is used as destination
// address.
type TargetRedirect struct {
	baseTarget
	RedirectTarget TargetType
}

func (tr *TargetRedirect) Short() string {
	return strings.Join(tr.ShortArgs(), " ")
}

func (tr *TargetRedirect) ShortArgs() []string {
	args := make([]string, 0, 4)
	args = append(args, "-j", tr.targetType.String())
	if tr.RedirectTarget != TargetTypeUnknown {
		args = append(args, "--redirect-target", tr.RedirectTarget.String())
	}
	return args
}

func (tr *TargetRedirect) Long() string {
	return tr.Short()
}

func (tr *TargetRedirect) LongArgs() []string {
	return tr.ShortArgs()
}

func (tr *TargetRedirect) Parse(main []byte) (int, bool) {
	// 1. "-j redirect"
	// 2. "(--redirect-target (ACCEPT|CONTINUE|DROP|RETURN))? *" #1 #2
	pattern := `-j redirect` +
		`(--redirect-target (ACCEPT|CONTINUE|DROP|RETURN))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		switch string(matches[2]) {
		case "ACCEPT":
			tr.RedirectTarget = TargetTypeAccept
		case "CONTINUE":
			tr.RedirectTarget = TargetTypeContinue
		case "DROP":
			tr.RedirectTarget = TargetTypeDrop
		case "RETURN":
			tr.RedirectTarget = TargetTypeReturn
		}
	}
	return len(matches[0]), true
}

type OptionTargetSNAT func(*TargetSNAT)

// Changes the source MAC address to the specified address.
func WithTargetSNATToSource(mac net.HardwareAddr) OptionTargetSNAT {
	return func(ts *TargetSNAT) {
		ts.ToSource = mac
	}
}

// Specifies the standard target. After doing the snat, the rule still has to
// give a standard target so ebtables knows what to do. The default target is
// ACCEPT. Making it CONTINUE could let you use multiple target extensions on
// the same frame. Makeing it DROP doesn't make sense, but you could do that too.
// RETURN is also allowed. Note that using RETURN in a base chain is not allowed.
func WithTargetSNATTarget(typ TargetType) OptionTargetSNAT {
	return func(ts *TargetSNAT) {
		ts.SNATTarget = typ
	}
}

// Also change the hardware source address inside the arp header if the packet
// is an arp message and the hardware address length in the arp header is 6 bytes.
func WithTargetSNATARP() OptionTargetSNAT {
	return func(ts *TargetSNAT) {
		ts.SNATARP = true
	}
}

func newTargetSNAT(opts ...OptionTargetSNAT) (*TargetSNAT, error) {
	target := &TargetSNAT{
		baseTarget: baseTarget{
			targetType: TargetTypeSNAT,
		},
	}
	target.setChild(target)
	for _, opt := range opts {
		opt(target)
	}
	return target, nil
}

// The snat target can only be used in the POSTROUTING chain of the nat table.
// It specifies that the source MAC address has to be changed.
type TargetSNAT struct {
	baseTarget
	ToSource   net.HardwareAddr
	SNATTarget TargetType
	SNATARP    bool
}

func (ts *TargetSNAT) Short() string {
	return strings.Join(ts.ShortArgs(), " ")
}

func (ts *TargetSNAT) ShortArgs() []string {
	args := make([]string, 0, 7)
	args = append(args, "-j", ts.targetType.String())
	if ts.ToSource != nil {
		args = append(args, "--to-source", ts.ToSource.String())
	}
	if ts.SNATTarget != TargetTypeUnknown {
		args = append(args, "--snat-target", ts.SNATTarget.String())
	}
	if ts.SNATARP {
		args = append(args, "--snat-arp")
	}
	return args
}

func (ts *TargetSNAT) Parse(main []byte) (int, bool) {
	// 1. "-j snat"
	// 2. "( --to-source ([[:graph:]]+))?" #1 #2
	// 3. "( --snat-target (ACCEPT|CONTINUE|DROP|RETURN))?" #3 #4
	// 4. "( --snat-arp)? *" #5
	pattern := `-j snat` +
		`( --to-source ([[:graph:]]+))?` +
		`( --snat-target (ACCEPT|CONTINUE|DROP|RETURN))?` +
		`( --snat-arp)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		mac, err := parseMAC(main)
		if err != nil {
			return 0, false
		}
		ts.ToSource = mac
	}
	if len(matches[4]) != 0 {
		switch string(matches[4]) {
		case "ACCEPT":
			ts.SNATTarget = TargetTypeAccept
		case "CONTINUE":
			ts.SNATTarget = TargetTypeContinue
		case "DROP":
			ts.SNATTarget = TargetTypeDrop
		case "RETURN":
			ts.SNATTarget = TargetTypeReturn
		}
	}
	if len(matches[5]) != 0 {
		ts.SNATARP = true
	}
	return len(matches[0]), true
}

// for the case:
// 0:0:aa:bb:cc:dd
func parseMAC(mac []byte) (net.HardwareAddr, error) {
	parts := bytes.Split(mac, []byte{':'})
	newParts := make([][]byte, len(parts))
	for i, part := range parts {
		if len(part) == 1 {
			newParts[i] = []byte{'0', part[0]}
		} else if len(part) == 2 {
			newParts[i] = []byte{part[0], part[1]}
		}
	}
	newMac := bytes.Join(newParts, []byte{':'})
	mac, err := net.ParseMAC(string(newMac))
	return mac, err
}

var (
	targetPrefixes = map[string]TargetType{
		"-j ACCEPT":   TargetTypeAccept,
		"-j CONTINUE": TargetTypeContinue,
		"-j DROP":     TargetTypeDrop,
		"-j RETURN":   TargetTypeReturn,
		"-j":          TargetTypeJumpChain,
		"-j arpreply": TargetTypeARPReply,
		"-j dnat":     TargetTypeDNAT,
		"-j mark":     TargetTypeMark,
		"-j redirect": TargetTypeRedirect,
		"-j snat":     TargetTypeSNAT,
	}

	targetTrie tree.Trie
)

func init() {
	targetTrie = tree.NewTrie()
	for prefix, typ := range targetPrefixes {
		targetTrie.Add(prefix, typ)
	}
}

func parseTarget(params []byte) (Target, int, error) {
	node, ok := targetTrie.LPM(string(params))
	if !ok {
		fmt.Println("singchia watching 1", string(params))
		return nil, 0, xtables.ErrTargetNotFound
	}
	typ := node.Value().(TargetType)
	// get target by target type
	target := TargetFactory(typ)
	if target == nil {
		return nil, 0, xtables.ErrTargetParams
	}
	// index meaning the end of this match
	offset, ok := target.Parse(params)
	if !ok {
		return nil, 0, xtables.ErrTargetParams
	}
	return target, offset, nil
}
