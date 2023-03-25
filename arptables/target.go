package arptables

import (
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
	TargetTypeMangle
	TargetTypeClassify
	TargetTypeEmpty
)

var (
	TargetTypeValue = map[TargetType]string{
		TargetTypeAccept:    "ACCEPT",
		TargetTypeContinue:  "CONTINUE",
		TargetTypeDrop:      "DROP",
		TargetTypeReturn:    "RETURN",
		TargetTypeJumpChain: "JUMP",
		TargetTypeMangle:    "mangle",
		TargetTypeClassify:  "CLASSIFY",
	}

	TargetValueType = map[string]TargetType{
		"ACCEPT":   TargetTypeAccept,
		"CONTINUE": TargetTypeContinue,
		"DROP":     TargetTypeDrop,
		"RETURN":   TargetTypeReturn,
		"JUMP":     TargetTypeJumpChain,
		"mangle":   TargetTypeMangle,
		"CLASSIFY": TargetTypeClassify,
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
	case TargetTypeClassify:
		return "CLASSIFY"
	case TargetTypeMangle:
		return "mangle"
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
		target := NewTargetAccept()
		return target
	case TargetTypeContinue:
		target := NewTargetContinue()
		return target
	case TargetTypeDrop:
		target := NewTargetDrop()
		return target
	case TargetTypeReturn:
		target := NewTargetReturn()
		return target
	case TargetTypeJumpChain:
		target := NewTargetJumpChain("")
		return target
	case TargetTypeMangle:
		target, _ := NewTargetMangle()
		return target
	case TargetTypeClassify:
		target, _ := NewTargetClassify(0, 0)
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
	return bt.LongArgs()
}

func (bt baseTarget) Parse([]byte) (int, bool) {
	return 0, false
}

type TargetEmpty struct {
	baseTarget
}

func NewTargetEmpty() (*TargetEmpty, error) {
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

func NewTargetUnknown(unknown string) *TargetUnknown {
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

func NewTargetAccept() *TargetAccept {
	return &TargetAccept{
		baseTarget: baseTarget{
			targetType: TargetTypeAccept,
		},
	}
}

func (ta *TargetAccept) Short() string {
	return "-j ACCEPT"
}

func (ta *TargetAccept) ShortArgs() []string {
	return []string{"-j", "ACCEPT"}
}

func (ta *TargetAccept) Long() string {
	return ta.Short()
}

func (ta *TargetAccept) LongArgs() []string {
	return ta.ShortArgs()
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

func NewTargetContinue() *TargetContinue {
	return &TargetContinue{
		baseTarget: baseTarget{
			targetType: TargetTypeContinue,
		},
	}
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

func NewTargetDrop() *TargetDrop {
	return &TargetDrop{
		baseTarget: baseTarget{
			targetType: TargetTypeDrop,
		},
	}
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

func NewTargetReturn() *TargetReturn {
	return &TargetReturn{
		baseTarget: baseTarget{
			targetType: TargetTypeReturn,
		},
	}
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

func NewTargetJumpChain(chain string) *TargetJumpChain {
	return &TargetJumpChain{
		baseTarget: baseTarget{
			targetType: TargetTypeJumpChain,
		},
		chain: chain,
	}
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
	pattern := `-j ([[:graph:]]) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 2 {
		return 0, false
	}
	tj.chain = string(matches[1])
	return len(matches[0]), true
}

type OptionTargetMangle func(*TargetMangle)

// Mangles source IP address to given value.
func WithTargetMangleSourceIP(ip net.IP) OptionTargetMangle {
	return func(target *TargetMangle) {
		target.SourceIP = ip
	}
}

// Mangles destination IP address to given value.
func WithTargetMangleDestinationIP(ip net.IP) OptionTargetMangle {
	return func(target *TargetMangle) {
		target.DestinationIP = ip
	}
}

// Mangles source MAC address to given value.
func WithTargetMangleSourceMAC(mac net.HardwareAddr) OptionTargetMangle {
	return func(target *TargetMangle) {
		target.SourceMAC = mac
	}
}

// Mangles destination MAC address to given value.
func WithTargetMangleDestinationMAC(mac net.HardwareAddr) OptionTargetMangle {
	return func(target *TargetMangle) {
		target.DestinationMAC = mac
	}
}

// Target of ARP mangle operation, default is ACCEPT.
func WithTargetMangleTarget(tgt TargetType) OptionTargetMangle {
	return func(target *TargetMangle) {
		target.MangleTarget = tgt
	}
}

func NewTargetMangle(opts ...OptionTargetMangle) (*TargetMangle, error) {
	target := &TargetMangle{
		baseTarget: baseTarget{
			targetType: TargetTypeMangle,
		},
	}
	target.setChild(target)
	for _, opt := range opts {
		opt(target)
	}
	return target, nil
}

type TargetMangle struct {
	baseTarget
	SourceIP       net.IP
	DestinationIP  net.IP
	SourceMAC      net.HardwareAddr
	DestinationMAC net.HardwareAddr
	MangleTarget   TargetType
}

func (target *TargetMangle) Short() string {
	return strings.Join(target.ShortArgs(), " ")
}

func (target *TargetMangle) ShortArgs() []string {
	args := make([]string, 0, 10)
	if target.SourceIP != nil {
		args = append(args, "--mangle-ip-s", target.SourceIP.String())
	}
	if target.DestinationIP != nil {
		args = append(args, "--mangle-ip-d", target.DestinationIP.String())
	}
	if target.SourceMAC != nil {
		args = append(args, "--mangle-mac-s", target.SourceMAC.String())
	}
	if target.DestinationMAC != nil {
		args = append(args, "--mangle-mac-d", target.DestinationMAC.String())
	}
	if target.MangleTarget != TargetTypeUnknown {
		args = append(args, "--mangle-target", target.MangleTarget.String())
	}
	return args
}

func (target *TargetMangle) Parse(main []byte) (int, bool) {
	// 1. "--mangle"
	// 2. "(-(ip-s|ip-d|mac-s|mac-d) ([[:graph:]]+))?" #1 #2 #3
	// 3. "(-target (ACCEPT|CONTINUE|DROP|RETURN))? *" #4 #5
	pattern := `--mangle` +
		`(-(ip-s|ip-d|mac-s|mac-d) ([[:graph:]]+))?` +
		`(-target (ACCEPT|CONTINUE|DROP|RETURN))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 6 {
		return 0, false
	}
	switch string(matches[2]) {
	case "ip-s":
		target.SourceIP = net.ParseIP(string(matches[3]))
	case "ip-d":
		target.DestinationIP = net.ParseIP(string(matches[3]))
	case "mac-s":
		mac, err := net.ParseMAC(string(matches[3]))
		if err != nil {
			return 0, false
		}
		target.SourceMAC = mac
	case "mac-d":
		mac, err := net.ParseMAC(string(matches[3]))
		if err != nil {
			return 0, false
		}
		target.DestinationMAC = mac
	}

	switch string(matches[5]) {
	case "ACCEPT":
		target.MangleTarget = TargetTypeAccept
	case "CONTINUE":
		target.MangleTarget = TargetTypeContinue
	case "DROP":
		target.MangleTarget = TargetTypeDrop
	case "RETURN":
		target.MangleTarget = TargetTypeReturn
	}
	return len(matches[0]), true
}

// This module allows you to set the skb->priority value.
func NewTargetClassify(major, minor uint16) (*TargetClassify, error) {
	target := &TargetClassify{
		baseTarget: baseTarget{
			targetType: TargetTypeClassify,
		},
		Major: int(major),
		Minor: int(minor),
	}
	return target, nil
}

type TargetClassify struct {
	baseTarget
	Major int
	Minor int
}

func (target *TargetClassify) Short() string {
	return strings.Join(target.ShortArgs(), " ")
}

func (target *TargetClassify) ShortArgs() []string {
	args := make([]string, 0, 2)
	if target.Major > -1 && target.Minor > -1 {
		args = append(args, "--set-class",
			strconv.Itoa(target.Major)+":"+strconv.Itoa(target.Minor))
	}
	return args
}

func (target *TargetClassify) Parse(main []byte) (int, bool) {
	// 1. "--set-class ([0-9A-Za-z]+):([0-9A-Za-z]+) *" #1 #2
	pattern := `--set-class ([0-9A-Za-z]+):([0-9A-Za-z]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	major, err := strconv.ParseInt(string(matches[1]), 16, 32)
	if err != nil {
		return 0, false
	}
	minor, err := strconv.ParseInt(string(matches[2]), 16, 32)
	if err != nil {
		return 0, false
	}
	target.Major = int(major)
	target.Minor = int(minor)
	return len(matches[0]), true
}

var (
	targetPrefixes = map[string]TargetType{
		"-j ACCEPT":    TargetTypeAccept,
		"-j CONTINUE":  TargetTypeContinue,
		"-j DROP":      TargetTypeDrop,
		"-j RETURN":    TargetTypeReturn,
		"-j CLASSIFY ": TargetTypeClassify,
		"-j mangle ":   TargetTypeMangle,
		"-j ":          TargetTypeJumpChain,
	}

	targetTrie tree.Trie
)

func init() {
	targetTrie = tree.NewTrie()
	for prefix, typ := range targetPrefixes {
		targetTrie.Add(prefix, typ)
	}
}

func ParseTarget(params []byte) (Target, int, error) {
	node, ok := targetTrie.LPM(string(params))
	if !ok {
		return nil, 0, xtables.ErrTargetNotFound
	}
	typ := node.Value().(TargetType)
	// get target by target type
	target := TargetFactory(typ)
	if target == nil {
		return nil, 0, xtables.ErrMatchParams
	}
	if typ != TargetTypeClassify && typ != TargetTypeMangle {
		offset, ok := target.Parse(params)
		if !ok {
			return nil, 0, xtables.ErrMatchParams
		}
		return target, offset, nil
	}
	return target, len(node.Word()), nil
}
