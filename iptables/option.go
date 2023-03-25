package iptables

import (
	"fmt"
	"strconv"
)

type OptionType int

func (ot OptionType) Type() string {
	return "OptionType"
}

func (ot OptionType) Value() string {
	return strconv.Itoa(int(ot))
}

const (
	OptionTypeFragment OptionType = iota
	OptionTypeSetCounters
	OptionTypeVerbose
	OptionTypeWait
	OptionTypeWaitInterval
	OptionTypeNumeric
	OptionTypeNotNumeric
	OptionTypeExact
	OptionTypeLineNumbers
	OptionTypeModprobe
)

type Option interface {
	Type() OptionType
	Short() string
	ShortArgs() []string
	Long() string
	LongArgs() []string
}

type baseOption struct {
	optionType OptionType
	child      Option
	invert     bool
}

func (bo baseOption) setChild(child Option) {
	bo.child = child
}

func (bo baseOption) Type() OptionType {
	return bo.optionType
}

func (bo baseOption) Short() string {
	if bo.child != nil {
		return bo.child.Short()
	}
	return ""
}

func (bo baseOption) ShortArgs() []string {
	if bo.child != nil {
		return bo.child.ShortArgs()
	}
	return nil
}

func (bo baseOption) Long() string {
	return bo.Short()
}

func (bo baseOption) LongArgs() []string {
	return bo.ShortArgs()
}

func newOptionFragment(invert bool) (*OptionFragment, error) {
	option := &OptionFragment{
		baseOption: baseOption{
			optionType: OptionTypeFragment,
			invert:     invert,
		},
	}
	option.setChild(option)
	return option, nil
}

type OptionFragment struct {
	baseOption
}

func (opt *OptionFragment) Short() string {
	if opt.invert {
		return "! -f"
	}
	return "-f"
}

func (opt *OptionFragment) ShortArgs() []string {
	if opt.invert {
		return []string{"!", "-f"}
	}
	return []string{"-f"}
}

func (opt *OptionFragment) Long() string {
	if opt.invert {
		return "! --fragment"
	}
	return "--fragment"
}

func (opt *OptionFragment) LongArgs() []string {
	if opt.invert {
		return []string{"!", "--fragment"}
	}
	return []string{"--fragment"}
}

func newOptionSetCounters(packets, bytes uint64) (*OptionSetCounters, error) {
	option := &OptionSetCounters{
		baseOption: baseOption{
			optionType: OptionTypeSetCounters,
		},
		packets: packets,
		bytes:   bytes,
	}
	option.setChild(option)
	return option, nil
}

type OptionSetCounters struct {
	baseOption
	packets uint64
	bytes   uint64
}

func (opt *OptionSetCounters) Short() string {
	return fmt.Sprintf("-c %d %d", opt.packets, opt.bytes)
}

func (opt *OptionSetCounters) ShortArgs() []string {
	return []string{"-c",
		strconv.FormatUint(opt.packets, 10),
		strconv.FormatUint(opt.bytes, 10),
	}
}

func (opt *OptionSetCounters) Long() string {
	return fmt.Sprintf("--set-counters %d %d", opt.packets, opt.bytes)
}

func (opt *OptionSetCounters) LongArgs() []string {
	return []string{"--set-counters",
		strconv.FormatUint(opt.packets, 10),
		strconv.FormatUint(opt.bytes, 10),
	}
}

func newOptionVerbose() (*OptionVerbose, error) {
	option := &OptionVerbose{
		baseOption: baseOption{
			optionType: OptionTypeVerbose,
		},
	}
	option.setChild(option)
	return option, nil
}

type OptionVerbose struct {
	baseOption
}

func (opt *OptionVerbose) Short() string {
	return "-v"
}

func (opt *OptionVerbose) ShortArgs() []string {
	return []string{"-v"}
}

func (opt *OptionVerbose) Long() string {
	return "--verbose"
}

func (opt *OptionVerbose) LongArgs() []string {
	return []string{"--verbose"}
}

func newOptionWait(seconds uint32) (*OptionWait, error) {
	option := &OptionWait{
		baseOption: baseOption{
			optionType: OptionTypeWait,
		},
		seconds: seconds,
	}
	option.setChild(option)
	return option, nil
}

type OptionWait struct {
	baseOption
	seconds uint32
}

func (opt *OptionWait) Short() string {
	if opt.seconds == 0 {
		// indefinitely
		return "-w"
	}
	return fmt.Sprintf("-w %d", opt.seconds)
}

func (opt *OptionWait) ShortArgs() []string {
	if opt.seconds == 0 {
		// indefinitely
		return []string{"-w"}
	}
	return []string{"-w", strconv.FormatUint(uint64(opt.seconds), 10)}
}

func (opt *OptionWait) Long() string {
	if opt.seconds == 0 {
		// indefinitely
		return "--wait"
	}
	return fmt.Sprintf("--wait %d", opt.seconds)
}

func (opt *OptionWait) LongArgs() []string {
	if opt.seconds == 0 {
		// indefinitely
		return []string{"--wait"}
	}
	return []string{"--wait", strconv.FormatUint(uint64(opt.seconds), 10)}
}

func newOptionWaitInterval(microseconds uint64) (*OptionWaitInterval, error) {
	option := &OptionWaitInterval{
		baseOption: baseOption{
			optionType: OptionTypeWaitInterval,
		},
		microseconds: microseconds,
	}
	option.setChild(option)
	return option, nil
}

type OptionWaitInterval struct {
	baseOption
	microseconds uint64
}

func (opt *OptionWaitInterval) Short() string {
	return fmt.Sprintf("-W %d", opt.microseconds)
}

func (opt *OptionWaitInterval) ShortArgs() []string {
	return []string{"-W", strconv.FormatUint(opt.microseconds, 10)}
}

func (opt *OptionWaitInterval) Long() string {
	return fmt.Sprintf("--wait-interval %d", opt.microseconds)
}

func (opt *OptionWaitInterval) LongArgs() []string {
	return []string{"--wait-interval", strconv.FormatUint(opt.microseconds, 10)}
}

func newOptionNumeric() (*OptionNumeric, error) {
	option := &OptionNumeric{
		baseOption: baseOption{
			optionType: OptionTypeNumeric,
		},
	}
	option.setChild(option)
	return option, nil
}

type OptionNumeric struct {
	baseOption
}

func (opt *OptionNumeric) Short() string {
	return "-n"
}

func (opt *OptionNumeric) ShortArgs() []string {
	return []string{"-n"}
}

func newOptionExact() (*OptionExact, error) {
	option := &OptionExact{
		baseOption: baseOption{
			optionType: OptionTypeExact,
		},
	}
	option.setChild(option)
	return option, nil
}

// Display the exact value of the packet and byte counters, instead
// of only the rounded number in K's(multiples of 1000) M's(multiples
// of 1000K) or G's(multiples of 1000M). this option if only relevant
// for the List command.
type OptionExact struct {
	baseOption
}

func (opt *OptionExact) Short() string {
	return "-x"
}

func (opt *OptionExact) ShortArgs() []string {
	return []string{"-x"}
}

func (opt *OptionExact) Long() string {
	return "--exact"
}

func (opt *OptionExact) LongArgs() []string {
	return []string{"--exact"}
}

func newOptionLineNumbers() (*OptionLineNumbers, error) {
	option := &OptionLineNumbers{
		baseOption: baseOption{
			optionType: OptionTypeLineNumbers,
		},
	}
	option.setChild(option)
	return option, nil
}

// List with line numbers of each rule, corresponding to that rule's
// position in the chain.
type OptionLineNumbers struct {
	baseOption
}

func (opt *OptionLineNumbers) Short() string {
	return "--line-numbers"
}

func (opt *OptionLineNumbers) ShortArgs() []string {
	return []string{"--line-numbers"}
}

func newOptionModprobe(command string) (*OptionModprobe, error) {
	option := &OptionModprobe{
		baseOption: baseOption{
			optionType: OptionTypeModprobe,
		},
		command: command,
	}
	return option, nil
}

// When adding or inserting rule into a chain, use command to load any
// necessary modules(targets, match extensions, etc).
type OptionModprobe struct {
	baseOption
	command string
}

func (opt *OptionModprobe) Short() string {
	return fmt.Sprintf("--modprobe=%s", opt.command)
}

func (opt *OptionModprobe) ShortArgs() []string {
	return []string{fmt.Sprintf("--modprobe=%s", opt.command)}
}
