package arptables

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
	_ OptionType = iota
	OptionTypeSetCounters
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

func NewOptionSetCounters(packets, bytes uint64) (*OptionSetCounters, error) {
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

// This enables the administrator to initialize the packet and byte counters
// of a rule(during INSERT, APPEND, REPLACE operations).
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
