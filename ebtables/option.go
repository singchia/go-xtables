/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package ebtables

import (
	"fmt"
	"strconv"
	"strings"
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
	OptionTypeConcurrent
	OptionTypeListNumbers
	OptionTypeListCounters
	OptionTypeListChange
	OptionTypeListMACSameLength
	OptionTypeModprobe
	OptionTypeCounters
	OptionTypeAtomicFile
)

type Option interface {
	Type() OptionType
	Short() string
	ShortArgs() []string
	Long() string
	LongArgs() []string
	Equal(Option) bool
}

type baseOption struct {
	optionType OptionType
	child      Option
	invert     bool
}

func (bo *baseOption) setChild(child Option) {
	bo.child = child
}

func (bo *baseOption) Type() OptionType {
	return bo.optionType
}

func (bo *baseOption) Short() string {
	if bo.child != nil {
		return bo.child.Short()
	}
	return ""
}

func (bo *baseOption) ShortArgs() []string {
	if bo.child != nil {
		return bo.child.ShortArgs()
	}
	return nil
}

func (bo *baseOption) Long() string {
	return bo.Short()
}

func (bo *baseOption) LongArgs() []string {
	return bo.ShortArgs()
}

func (bo *baseOption) Equal(opt Option) bool {
	return bo.Short() == opt.Short()
}

// Use a file lock to support concurrent scripts updating the
// ebtables kernel tables.
type OptionConcurrent struct {
	*baseOption
}

func newOptionConcurrent() (*OptionConcurrent, error) {
	option := &OptionConcurrent{
		baseOption: &baseOption{
			optionType: OptionTypeConcurrent,
		},
	}
	option.setChild(option)
	return option, nil
}

func (opt *OptionConcurrent) Short() string {
	return strings.Join(opt.ShortArgs(), " ")
}

func (opt *OptionConcurrent) ShortArgs() []string {
	return []string{"--concurrent"}
}

// Must be shown with List command.
type OptionListNumbers struct {
	*baseOption
}

func newOptionListNumbers() (*OptionListNumbers, error) {
	option := &OptionListNumbers{
		baseOption: &baseOption{
			optionType: OptionTypeListNumbers,
		},
	}
	option.setChild(option)
	return option, nil
}

func (opt *OptionListNumbers) Short() string {
	return strings.Join(opt.ShortArgs(), " ")
}

func (opt *OptionListNumbers) ShortArgs() []string {
	return []string{"--Ln"}
}

// Shows the counters.
type OptionListCounters struct {
	*baseOption
}

func newOptionListCounters() (*OptionListCounters, error) {
	option := &OptionListCounters{
		baseOption: &baseOption{
			optionType: OptionTypeListCounters,
		},
	}
	option.setChild(option)
	return option, nil
}

func (opt *OptionListCounters) Short() string {
	return strings.Join(opt.ShortArgs(), " ")
}

func (opt *OptionListCounters) ShortArgs() []string {
	return []string{"--Lc"}
}

// Changes the output so that it produces a set of ebtables commands that
// construct the contents of the chain.
type OptionListChange struct {
	*baseOption
}

func newOptionListChange() (*OptionListChange, error) {
	option := &OptionListChange{
		baseOption: &baseOption{
			optionType: OptionTypeListChange,
		},
	}
	option.setChild(option)
	return option, nil
}

func (opt *OptionListChange) ShortArgs() []string {
	return []string{"--Lx"}
}

func (opt *OptionListChange) Short() string {
	return strings.Join(opt.ShortArgs(), " ")
}

// Shows all MAC addresses with the same length.
type OptionListMACSameLength struct {
	*baseOption
}

func newOptionListMACSameLength() (*OptionListMACSameLength, error) {
	option := &OptionListMACSameLength{
		baseOption: &baseOption{
			optionType: OptionTypeListMACSameLength,
		},
	}
	option.setChild(option)
	return option, nil
}

func (opt *OptionListMACSameLength) Short() string {
	return strings.Join(opt.ShortArgs(), " ")
}

func (opt *OptionListMACSameLength) ShortArgs() []string {
	return []string{"--Lmac2"}
}

// When talking to the kernel, use this program to try to automatically
// load missing kernel modules.
type OptionModprobe struct {
	*baseOption
	program string
}

func newOptionModprobe(program string) (*OptionModprobe, error) {
	option := &OptionModprobe{
		baseOption: &baseOption{
			optionType: OptionTypeModprobe,
		},
	}
	option.setChild(option)
	return option, nil
}

func (opt *OptionModprobe) Short() string {
	return strings.Join(opt.ShortArgs(), " ")
}

func (opt *OptionModprobe) ShortArgs() []string {
	return []string{"--modprobe", opt.program}
}

// If used with Append or Insert, then the packet and byte counters of
// the  new rule will be set to packets, resp. bytes. If used with the
// Check or Delete commands, only rules with a packet and byte count
// queal to packets, resp. bytes will match.
type OptionCounters struct {
	*baseOption
	packets int64
	bytes   int64
}

func newOptionCounters(packets, bytes int64) (*OptionCounters, error) {
	option := &OptionCounters{
		baseOption: &baseOption{
			optionType: OptionTypeCounters,
		},
		packets: packets,
		bytes:   bytes,
	}
	option.setChild(option)
	return option, nil
}

func (opt *OptionCounters) Short() string {
	return fmt.Sprintf("-c %d %d", opt.packets, opt.bytes)
}

func (opt *OptionCounters) ShortArgs() []string {
	return []string{"-c",
		strconv.FormatInt(opt.packets, 10),
		strconv.FormatInt(opt.bytes, 10),
	}
}

func (opt *OptionCounters) Long() string {
	return fmt.Sprintf("--set-counters %d %d", opt.packets, opt.bytes)
}

func (opt *OptionCounters) LongArgs() []string {
	return []string{"--set-counters",
		strconv.FormatInt(opt.packets, 10),
		strconv.FormatInt(opt.bytes, 10),
	}
}

// Let the command operate on the specified file. The data of the table
// to operate on will be extracted from the file and the result of the
// operation will be saved back into the file.
type OptionAtomicFile struct {
	*baseOption
	path string
}

func newOptionAtomicFile(path string) (*OptionAtomicFile, error) {
	option := &OptionAtomicFile{
		baseOption: &baseOption{
			optionType: OptionTypeAtomicFile,
		},
		path: path,
	}
	option.setChild(option)
	return option, nil
}

func (opt *OptionAtomicFile) Short() string {
	return strings.Join(opt.ShortArgs(), " ")
}

func (opt *OptionAtomicFile) ShortArgs() []string {
	return []string{"--atomic-file", opt.path}
}
