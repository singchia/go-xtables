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
	OptionTypeListMACSameLength
	OptionTypeModprobe
	OptionTypeSetCounters
	OptionTypeAtomicFile
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

func newOptionConcurrent() (*OptionConcurrent, error) {
	option := &OptionConcurrent{
		baseOption: baseOption{
			optionType: OptionTypeConcurrent,
		},
	}
	option.setChild(option)
	return option, nil
}

// Use a file lock to support concurrent scripts updating the
// ebtables kernel tables.
type OptionConcurrent struct {
	baseOption
}

func (opt *OptionConcurrent) Short() string {
	return strings.Join(opt.ShortArgs(), " ")
}

func (opt *OptionConcurrent) ShortArgs() []string {
	return []string{"--concurrent"}
}

func newOptionListNumbers() (*OptionListNumbers, error) {
	option := &OptionListNumbers{
		baseOption: baseOption{
			optionType: OptionTypeListNumbers,
		},
	}
	option.setChild(option)
	return option, nil
}

// Must be shown with List command.
type OptionListNumbers struct {
	baseOption
}

func (opt *OptionListNumbers) Short() string {
	return strings.Join(opt.ShortArgs(), " ")
}

func (opt *OptionListNumbers) ShortArgs() []string {
	return []string{"--Ln"}
}

func newOptionListCounters() (*OptionListCounters, error) {
	option := &OptionListCounters{
		baseOption: baseOption{
			optionType: OptionTypeListCounters,
		},
	}
	option.setChild(option)
	return option, nil
}

type OptionListCounters struct {
	baseOption
}

func (opt *OptionListCounters) Short() string {
	return strings.Join(opt.ShortArgs(), " ")
}

func (opt *OptionListCounters) ShortArgs() []string {
	return []string{"--Lc"}
}

type OptionListMACSameLength struct {
	baseOption
}

func (opt *OptionListMACSameLength) Short() string {
	return strings.Join(opt.ShortArgs(), " ")
}

func (opt *OptionListMACSameLength) ShortArgs() []string {
	return []string{"--Lx"}
}

func newOptionModprobe(program string) (*OptionModprobe, error) {
	option := &OptionModprobe{
		baseOption: baseOption{
			optionType: OptionTypeModprobe,
		},
	}
	option.setChild(option)
	return option, nil
}

// When talking to the kernel, use this program to try to automatically
// load missing kernel modules.
type OptionModprobe struct {
	baseOption
	program string
}

func (opt *OptionModprobe) Short() string {
	return strings.Join(opt.ShortArgs(), " ")
}

func (opt *OptionModprobe) ShortArgs() []string {
	return []string{"--modprobe", opt.program}
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

// If used with Append or Insert, then the packet and byte counters of
// the  new rule will be set to packets, resp. bytes. If used with the
// Check or Delete commands, only rules with a packet and byte count
// queal to packets, resp. bytes will match.
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

func newOptionAtomicFile(path string) (*OptionAtomicFile, error) {
	option := &OptionAtomicFile{
		baseOption: baseOption{
			optionType: OptionTypeAtomicFile,
		},
		path: path,
	}
	option.setChild(option)
	return option, nil
}

// Let the command operate on the specified file. The data of the table
// to operate on will be extracted from the file and the result of the
// operation will be saved back into the file.
type OptionAtomicFile struct {
	baseOption
	path string
}

func (opt *OptionAtomicFile) Short() string {
	return strings.Join(opt.ShortArgs(), " ")
}

func (opt *OptionAtomicFile) ShortArgs() []string {
	return []string{"--atomic-file", opt.path}
}
