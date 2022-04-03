/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
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
	invert     bool
}

func (bo baseOption) Type() OptionType {
	return bo.optionType
}

func (bo baseOption) Short() string {
	return ""
}

func (bo baseOption) ShortArgs() []string {
	return nil
}

func (bo baseOption) Long() string {
	return ""
}

func (bo baseOption) LongArgs() []string {
	return nil
}

type OptionFragment struct {
	baseOption
}

func (oFrag *OptionFragment) Short() string {
	if oFrag.invert {
		return "! -f"
	}
	return "-f"
}

func (oFrag *OptionFragment) ShortArgs() []string {
	if oFrag.invert {
		return []string{"!", "-f"}
	}
	return []string{"-f"}
}

func (oFrag *OptionFragment) Long() string {
	if oFrag.invert {
		return "! --fragment"
	}
	return "--fragment"
}

func (oFrag *OptionFragment) LongArgs() []string {
	if oFrag.invert {
		return []string{"!", "--fragment"}
	}
	return []string{"--fragment"}
}

type OptionSetCounters struct {
	baseOption
	packets uint64
	bytes   uint64
}

func (oCounters *OptionSetCounters) Short() string {
	return fmt.Sprintf("-c %d %d", oCounters.packets, oCounters.bytes)
}

func (oCounters *OptionSetCounters) ShortArgs() []string {
	return []string{"-c",
		strconv.FormatUint(oCounters.packets, 10),
		strconv.FormatUint(oCounters.bytes, 10),
	}
}

func (oCounters *OptionSetCounters) Long() string {
	return fmt.Sprintf("--set-counters %d %d", oCounters.packets, oCounters.bytes)
}

func (oCounters *OptionSetCounters) LongArgs() []string {
	return []string{"--set-counters",
		strconv.FormatUint(oCounters.packets, 10),
		strconv.FormatUint(oCounters.bytes, 10),
	}
}

type OptionVerbose struct {
	baseOption
}

func (oVerbose *OptionVerbose) Short() string {
	return "-v"
}

func (oVerbose *OptionVerbose) ShortArgs() []string {
	return []string{"-v"}
}

func (oVerbose *OptionVerbose) Long() string {
	return "--verbose"
}

func (oVerbose *OptionVerbose) LongArgs() []string {
	return []string{"--verbose"}
}

type OptionWait struct {
	baseOption
	seconds uint32
}

func (oWait *OptionWait) Short() string {
	if oWait.seconds == 0 {
		// indefinitely
		return "-w"
	}
	return fmt.Sprintf("-w %d", oWait.seconds)
}

func (oWait *OptionWait) ShortArgs() []string {
	if oWait.seconds == 0 {
		// indefinitely
		return []string{"-w"}
	}
	return []string{"-w", strconv.FormatUint(uint64(oWait.seconds), 10)}
}

func (oWait *OptionWait) Long() string {
	if oWait.seconds == 0 {
		// indefinitely
		return "--wait"
	}
	return fmt.Sprintf("--wait %d", oWait.seconds)
}

func (oWait *OptionWait) LongArgs() []string {
	if oWait.seconds == 0 {
		// indefinitely
		return []string{"--wait"}
	}
	return []string{"--wait", strconv.FormatUint(uint64(oWait.seconds), 10)}
}

type OptionWaitInterval struct {
	baseOption
	microseconds uint64
}

func (oWaitInterval *OptionWaitInterval) Short() string {
	return fmt.Sprintf("-W %d", oWaitInterval.microseconds)
}

func (oWaitInterval *OptionWaitInterval) ShortArgs() []string {
	return []string{"-W", strconv.FormatUint(oWaitInterval.microseconds, 10)}
}

func (oWaitInterval *OptionWaitInterval) Long() string {
	return fmt.Sprintf("--wait-interval %d", oWaitInterval.microseconds)
}

func (oWaitInterval *OptionWaitInterval) LongArgs() []string {
	return []string{"--wait-interval", strconv.FormatUint(oWaitInterval.microseconds, 10)}
}

type OptionNotNumeric struct{}

// by default
type OptionNumeric struct {
	baseOption
}

func (oNumeric *OptionNumeric) Short() string {
	return "-n"
}

func (oNumeric *OptionNumeric) ShortArgs() []string {
	return []string{"-n"}
}

func (oNumeric *OptionNumeric) Long() string {
	return "-n"
}

func (oNumeric *OptionNumeric) LongArgs() []string {
	return []string{"-n"}
}

type OptionExact struct {
	baseOption
}

func (oExact *OptionExact) Short() string {
	return "-x"
}

func (oExact *OptionExact) ShortArgs() []string {
	return []string{"-x"}
}

func (oExact *OptionExact) Long() string {
	return "--exact"
}

func (oExact *OptionExact) LongArgs() []string {
	return []string{"--exact"}
}

type OptionLineNumbers struct {
	baseOption
}

func (oLineNumbers *OptionLineNumbers) Short() string {
	return "--line-numbers"
}

func (oLineNumbers *OptionLineNumbers) ShortArgs() []string {
	return []string{"--line-numbers"}
}

func (oLineNumbers *OptionLineNumbers) Long() string {
	return "--line-numbers"
}

func (oLineNumbers *OptionLineNumbers) LongArgs() []string {
	return []string{"--line-numbers"}
}

type OptionModprobe struct {
	baseOption
	command string
}

func (oModprobe *OptionModprobe) Short() string {
	return fmt.Sprintf("--modprobe=%s", oModprobe.command)
}

func (oModprobe *OptionModprobe) ShortArgs() []string {
	return []string{fmt.Sprintf("--modprobe=%s", oModprobe.command)}
}

func (oModprobe *OptionModprobe) Long() string {
	return fmt.Sprintf("--modprobe=%s", oModprobe.command)
}

func (oModprobe *OptionModprobe) LongArgs() []string {
	return []string{fmt.Sprintf("--modprobe=%s", oModprobe.command)}
}
