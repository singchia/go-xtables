/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package iptables

import "fmt"

type OptionType int

const (
	OptionTypeFragment OptionType = iota
	OptionTypeSetCounters
	OptionTypeVerbose
	OptionTypeWait
	OptionTypeWaitInterval
	OptionTypeNumeric
	OptionTypeExact
	OptionTypeLineNumbers
	OptionTypeModprobe
)

type Option interface {
	Type() OptionType
	Short() string
	Long() string
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

func (bo baseOption) Long() string {
	return ""
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

func (oFrag *OptionFragment) Long() string {
	if oFrag.invert {
		return "! --fragment"
	}
	return "--fragment"
}

type OptionSetCounters struct {
	baseOption
	packets uint64
	bytes   uint64
}

func (oCounters *OptionSetCounters) Short() string {
	return fmt.Sprintf("-c %d %d", oCounters.packets, oCounters.bytes)
}

func (oCounters *OptionSetCounters) Long() string {
	return fmt.Sprintf("--set-counters %d %d", oCounters.packets, oCounters.bytes)
}

type OptionVerbose struct {
	baseOption
}

func (oVerbose *OptionVerbose) Short() string {
	return "-v"
}

func (oVerbose *OptionVerbose) Long() string {
	return "--verbose"
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

func (oWait *OptionWait) Long() string {
	if oWait.seconds == 0 {
		// indefinitely
		return "--wait"
	}
	return fmt.Sprintf("--wait %d", oWait.seconds)
}

type OptionWaitInterval struct {
	baseOption
	microseconds uint64
}

func (oWaitInterval *OptionWaitInterval) Short() string {
	return fmt.Sprintf("-W %d", oWaitInterval.microseconds)
}

func (oWaitInterval *OptionWaitInterval) Long() string {
	return fmt.Sprintf("--wait-interval %d", oWaitInterval.microseconds)
}

type OptionNumeric struct {
	baseOption
}

func (oNumeric *OptionNumeric) Short() string {
	return "-n"
}

func (oNumeric *OptionNumeric) Long() string {
	return "-n"
}

type OptionExact struct {
	baseOption
}

func (oExact *OptionExact) Short() string {
	return "-x"
}

func (oExact *OptionExact) Long() string {
	return "--exact"
}

type OptionLineNumbers struct {
	baseOption
}

func (oLineNumbers *OptionLineNumbers) Short() string {
	return "--line-numbers"
}

func (oLineNumbers *OptionLineNumbers) Long() string {
	return "--line-numbers"
}

type OptionModprobe struct {
	baseOption
	command string
}

func (oModprobe *OptionModprobe) Short() string {
	return fmt.Sprintf("--modprobe=%s", oModprobe.command)
}

func (oModprobe *OptionModprobe) Long() string {
	return fmt.Sprintf("--modprobe=%s", oModprobe.command)
}
