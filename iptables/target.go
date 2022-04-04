package iptables

import (
	"fmt"
	"strconv"
)

type TargetType int

func (tt TargetType) Type() string {
	return "TargetType"
}

func (tt TargetType) Value() string {
	return strconv.Itoa(int(tt))
}

const (
	_ = iota
	TargetTypeAccept
	TargetTypeDrop
	TargetTypeReturn
	TargetTypeJumpChain // jump chain
	TargetTypeGoto
	TargetTypeAudit
	TargetTypeCheckSum
	TargetTypeClassify
	TargetTypeClusterIP
	TargetTypeConnMark
	TargetTypeConnSecMark
	TargetTypeCT
	TargetTypeDNAT
	TargetTypeDNPT
	TargetTypeDSCP
	TargetTypeECN
	TargetTypeHL
	TargetTypeHMark
	TargetTypeIdleTimer
	TargetTypeLED
	TargetTypeLog
	TargetTypeMark
	TargetTypeMasquerade
	TargetTypeMirror
	TargetTypeNetMap
	TargetTypeNFLog
	TargetTypeNFQueue
	TargetTypeNoTrack
	TargetTypeRateExt
	TargetTypeRedirect
	TargetTypeReject
	TargetTypeSame
	TargetTypeSecMarkk
	TargetTypeSet
	TargetTypeSNAT
	TargetTypeSNPT
	TargetTypeSynProxy
	TargetTypeTCPMSS
	TargetTypeTCPOptStrip
	TargetTypeTEE
	TargetTypeTOS
	TargetTypeTProxy
	TargetTypeTrace
	TargetTypeTTL
	TargetTypeULog
)

var (
	TargetTypeValue = map[TargetType]string{
		TargetTypeAccept: "ACCEPT",
		TargetTypeDrop:   "DROP",
	}
)

var (
	TargetValueType = map[string]TargetType{}
)

type Target interface {
	Type() TargetType
	String() string
	Args() []string
}

type baseTarget struct {
	targetType TargetType
}

func (bt baseTarget) Type() TargetType {
	return bt.targetType
}

func (bt baseTarget) String() string {
	return ""
}

func (bt baseTarget) Args() []string {
	return nil
}

type TargetAccept struct {
	baseTarget
}

func (ta *TargetAccept) String() string {
	return "-j ACCEPT"
}

func (ta *TargetAccept) Args() []string {
	return []string{"-j", "ACCEPT"}
}

type TargetDrop struct {
	baseTarget
}

func (ta *TargetDrop) String() string {
	return "-j DROP"
}

func (ta *TargetDrop) Args() []string {
	return []string{"-j", "ACCEPT"}
}

type TargetReturn struct {
	baseTarget
}

func (ta *TargetReturn) String() string {
	return "-j RETURN"
}

func (ta *TargetReturn) Args() []string {
	return []string{"-j", "RETURN"}
}

type TargetJumpChain struct {
	baseTarget
	chain string
}

func (ta *TargetJumpChain) String() string {
	return fmt.Sprintf("-j %s", ta.chain)
}

func (ta *TargetJumpChain) Args() []string {
	return []string{"-j", ta.chain}
}
