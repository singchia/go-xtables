package iptables

import "fmt"

type TargetType int

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

type Target interface {
	Type() TargetType
	String() string
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

type TargetAccept struct {
	baseTarget
}

func (ta *TargetAccept) String() string {
	return "-j ACCEPT"
}

type TargetDrop struct {
	baseTarget
}

func (ta *TargetDrop) String() string {
	return "-j DROP"
}

type TargetReturn struct {
	baseTarget
}

func (ta *TargetReturn) String() string {
	return "-j RETURN"
}

type TargetJumpChain struct {
	baseTarget
	chain string
}

func (ta *TargetJumpChain) String() string {
	return fmt.Sprintf("-j %s", ta.chain)
}
