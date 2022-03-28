package iptables

type TargetType int

const (
	TargetAccept TargetType = iota
	TargetDrop
	TargetReturn
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
	Short() string
	Long() string
}

type baseTarget struct {
	targetType TargetType
}

func (bt baseTarget) Type() TargetType {
	return bt.targetType
}

func (bt baseTarget) Short() string {
	return ""
}

func (bt baseTarget) Long() string {
	return ""
}
