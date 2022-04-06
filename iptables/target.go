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
	TargetTypeUnknown TargetType = iota
	TargetTypeAccept
	TargetTypeDrop
	TargetTypeReturn
	TargetTypeJumpChain // jump chain
	TargetTypeGotoChain // goto chain
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
	TargetTypeSecMark
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
		TargetTypeAccept:      "ACCEPT",
		TargetTypeDrop:        "DROP",
		TargetTypeReturn:      "RETURN",
		TargetTypeAudit:       "AUDIT",
		TargetTypeCheckSum:    "CHECKSUM",
		TargetTypeClassify:    "CLASSIFY",
		TargetTypeClusterIP:   "CLUSTERIP",
		TargetTypeConnMark:    "CONNMARK",
		TargetTypeConnSecMark: "CONNSECMARK",
		TargetTypeCT:          "CT",
		TargetTypeDNAT:        "DNAT",
		TargetTypeDNPT:        "DNPT",
		TargetTypeDSCP:        "DSCP",
		TargetTypeECN:         "ECN",
		TargetTypeHL:          "HL",
		TargetTypeHMark:       "HMARK",
		TargetTypeIdleTimer:   "IDLETIMER",
		TargetTypeLED:         "LED",
		TargetTypeLog:         "LOG",
		TargetTypeMark:        "MARK",
		TargetTypeMasquerade:  "MASQUDERDE",
		TargetTypeMirror:      "MIRROR",
		TargetTypeNetMap:      "NETMAP",
		TargetTypeNFLog:       "NFLOG",
		TargetTypeNFQueue:     "NFQUEUE",
		TargetTypeNoTrack:     "NOTRACK",
		TargetTypeRateExt:     "RATEEXT",
		TargetTypeRedirect:    "REDIRECT",
		TargetTypeReject:      "REJECT",
		TargetTypeSame:        "SECMARK",
		TargetTypeSet:         "SET",
		TargetTypeSNAT:        "SNAT",
		TargetTypeSNPT:        "SNPT",
		TargetTypeSyncProxy:   "SYNCPROXY",
		TargetTypeTCPMSS:      "TCPMSS",
		TargetTypeTCPOptStrip: "TCPOPTSTRIP",
		TargetTypeTEE:         "TEE",
		TargetTypeTOS:         "TOS",
		TargetTypeTPROXY:      "TPROXY",
		TargetTypeTRACE:       "TRACE",
		TargetTypeTTL:         "TTL",
		TargetTypeULog:        "ULOG",
	}

	TargetValueType = map[string]TargetType{
		"ACCEPT":      TargetTypeAccept,
		"DROP":        TargetTypeDrop,
		"RETURN":      TargetTypeReturn,
		"AUDIT":       TargetTypeAudit,
		"CHECKSUM":    TargetTypeCheckSum,
		"CLASSIFY":    TargetTypeClassify,
		"CLUSTERIP":   TargetTypeClusterIP,
		"CONNMARK":    TargetTypeConnMark,
		"CONNSECMARK": TargetTypeConnSecMark,
		"CT":          TargetTypeCT,
		"DNAT":        TargetTypeDNAT,
		"DNPT":        TargetTypeDNPT,
		"DSCP":        TargetTypeDSCP,
		"ECN":         TargetTypeECN,
		"HL":          TargetTypeHL,
		"HMARK":       TargetTypeHMark,
		"IDLETIMER":   TargetTypeIdleTimer,
		"LED":         TargetTypeLED,
		"LOG":         TargetTypeLog,
		"MARK":        TargetTypeMark,
		"MASQUDERDE":  TargetTypeMasquerade,
		"MIRROR":      TargetTypeMirror,
		"NETMAP":      TargetTypeNetMap,
		"NFLOG":       TargetTypeNFLog,
		"NFQUEUE":     TargetTypeNFQueue,
		"NOTRACK":     TargetTypeNoTrack,
		"RATEEXT":     TargetTypeRateExt,
		"REDIRECT":    TargetTypeRedirect,
		"REJECT":      TargetTypeReject,
		"SECMARK":     TargetTypeSame,
		"SET":         TargetTypeSet,
		"SNAT":        TargetTypeSNAT,
		"SNPT":        TargetTypeSNPT,
		"SYNCPROXY":   TargetTypeSyncProxy,
		"TCPMSS":      TargetTypeTCPMSS,
		"TCPOPTSTRIP": TargetTypeTCPOptStrip,
		"TEE":         TargetTypeTEE,
		"TOS":         TargetTypeTOS,
		"TPROXY":      TargetTypeTPROXY,
		"TRACE":       TargetTypeTRACE,
		"TTL":         TargetTypeTTL,
		"ULOG":        TargetTypeULog,
	}
)

type Target interface {
	Type() TargetType
	String() string
	Args() []string
}

func NewTarget(targetType TargetType, args ...interface{}) (Target, error) {
	switch targetType {
	case TargetTypeUnknown:
		if len(args) != 1 {
			goto Err
		}
		name, ok := args[0].(string)
		if !ok {
			goto Err
		}
		return NewTargetUnknown(name), nil
	case TargetTypeJumpChain:
		if len(args) != 1 {
			goto Err
		}
		chain, ok := args[0].(string)
		if !ok {
			goto Err
		}
		return NewTargetJumpChain(chain)
	case TargetTypeGotoChain:
		if len(args) != 1 {
			goto Err
		}
		name, ok := args[0].(string)
		if !ok {
			goto Err
		}
		return NewTargetGotoChain(chain)
	}

Err:
	return nil, ErrArgs
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

type TargetUnknown struct {
	baseTarget
	unknown string
}

func NewTargetUnknown(unknown string) *TargetUnknown {
	return &TargetUnknown{
		baseTarget: baseTarget{
			tagetType: TargetTypeUnknown,
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

func NewTargetJumpChain(chain string) *TargetJumpChain {
	return &TargetJumpChain{
		baseTarget: baseTarget{
			targetType: TargetTypeJumpChain,
		},
		chain: chain,
	}
}

func (ta *TargetJumpChain) String() string {
	return fmt.Sprintf("-j %s", ta.chain)
}

func (ta *TargetJumpChain) Args() []string {
	return []string{"-j", ta.chain}
}

type TargetGotoChain struct {
	baseTarget
	chain string
}

func NewTargetGotoChain(chain string) *TargetGotoChain {
	return &TargetGotoChain{
		baseTarget: baseTarget{
			targetType: TargetTypeGotoChain,
		},
		chain: chain,
	}
}

func (ta *TargetGotoChain) String() string {
	return fmt.Sprintf("-g %s", ta.chain)
}

func (ta *TargetGotoChain) Args() []string {
	return []string{"-g", ta.chain}
}
