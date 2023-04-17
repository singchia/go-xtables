package iptables

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/singchia/go-xtables"
	"github.com/singchia/go-xtables/pkg/network"
)

type TargetType int

const (
	TargetTypeNull TargetType = iota
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
	TargetTypeMirror // unsupport
	TargetTypeNetmap
	TargetTypeNFLog
	TargetTypeNFQueue
	TargetTypeNoTrack // unsupport
	TargetTypeRateEst
	TargetTypeRedirect
	TargetTypeReject
	TargetTypeSame
	TargetTypeSecMark
	TargetTypeSet
	TargetTypeSNAT
	TargetTypeSNPT
	TargetTypeSYNProxy
	TargetTypeTCPMSS
	TargetTypeTCPOptStrip
	TargetTypeTEE
	TargetTypeTOS
	TargetTypeTProxy
	TargetTypeTrace
	TargetTypeTTL
	TargetTypeULog
	TargetTypeEmpty
)

var (
	targetTypeValue = map[TargetType]string{
		TargetTypeAccept:      "ACCEPT",
		TargetTypeDrop:        "DROP",
		TargetTypeReturn:      "RETURN",
		TargetTypeJumpChain:   "JUMP",
		TargetTypeGotoChain:   "GOTO",
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
		TargetTypeNetmap:      "NETMAP",
		TargetTypeNFLog:       "NFLOG",
		TargetTypeNFQueue:     "NFQUEUE",
		//TargetTypeNoTrack:     "NOTRACK",
		TargetTypeRateEst:     "RATEEST",
		TargetTypeRedirect:    "REDIRECT",
		TargetTypeReject:      "REJECT",
		TargetTypeSame:        "SECMARK",
		TargetTypeSet:         "SET",
		TargetTypeSNAT:        "SNAT",
		TargetTypeSNPT:        "SNPT",
		TargetTypeSYNProxy:    "SYNCPROXY",
		TargetTypeTCPMSS:      "TCPMSS",
		TargetTypeTCPOptStrip: "TCPOPTSTRIP",
		TargetTypeTEE:         "TEE",
		TargetTypeTOS:         "TOS",
		TargetTypeTProxy:      "TPROXY",
		TargetTypeTrace:       "TRACE",
		TargetTypeTTL:         "TTL",
		TargetTypeULog:        "ULOG",
	}

	targetValueType = map[string]TargetType{
		"ACCEPT":      TargetTypeAccept,
		"DROP":        TargetTypeDrop,
		"RETURN":      TargetTypeReturn,
		"JUMP":        TargetTypeJumpChain,
		"GOTO":        TargetTypeGotoChain,
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
		"NETMAP":      TargetTypeNetmap,
		"NFLOG":       TargetTypeNFLog,
		"NFQUEUE":     TargetTypeNFQueue,
		//"NOTRACK":     TargetTypeNoTrack,
		"RATEEST":     TargetTypeRateEst,
		"REDIRECT":    TargetTypeRedirect,
		"REJECT":      TargetTypeReject,
		"SECMARK":     TargetTypeSame,
		"SET":         TargetTypeSet,
		"SNAT":        TargetTypeSNAT,
		"SNPT":        TargetTypeSNPT,
		"SYNCPROXY":   TargetTypeSYNProxy,
		"TCPMSS":      TargetTypeTCPMSS,
		"TCPOPTSTRIP": TargetTypeTCPOptStrip,
		"TEE":         TargetTypeTEE,
		"TOS":         TargetTypeTOS,
		"TPROXY":      TargetTypeTProxy,
		"TRACE":       TargetTypeTrace,
		"TTL":         TargetTypeTTL,
		"ULOG":        TargetTypeULog,
	}
)

func (tt TargetType) Type() string {
	return "TargetType"
}

func (tt TargetType) Value() string {
	return strconv.Itoa(int(tt))
}

func (tt TargetType) String() string {
	switch tt {
	case TargetTypeAccept:
		return "ACCEPT"
	case TargetTypeDrop:
		return "DROP"
	case TargetTypeReturn:
		return "RETURN"
	case TargetTypeAudit:
		return "AUDIT"
	case TargetTypeCheckSum:
		return "CHECKSUM"
	case TargetTypeClassify:
		return "CLASSIFY"
	case TargetTypeClusterIP:
		return "CLUSTERIP"
	case TargetTypeConnMark:
		return "CONNMARK"
	case TargetTypeConnSecMark:
		return "CONNSECMARK"
	case TargetTypeCT:
		return "CT"
	case TargetTypeDNAT:
		return "DNAT"
	case TargetTypeDNPT:
		return "DNPT"
	case TargetTypeDSCP:
		return "DSCP"
	case TargetTypeECN:
		return "ECN"
	case TargetTypeHL:
		return "HL"
	case TargetTypeHMark:
		return "HMARK"
	case TargetTypeIdleTimer:
		return "IDLETIMER"
	case TargetTypeLED:
		return "LED"
	case TargetTypeLog:
		return "LOG"
	case TargetTypeMark:
		return "MARK"
	case TargetTypeMasquerade:
		return "MASQUDERDE"
	case TargetTypeNetmap:
		return "NETMAP"
	case TargetTypeNFLog:
		return "NFLOG"
	case TargetTypeNFQueue:
		return "NFQUEUE"
	case TargetTypeRateEst:
		return "RATEEST"
	case TargetTypeRedirect:
		return "REDIRECT"
	case TargetTypeReject:
		return "REJECT"
	case TargetTypeSame:
		return "SAME"
	case TargetTypeSecMark:
		return "SECMARK"
	case TargetTypeSet:
		return "SET"
	case TargetTypeSNAT:
		return "SNAT"
	case TargetTypeSNPT:
		return "SNPT"
	case TargetTypeSYNProxy:
		return "SYNPROXY"
	case TargetTypeTCPMSS:
		return "TCPMSS"
	case TargetTypeTCPOptStrip:
		return "TCPOPTSTRIP"
	case TargetTypeTEE:
		return "TEE"
	case TargetTypeTOS:
		return "TOS"
	case TargetTypeTProxy:
		return "TPROXY"
	case TargetTypeTrace:
		return "TRACE"
	case TargetTypeTTL:
		return "TTL"
	case TargetTypeULog:
		return "ULOG"
	default:
		return ""
	}
}

type Target interface {
	Type() TargetType
	Short() string
	Long() string
	ShortArgs() []string
	LongArgs() []string
	Parse([]byte) (int, bool)
	Equal(Target) bool
}

func targetFactory(targetType TargetType, args ...interface{}) (Target, error) {
	switch targetType {
	case TargetTypeNull:
		if len(args) != 1 {
			goto Err
		}
		name, ok := args[0].(string)
		if !ok {
			goto Err
		}
		return newTargetUnknown(name), nil
	case TargetTypeAccept:
		return newTargetAccept(), nil
	case TargetTypeDrop:
		return newTargetDrop(), nil
	case TargetTypeReturn:
		return newTargetReturn(), nil
	case TargetTypeJumpChain:
		if len(args) != 1 {
			goto Err
		}
		chain, ok := args[0].(string)
		if !ok {
			goto Err
		}
		return newTargetJumpChain(chain), nil
	case TargetTypeGotoChain:
		if len(args) != 1 {
			goto Err
		}
		chain, ok := args[0].(string)
		if !ok {
			goto Err
		}
		return newTargetGotoChain(chain), nil
	case TargetTypeAudit:
		return newTargetAudit(-1)
	case TargetTypeCheckSum:
		return newTargetCheckSum()
	case TargetTypeClassify:
		return newTargetClassify(-1, -1)
	case TargetTypeClusterIP:
		return newTargetClusterIP()
	case TargetTypeConnMark:
		return newTargetConnMark()
	case TargetTypeConnSecMark:
		return newTargetConnSecMark(-1)
	case TargetTypeCT:
		return newTargetCT()
	case TargetTypeDNAT:
		return newTargetDNAT()
	case TargetTypeDNPT:
		return newTargetDNPT()
	case TargetTypeDSCP:
		return newTargetDSCP()
	case TargetTypeECN:
		return newTargetECN()
	case TargetTypeHL:
		return newTargetHL()
	case TargetTypeHMark:
		return newTargetHMark()
	case TargetTypeIdleTimer:
		return newTargetIdleTimer()
	case TargetTypeLED:
		return newTargetLED()
	case TargetTypeLog:
		return newTargetLog()
	case TargetTypeMark:
		return newTargetMark()
	case TargetTypeMasquerade:
		return newTargetMasquerade()
	case TargetTypeNetmap:
		return newTargetNetmap()
	case TargetTypeNFLog:
		return newTargetNFLog()
	case TargetTypeNFQueue:
		return newTargetNFQueue()
	case TargetTypeRateEst:
		return newTargetRateEst()
	case TargetTypeRedirect:
		return newTargetRedirect()
	case TargetTypeReject:
		return newTargetReject()
	case TargetTypeSame:
		return newTargetSame()
	case TargetTypeSecMark:
		return newTargetSecMark()
	case TargetTypeSet:
		return newTargetSet()
	case TargetTypeSNAT:
		return newTargetSNAT()
	case TargetTypeSNPT:
		return newTargetSNPT()
	case TargetTypeSYNProxy:
		return newTargetSYNProxy()
	case TargetTypeTCPMSS:
		return newTargetTCPMSS()
	case TargetTypeTCPOptStrip:
		return newTargetTCPOptStrip()
	case TargetTypeTEE:
		return newTargetTEE(nil)
	case TargetTypeTOS:
		return newTargetTOS()
	case TargetTypeTProxy:
		return newTargetTProxy()
	case TargetTypeTrace:
		return newTargetTrace()
	case TargetTypeTTL:
		return newTargetTTL()
	case TargetTypeULog:
		return newTargetULog()
	default:
		return newTargetEmpty()
	}

Err:
	return nil, xtables.ErrArgs
}

type baseTarget struct {
	targetType TargetType
	child      Target
}

func (bt *baseTarget) setChild(child Target) {
	bt.child = child
}
func (bt *baseTarget) Type() TargetType {
	return bt.targetType
}

func (bt *baseTarget) Short() string {
	if bt.child != nil {
		return bt.child.Short()
	}
	return ""
}

func (bt *baseTarget) ShortArgs() []string {
	if bt.child != nil {
		return bt.child.ShortArgs()
	}
	return nil
}

func (bt *baseTarget) Long() string {
	return bt.Short()
}

func (bt *baseTarget) LongArgs() []string {
	return bt.ShortArgs()
}

func (bt *baseTarget) Parse([]byte) (int, bool) {
	return 0, true
}

func (bt *baseTarget) Equal(tgt Target) bool {
	return bt.Short() == tgt.Short()
}

type TargetEmpty struct {
	*baseTarget
}

func newTargetEmpty() (*TargetEmpty, error) {
	return &TargetEmpty{
		baseTarget: &baseTarget{
			targetType: TargetTypeEmpty,
		},
	}, nil
}

type TargetUnknown struct {
	*baseTarget
	unknown string
}

func newTargetUnknown(unknown string) *TargetUnknown {
	return &TargetUnknown{
		baseTarget: &baseTarget{
			targetType: TargetTypeNull,
		},
		unknown: unknown,
	}
}

func (tu *TargetUnknown) Unknown() string {
	return tu.unknown
}

type TargetAccept struct {
	*baseTarget
}

func newTargetAccept() *TargetAccept {
	target := &TargetAccept{
		baseTarget: &baseTarget{
			targetType: TargetTypeAccept,
		},
	}
	target.setChild(target)
	return target
}

func (ta *TargetAccept) Short() string {
	return "-j ACCEPT"
}

func (ta *TargetAccept) ShortArgs() []string {
	return []string{"-j", "ACCEPT"}
}

func (ta *TargetAccept) Long() string {
	return ta.Short()
}

func (ta *TargetAccept) LongArgs() []string {
	return ta.ShortArgs()
}

type TargetDrop struct {
	*baseTarget
}

func newTargetDrop() *TargetDrop {
	target := &TargetDrop{
		baseTarget: &baseTarget{
			targetType: TargetTypeDrop,
		},
	}
	target.setChild(target)
	return target
}

func (ta *TargetDrop) Short() string {
	return "-j DROP"
}

func (ta *TargetDrop) ShortArgs() []string {
	return []string{"-j", "ACCEPT"}
}

func (ta *TargetDrop) Long() string {
	return ta.Short()
}

func (ta *TargetDrop) LongArgs() []string {
	return ta.ShortArgs()
}

type TargetReturn struct {
	*baseTarget
}

func newTargetReturn() *TargetReturn {
	target := &TargetReturn{
		baseTarget: &baseTarget{
			targetType: TargetTypeReturn,
		},
	}
	target.setChild(target)
	return target
}

func (ta *TargetReturn) Short() string {
	return "-j RETURN"
}

func (ta *TargetReturn) ShortArgs() []string {
	return []string{"-j", "RETURN"}
}

func (ta *TargetReturn) Long() string {
	return ta.Short()
}

func (ta *TargetReturn) LongArgs() []string {
	return ta.ShortArgs()
}

type TargetJumpChain struct {
	*baseTarget
	chain string
}

func newTargetJumpChain(chain string) *TargetJumpChain {
	target := &TargetJumpChain{
		baseTarget: &baseTarget{
			targetType: TargetTypeJumpChain,
		},
		chain: chain,
	}
	target.setChild(target)
	return target
}

func (ta *TargetJumpChain) Short() string {
	return fmt.Sprintf("-j %s", ta.chain)
}

func (ta *TargetJumpChain) ShortArgs() []string {
	return []string{"-j", ta.chain}
}

func (ta *TargetJumpChain) Long() string {
	return ta.Short()
}

func (ta *TargetJumpChain) LongArgs() []string {
	return ta.ShortArgs()
}

type TargetGotoChain struct {
	*baseTarget
	chain string
}

func newTargetGotoChain(chain string) *TargetGotoChain {
	target := &TargetGotoChain{
		baseTarget: &baseTarget{
			targetType: TargetTypeGotoChain,
		},
		chain: chain,
	}
	target.setChild(target)
	return target
}

func (ta *TargetGotoChain) Short() string {
	return fmt.Sprintf("-g %s", ta.chain)
}

func (ta *TargetGotoChain) ShortArgs() []string {
	return []string{"-g", ta.chain}
}

func (ta *TargetGotoChain) Long() string {
	return ta.Short()
}

func (ta *TargetGotoChain) LongArgs() []string {
	return ta.ShortArgs()
}

type AuditType int8

func (auditType AuditType) String() string {
	switch auditType {
	case AuditAccept:
		return "accetp"
	case AuditDrop:
		return "drop"
	case AuditReject:
		return "reject"
	default:
		return ""
	}
}

const (
	_ AuditType = iota
	AuditAccept
	AuditDrop
	AuditReject
)

// Set type of audit record.
func newTargetAudit(typ AuditType) (*TargetAudit, error) {
	target := &TargetAudit{
		baseTarget: &baseTarget{
			targetType: TargetTypeAudit,
		},
		AuditType: typ,
	}
	target.setChild(target)
	return target, nil
}

type TargetAudit struct {
	*baseTarget
	AuditType AuditType
}

func (tAudit *TargetAudit) Short() string {
	return strings.Join(tAudit.ShortArgs(), " ")
}

func (tAudit *TargetAudit) ShortArgs() []string {
	args := make([]string, 0, 4)
	args = append(args, "-j", tAudit.targetType.String())
	args = append(args, "--type", tAudit.AuditType.String())
	return args
}

func (tAudit *TargetAudit) Long() string {
	return tAudit.Short()
}

func (tAudit *TargetAudit) LongArgs() []string {
	return tAudit.ShortArgs()
}

func (tAudit *TargetAudit) Parse(main []byte) (int, bool) {
	// 1. "^AUDIT "
	// 2. "(accept|drop|reject)?"
	pattern := `^AUDIT (accept|drop|reject)?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 2 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		switch string(matches[1]) {
		case "accept":
			tAudit.AuditType = AuditAccept
		case "drop":
			tAudit.AuditType = AuditDrop
		case "reject":
			tAudit.AuditType = AuditReject
		}
	}
	return len(matches[0]), true
}

// This target allows to selectively work around broken/old applications.
// Compute and fill in the checksum in a packet that lacks a checksum.
func newTargetCheckSum() (*TargetChecksum, error) {
	target := &TargetChecksum{
		baseTarget: &baseTarget{
			targetType: TargetTypeCheckSum,
		},
		Fill: true,
	}
	target.setChild(target)
	return target, nil
}

type TargetChecksum struct {
	*baseTarget
	Fill bool
}

func (tChecksum *TargetChecksum) Short() string {
	return strings.Join(tChecksum.ShortArgs(), " ")
}

func (tChecksum *TargetChecksum) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-j", tChecksum.targetType.String())
	args = append(args, "--checksum-fill")
	return args
}

func (tChecksum *TargetChecksum) Long() string {
	return tChecksum.Short()
}

func (tChecksum *TargetChecksum) LongArgs() []string {
	return tChecksum.ShortArgs()
}

func (tChecksum *TargetChecksum) Parse(main []byte) (int, bool) {
	pattern := `^CHECKSUM( fill)?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 2 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		tChecksum.Fill = true
	}
	return len(matches[0]), true
}

// This option takes major and minor of class value
func newTargetClassify(major, minor int) (*TargetClassify, error) {
	target := &TargetClassify{
		baseTarget: &baseTarget{
			targetType: TargetTypeClassify,
		},
		Major: major,
		Minor: minor,
	}
	target.setChild(target)
	return target, nil
}

type TargetClassify struct {
	*baseTarget
	Major int
	Minor int
}

func (tClassify *TargetClassify) Short() string {
	return strings.Join(tClassify.ShortArgs(), " ")
}

func (tClassify *TargetClassify) ShortArgs() []string {
	args := make([]string, 0, 4)
	args = append(args, "-j", tClassify.targetType.String())
	args = append(args, "--set-class",
		strconv.Itoa(tClassify.Minor)+":"+strconv.Itoa(tClassify.Major))
	return args
}

func (tClassify *TargetClassify) Long() string {
	return tClassify.Short()
}

func (tClassify *TargetClassify) LongArgs() []string {
	return tClassify.ShortArgs()
}

func (tClassify *TargetClassify) Parse(main []byte) (int, bool) {
	// 1. "^CLASSIFY set"
	// 2. " ([0-9A-Za-z]+):([0-9A-Za-z]+)"
	pattern := `^CLASSIFY set` +
		` ([0-9A-Za-z]+):([0-9A-Za-z]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	major, err := strconv.ParseInt(string(matches[1]), 16, 32)
	if err != nil {
		return 0, false
	}
	minor, err := strconv.ParseInt(string(matches[2]), 16, 32)
	if err != nil {
		return 0, false
	}
	tClassify.Major = int(major)
	tClassify.Minor = int(minor)
	return len(matches[0]), true
}

type ClusterIPHashMode int8

func (clusterIPHashMode ClusterIPHashMode) String() string {
	switch clusterIPHashMode {
	case ClusterIPHashModeSrcIP:
		return "sourceip"
	case ClusterIPHashModeSrcIPSrcPort:
		return "sourceip-sourceport"
	case ClusterIPHashModeSrcIPSrcPortDstPort:
		return "sourceip-sourceport-destport"
	default:
		return ""
	}
}

const (
	_ ClusterIPHashMode = iota
	ClusterIPHashModeSrcIP
	ClusterIPHashModeSrcIPSrcPort
	ClusterIPHashModeSrcIPSrcPortDstPort
)

type OptionTargetClusterIP func(*TargetClusterIP)

// Create a new ClusterIP.
func WithTargetClusterIPNew() OptionTargetClusterIP {
	return func(tClusterIP *TargetClusterIP) {
		tClusterIP.New = true
	}
}

// Specify the hashing mode.
func WithTargetClusterIPHashMode(mode ClusterIPHashMode) OptionTargetClusterIP {
	return func(tClusterIP *TargetClusterIP) {
		tClusterIP.HashMode = mode
	}
}

// Specify the ClusterIP MAC address.
func WithTargetClusterIPMac(mac net.HardwareAddr) OptionTargetClusterIP {
	return func(tClusterIP *TargetClusterIP) {
		tClusterIP.Mac = mac
	}
}

// Number of total nodes within this cluster.
func WithTargetClusterIPTotalNodes(totalNodes int) OptionTargetClusterIP {
	return func(tClusterIP *TargetClusterIP) {
		tClusterIP.TotalNodes = totalNodes
	}
}

// Local node number within this cluster.
func WithTargetClusterIPLocalNode(localNode int) OptionTargetClusterIP {
	return func(tClusterIP *TargetClusterIP) {
		tClusterIP.LocalNode = localNode
	}
}

// Specify the random seed used for hash initialization.
func WithTargetClusterIPHashInit(hashInit int) OptionTargetClusterIP {
	return func(tClusterIP *TargetClusterIP) {
		tClusterIP.HashInit = hashInit
	}
}

func newTargetClusterIP(opts ...OptionTargetClusterIP) (*TargetClusterIP, error) {
	target := &TargetClusterIP{
		baseTarget: &baseTarget{
			targetType: TargetTypeClusterIP,
		},
		HashMode:   -1,
		TotalNodes: -1,
		LocalNode:  -1,
		HashInit:   -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

// IPv4 specific
type TargetClusterIP struct {
	*baseTarget
	New        bool
	HashMode   ClusterIPHashMode
	Mac        net.HardwareAddr
	TotalNodes int
	LocalNode  int
	HashInit   int // randon seed
}

func (tClusterIP *TargetClusterIP) Short() string {
	return strings.Join(tClusterIP.ShortArgs(), " ")
}

func (tClusterIP *TargetClusterIP) ShortArgs() []string {
	args := make([]string, 0, 13)
	args = append(args, "-j", tClusterIP.targetType.String())
	if tClusterIP.New {
		args = append(args, "--new")
	}
	if tClusterIP.HashMode > -1 {
		args = append(args, "--hashmode", tClusterIP.HashMode.String())
	}
	if tClusterIP.Mac != nil {
		args = append(args, "--clustermac", tClusterIP.Mac.String())
	}
	if tClusterIP.TotalNodes > -1 {
		args = append(args, "--total-nodes",
			strconv.Itoa(tClusterIP.TotalNodes))
	}
	if tClusterIP.LocalNode > -1 {
		args = append(args, "--local-node",
			strconv.Itoa(tClusterIP.LocalNode))
	}
	if tClusterIP.HashInit > -1 {
		args = append(args, "--hash-init",
			strconv.Itoa(tClusterIP.HashInit))
	}
	return args
}

func (tClusterIP *TargetClusterIP) Long() string {
	return tClusterIP.Short()
}

func (tClusterIP *TargetClusterIP) LongArgs() []string {
	return tClusterIP.ShortArgs()
}

func (tClusterIP *TargetClusterIP) Parse(main []byte) (int, bool) {
	pattern := `^CLUSTERIP` +
		`( hashmode=([0-9A-Za-z-_.]+)` +
		` clustermac=([0-9A-Za-z-_.:]+)` +
		` total_nodes=([0-9]+)` +
		` local_node=([0-9]+)` +
		` hash_init=([0-9]+))?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 7 {
		return 0, false
	}
	if len(matches[1]) == 0 {
		tClusterIP.New = true
		return len(matches[0]), true
	}
	if len(matches[2]) != 0 {
		switch string(matches[2]) {
		case "sourceip":
			tClusterIP.HashMode = ClusterIPHashModeSrcIP
		case "sourceip-sourceport":
			tClusterIP.HashMode = ClusterIPHashModeSrcIPSrcPort
		case "sourceip-sourceport-destport":
			tClusterIP.HashMode = ClusterIPHashModeSrcIPSrcPortDstPort
		}
	}
	if len(matches[3]) != 0 {
		mac, err := net.ParseMAC(string(matches[3]))
		if err != nil {
			return 0, false
		}
		tClusterIP.Mac = mac
	}
	if len(matches[4]) != 0 {
		totalNodes, err := strconv.Atoi(string(matches[4]))
		if err != nil {
			return 0, false
		}
		tClusterIP.TotalNodes = totalNodes
	}
	if len(matches[5]) != 0 {
		localNode, err := strconv.Atoi(string(matches[5]))
		if err != nil {
			return 0, false
		}
		tClusterIP.LocalNode = localNode
	}
	if len(matches[6]) != 0 {
		hashInit, err := strconv.Atoi(string(matches[6]))
		if err != nil {
			return 0, false
		}
		tClusterIP.HashInit = hashInit
	}
	return len(matches[0]), true
}

type TargetConnMarkMode int8

const (
	_ TargetConnMarkMode = iota
	TargetConnMarkModeAND
	TargetConnMarkModeOR
	TargetConnMarkModeXOR
	TargetConnMarkModeSET
	TargetConnMarkModeXSET
	TargetConnMarkModeSAVE
	TargetConnMarkModeRESTORE
)

type OptionTargetConnMark func(*TargetConnMark)

// This option takes mostly 2 value, (value) or (value, mask)
// Zero out the bits given by mask and XOR value into the ctmark.
func WithTargetConnMarkSetXMark(mark ...int) OptionTargetConnMark {
	return func(tConnMark *TargetConnMark) {
		switch len(mark) {
		case 1:
			tConnMark.CTMark = mark[0]
		case 2:
			tConnMark.CTMark = mark[0]
			tConnMark.CTMask = mark[1]
		}
		tConnMark.Mode = TargetConnMarkModeXSET
	}
}

// Set the connection mark. If a mask is specified then only those bits set in the mask are modified.
func WithTargetConnMarkSetMark(mark ...int) OptionTargetConnMark {
	return func(tConnMark *TargetConnMark) {
		switch len(mark) {
		case 1:
			tConnMark.CTMark = mark[0]
		case 2:
			tConnMark.CTMark = mark[0]
			tConnMark.CTMask = mark[1]
		}
		tConnMark.Mode = TargetConnMarkModeSET
	}
}

// Copy the packet mark (nfmark) to the connection mark (ctmark) using the given masks.
// The new nfmark value is determined as follows:
// ctmark = (ctmark & ~ctmask) ^ (nfmark & nfmask)
func WithTargetConnMarkSaveMark(mask ...int) OptionTargetConnMark {
	return func(tConnMark *TargetConnMark) {
		switch len(mask) {
		case 1:
			tConnMark.CTMask = mask[0]
		case 2:
			tConnMark.CTMask = mask[0]
			tConnMark.NFMask = mask[1]
		}
		tConnMark.Mode = TargetConnMarkModeSAVE
	}
}

// Copy the connection mark (ctmark) to the packet mark (nfmark) using the given masks.
// The new ctmark value is determined as follows:
// nfmark = (nfmark & ~nfmask) ^ (ctmark & ctmask)
func WithTargetConnMarkRestore(mask ...int) OptionTargetConnMark {
	return func(tConnMark *TargetConnMark) {
		switch len(mask) {
		case 1:
			tConnMark.CTMask = mask[0]
		case 2:
			tConnMark.CTMask = mask[0]
			tConnMark.NFMask = mask[1]
		}
		tConnMark.Mode = TargetConnMarkModeRESTORE
	}
}

// Binary AND the ctmark with bits.
func WithTargetConnMarkAnd(mark int) OptionTargetConnMark {
	return func(tConnMark *TargetConnMark) {
		tConnMark.CTMark = mark
		tConnMark.Mode = TargetConnMarkModeAND
	}
}

// Binary OR the ctmark with bits.
func WithTargetConnMarkOr(mark int) OptionTargetConnMark {
	return func(tConnMark *TargetConnMark) {
		tConnMark.CTMark = mark
		tConnMark.Mode = TargetConnMarkModeOR
	}
}

// Binary XOR the ctmark with bits.
func WithTargetConnMarkXor(mark int) OptionTargetConnMark {
	return func(tConnMark *TargetConnMark) {
		tConnMark.CTMark = mark
		tConnMark.Mode = TargetConnMarkModeXOR
	}
}

func newTargetConnMark(opts ...OptionTargetConnMark) (*TargetConnMark, error) {
	target := &TargetConnMark{
		baseTarget: &baseTarget{
			targetType: TargetTypeConnMark,
		},
		Mode:   -1,
		CTMark: -1,
		CTMask: -1,
		NFMask: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetConnMark struct {
	*baseTarget
	Mode   TargetConnMarkMode
	CTMark int
	CTMask int
	NFMask int
}

func (tConnMark *TargetConnMark) Short() string {
	return strings.Join(tConnMark.ShortArgs(), " ")
}

func (tConnMark *TargetConnMark) ShortArgs() []string {
	args := make([]string, 0, 8)
	args = append(args, "-j", tConnMark.targetType.String())
	switch tConnMark.Mode {
	case TargetConnMarkModeXSET:
		if tConnMark.CTMask > -1 {
			args = append(args, "--set-xmark",
				strconv.Itoa(tConnMark.CTMark)+"/"+strconv.Itoa(tConnMark.CTMask))
		} else {
			args = append(args, "--set-xmark", strconv.Itoa(tConnMark.CTMark))
		}
	case TargetConnMarkModeSAVE:
		args = append(args, "--save-mark")
		if tConnMark.NFMask > -1 && tConnMark.CTMask > -1 {
			args = append(args, "--nfmask", strconv.Itoa(tConnMark.NFMask))
			args = append(args, "--ctmask", strconv.Itoa(tConnMark.CTMask))
		} else if tConnMark.CTMask > -1 {
			args = append(args, "--mask", strconv.Itoa(tConnMark.CTMask))
		}
	case TargetConnMarkModeRESTORE:
		args = append(args, "--restore-mark")
		if tConnMark.NFMask > -1 && tConnMark.CTMask > -1 {
			args = append(args, "--nfmask", strconv.Itoa(tConnMark.NFMask))
			args = append(args, "--ctmask", strconv.Itoa(tConnMark.CTMask))
		} else if tConnMark.CTMask > -1 {
			args = append(args, "--mask", strconv.Itoa(tConnMark.CTMask))
		}
	case TargetConnMarkModeAND:
		args = append(args, "--and-mark", strconv.Itoa(tConnMark.CTMark))
	case TargetConnMarkModeOR:
		args = append(args, "--or-mark", strconv.Itoa(tConnMark.CTMark))
	case TargetConnMarkModeXOR:
		args = append(args, "--xor-mark", strconv.Itoa(tConnMark.CTMark))
	case TargetConnMarkModeSET:
		if tConnMark.CTMask > -1 {
			args = append(args, "--set-mark",
				strconv.Itoa(tConnMark.CTMark)+"/"+strconv.Itoa(tConnMark.CTMask))
		} else {
			args = append(args, "--set-mark", strconv.Itoa(tConnMark.CTMark))
		}
	}
	return args
}

func (tConnMark *TargetConnMark) Long() string {
	return tConnMark.Short()
}

func (tConnMark *TargetConnMark) LongArgs() []string {
	return tConnMark.ShortArgs()
}

func (tConnMark *TargetConnMark) Parse(main []byte) (int, bool) {
	// 1. "^CONNMARK "
	// 2. "( and 0x([0-9A-Za-z]+))?" and ctmark #1 #2
	// 3. "( or 0x([0-9A-Za-z]+))?" or ctmark #3 #4
	// 4. "( xor 0x([0-9A-Za-z]+))?" xor ctmark #5 #6
	// 5. "( set 0x([0-9A-Za-z]+))?" set ctmark #7 #8
	// 6. "( xset 0x([0-9A-Za-z]+)/0x([0-9A-Za-z]+))?" set ctmark #9 #10 #11
	// 7. "( save mask 0x([0-9A-Za-z]+))?" #12 #13
	// 8. "( save nfmask 0x([0-9A-Za-z]+) ctmask ~0x([0-9A-Za-z]+))?" #14 #15 #16
	// 9. "( save)?" #17
	// 10. "( restore mask 0x([0-9A-Za-z]+))?" #18 #19
	// 11. "( restore ctmask 0x([0-9A-Za-z]+) nfmask 0x([0-9A-Za-z]+))?" #20 #21 #22
	// 12. "( restore)?" #23
	pattern := `^CONNMARK` +
		`( and 0x([0-9A-Za-z]+))?` +
		`( or 0x([0-9A-Za-z]+))?` +
		`( xor 0x([0-9A-Za-z]+))?` +
		`( set 0x([0-9A-Za-z]+))?` +
		`( xset 0x([0-9A-Za-z]+)/0x([0-9A-Za-z]+))?` +
		`( save mask 0x([0-9A-Za-z]+))?` +
		`( save nfmask 0x([0-9A-Za-z]+) ctmask ~0x([0-9A-Za-z]+))?` +
		`( save)?` +
		`( restore mask 0x([0-9A-Za-z]+))?` +
		`( restore ctmask 0x([0-9A-Za-z]+) nfmask 0x([0-9A-Za-z]+))? *` +
		`( restore)?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 24 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		mark, err := strconv.ParseInt(string(matches[2]), 16, 64)
		if err != nil {
			return 0, false
		}
		tConnMark.CTMark = int(mark)
		tConnMark.Mode = TargetConnMarkModeAND
	}
	if len(matches[4]) != 0 {
		mark, err := strconv.ParseInt(string(matches[4]), 16, 64)
		if err != nil {
			return 0, false
		}
		tConnMark.CTMark = int(mark)
		tConnMark.Mode = TargetConnMarkModeOR
	}
	if len(matches[6]) != 0 {
		mark, err := strconv.ParseInt(string(matches[6]), 16, 64)
		if err != nil {
			return 0, false
		}
		tConnMark.CTMark = int(mark)
		tConnMark.Mode = TargetConnMarkModeXOR
	}
	if len(matches[8]) != 0 {
		mark, err := strconv.ParseInt(string(matches[8]), 16, 64)
		if err != nil {
			return 0, false
		}
		tConnMark.CTMark = int(mark)
		tConnMark.Mode = TargetConnMarkModeSET
	}
	if len(matches[10]) != 0 {
		mark, err := strconv.ParseInt(string(matches[10]), 16, 64)
		if err != nil {
			return 0, false
		}
		mask, err := strconv.ParseInt(string(matches[11]), 16, 64)
		if err != nil {
			return 0, false
		}
		tConnMark.CTMark = int(mark)
		tConnMark.CTMask = int(mask)
		tConnMark.Mode = TargetConnMarkModeXSET
	}
	// save
	if len(matches[13]) != 0 {
		mask, err := strconv.ParseInt(string(matches[13]), 16, 64)
		if err != nil {
			return 0, false
		}
		tConnMark.CTMask = int(mask)
		tConnMark.Mode = TargetConnMarkModeSAVE
	}
	if len(matches[15]) != 0 {
		nfmask, err := strconv.ParseInt(string(matches[15]), 16, 64)
		if err != nil {
			return 0, false
		}
		ctmask, err := strconv.ParseInt(string(matches[16]), 16, 64)
		if err != nil {
			return 0, false
		}
		tConnMark.CTMask = int(ctmask)
		tConnMark.NFMask = int(nfmask)
		tConnMark.Mode = TargetConnMarkModeSAVE
	}
	if len(matches[17]) != 0 {
		tConnMark.Mode = TargetConnMarkModeSAVE
	}
	// restore
	if len(matches[19]) != 0 {
		mask, err := strconv.ParseInt(string(matches[19]), 16, 64)
		if err != nil {
			return 0, false
		}
		tConnMark.CTMask = int(mask)
		tConnMark.Mode = TargetConnMarkModeRESTORE
	}
	if len(matches[21]) != 0 {
		ctmask, err := strconv.ParseInt(string(matches[21]), 16, 64)
		if err != nil {
			return 0, false
		}
		nfmask, err := strconv.ParseInt(string(matches[22]), 16, 64)
		if err != nil {
			return 0, false
		}
		tConnMark.CTMask = int(ctmask)
		tConnMark.CTMask = int(nfmask)
		tConnMark.Mode = TargetConnMarkModeRESTORE
	}
	if len(matches[23]) != 0 {
		tConnMark.Mode = TargetConnMarkModeRESTORE
	}
	return len(matches[0]), true
}

type TargetConnSecMarkMode int8

const (
	_ TargetConnSecMarkMode = iota
	TargetConnSecMarkModeSAVE
	TargetConnSecMarkModeRESTORE
)

func newTargetConnSecMark(mode TargetConnSecMarkMode) (*TargetConnSecMark, error) {
	target := &TargetConnSecMark{
		baseTarget: &baseTarget{
			targetType: TargetTypeConnSecMark,
		},
		Mode: mode,
	}
	target.setChild(target)
	return target, nil
}

type TargetConnSecMark struct {
	*baseTarget
	Mode TargetConnSecMarkMode
}

func (tConnSecMark *TargetConnSecMark) Short() string {
	return strings.Join(tConnSecMark.ShortArgs(), " ")
}

func (tConnSecMark *TargetConnSecMark) ShortArgs() []string {
	args := make([]string, 0, 4)
	args = append(args, "-j", tConnSecMark.targetType.String())
	switch tConnSecMark.Mode {
	case TargetConnSecMarkModeSAVE:
		args = append(args, "--save")
	case TargetConnSecMarkModeRESTORE:
		args = append(args, "--restore")
	}
	return args
}

func (tConnSecMark *TargetConnSecMark) Long() string {
	return tConnSecMark.Short()
}

func (tConnSecMark *TargetConnSecMark) LongArgs() []string {
	return tConnSecMark.ShortArgs()
}

func (tConnSecMark *TargetConnSecMark) Parse(main []byte) (int, bool) {
	pattern := `^CONNSECMARK (save|restore)`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 2 {
		return 0, false
	}
	switch string(matches[1]) {
	case "save":
		tConnSecMark.Mode = TargetConnSecMarkModeSAVE
	case "restore":
		tConnSecMark.Mode = TargetConnSecMarkModeRESTORE
	}
	return len(matches[0]), true
}

type CTEvent uint8

func (ctEvent CTEvent) String() string {
	switch ctEvent {
	case CTEventNEW:
		return "new"
	case CTEventRELATED:
		return "related"
	case CTEventDESTROY:
		return "destroy"
	case CTEventREPLY:
		return "reply"
	case CTEventASSURED:
		return "assured"
	case CTEventPROTOINFO:
		return "protoinfo"
	case CTEventHELPER:
		return "helper"
	case CTEventMARK:
		return "mark"
	case CTEventSEQADJ:
		return "natseqinfo"
	case CTEventSECMARK:
		return "secmark"
	case CTEventLABEL:
		return "label"
	case CTEventSYNPROXY:
		return "synproxy"
	default:
		return ""
	}
}

const (
	CTEventNEW CTEvent = iota
	CTEventRELATED
	CTEventDESTROY
	CTEventREPLY
	CTEventASSURED
	CTEventPROTOINFO
	CTEventHELPER
	CTEventMARK
	CTEventSEQADJ
	CTEventSECMARK
	CTEventLABEL
	CTEventSYNPROXY
	CTEventNATSEQADJ = CTEventSEQADJ
)

type CTExpectEvent uint8

func (ctExpectEvent CTExpectEvent) String() string {
	switch ctExpectEvent {
	case CTExpectEventNEW:
		return "new"
	case CTExpectEventDESTORY:
		return "destroy"
	default:
		return ""
	}
}

const (
	CTExpectEventNEW CTExpectEvent = iota
	CTExpectEventDESTORY
)

type CTZone int8

const (
	CTZoneOrig CTZone = 1 << iota
	CTZoneReply
	CTZoneBoth = CTZoneOrig | CTZoneReply
)

type OptionTargetCT func(*TargetCT)

// Disables connection tracking for this packet.
func WithTargetCTNoTrack() OptionTargetCT {
	return func(tCT *TargetCT) {
		tCT.NoTrack = true
	}
}

// Use the helper identified by name for the connection.
// This is more flexible than loading the conntrack helper modules with preset ports.
func WithTargetCTHelper(name string) OptionTargetCT {
	return func(tCT *TargetCT) {
		tCT.Helper = name
	}
}

// Only generate the specified conntrack events for this connection.
func WithTargetCTEvents(events ...CTEvent) OptionTargetCT {
	return func(tCT *TargetCT) {
		tCT.Events = events
	}
}

// Only generate the specified expectation events for this connection.
func WithTargetCTExpectEvents(events ...CTExpectEvent) OptionTargetCT {
	return func(tCT *TargetCT) {
		tCT.ExpectEvents = events
	}
}

func WithTargetCTZone(id int) OptionTargetCT {
	return func(tCT *TargetCT) {
		tCT.ZoneID = id
		tCT.Zone = CTZoneBoth
	}
}

// The zone is derived from the packet nfmark
func WithTargetCTZoneMark() OptionTargetCT {
	return func(tCT *TargetCT) {
		tCT.Mark = true
		tCT.Zone = CTZoneBoth
	}
}

func WithTargetCTZoneOrig(id int) OptionTargetCT {
	return func(tCT *TargetCT) {
		tCT.ZoneID = id
		tCT.Zone = CTZoneOrig
	}
}

// The zone is derived from the packet nfmark
func WithTargetCTZoneOrigMark() OptionTargetCT {
	return func(tCT *TargetCT) {
		tCT.Mark = true
		tCT.Zone = CTZoneOrig
	}
}

func WithTargetCTZoneReply(id int) OptionTargetCT {
	return func(tCT *TargetCT) {
		tCT.ZoneID = id
		tCT.Zone = CTZoneReply
	}
}

// The zone is derived from the packet nfmark
func WithTargetCTZoneReplyMark() OptionTargetCT {
	return func(tCT *TargetCT) {
		tCT.Mark = true
		tCT.Zone = CTZoneReply
	}
}

// Use the timeout policy identified by name for the connection.
// This is provides more flexible timeout policy definition than
// global timeout values available at /proc/sys/net/netfilter/nf_conntrack_*_timeout_*.
func WithTargetCTTimeout(timeout string) OptionTargetCT {
	return func(tCT *TargetCT) {
		tCT.Timeout = timeout
	}
}

func newTargetCT(opts ...OptionTargetCT) (*TargetCT, error) {
	target := &TargetCT{
		baseTarget: &baseTarget{
			targetType: TargetTypeCT,
		},
		ZoneID: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetCT struct {
	*baseTarget
	NoTrack      bool
	Helper       string
	Timeout      string
	Events       []CTEvent
	ExpectEvents []CTExpectEvent
	Zone         CTZone
	ZoneID       int
	Mark         bool
}

func (tCT *TargetCT) Short() string {
	return strings.Join(tCT.ShortArgs(), " ")
}

func (tCT *TargetCT) ShortArgs() []string {
	args := make([]string, 0, 17)
	args = append(args, "-j", tCT.targetType.String())
	if tCT.NoTrack {
		args = append(args, "--notrack")
	}
	if tCT.Helper != "" {
		args = append(args, "--helper", tCT.Helper)
	}
	if tCT.Events != nil && len(tCT.Events) > 0 {
		events := ""
		sep := ""
		for _, event := range tCT.Events {
			events += sep + event.String()
			sep = ","
		}
		args = append(args, "--ctevents", events)
	}
	if tCT.ExpectEvents != nil && len(tCT.ExpectEvents) > 0 {
		events := ""
		sep := ""
		for _, event := range tCT.ExpectEvents {
			events += sep + event.String()
			sep = ","
		}
		args = append(args, "--expevents", events)
	}
	switch tCT.Zone {
	case CTZoneOrig:
		if tCT.Mark {
			args = append(args, "--zone-orig", "mark")
		} else {
			args = append(args, "--zone-orig", strconv.Itoa(tCT.ZoneID))
		}
	case CTZoneReply:
		if tCT.Mark {
			args = append(args, "--zone-reply", "mark")
		} else {
			args = append(args, "--zone-reply", strconv.Itoa(tCT.ZoneID))
		}
	}
	if tCT.Timeout != "" {
		args = append(args, "--timeout", tCT.Timeout)
	}
	return args
}

func (tCT *TargetCT) Long() string {
	return tCT.Short()
}

func (tCT *TargetCT) LongArgs() []string {
	return tCT.ShortArgs()
}

func (tCT *TargetCT) Parse(main []byte) (int, bool) {
	// 1. "^(NOTRACK|CT)" #1
	// 2. "( notrack)?" #2
	// 3. "( helper ([0-9A-Za-z-_.]+))?" #3 #4
	// 4. "( timeout ([0-9A-Za-z-_.]+))?" #5 #6
	// 5. "( ctevents ([0-9A-Za-z-_.,]+))?" #7 #8
	// 6. "( expevents ([0-9A-Za-z-_.,]+))?" #9 #10
	// 7. "( (zone|zone-orig|zone-reply)( mark)?( ([0-9]+)))?" #11 #12 #13 #14 #15
	pattern := `^(NOTRACK|CT)` +
		`( notrack)?` +
		`( helper ([0-9A-Za-z-_.]+))?` +
		`( timeout ([0-9A-Za-z-_.]+))?` +
		`( ctevents ([0-9A-Za-z-_.,]+))?` +
		`( expevents ([0-9A-Za-z-_.,]+))?` +
		`( (zone-orig|zone-reply|zone)( mark)?( ([0-9]+))?)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 16 {
		return 0, false
	}
	switch string(matches[1]) {
	case "NOTRACK":
		tCT.NoTrack = true
		return len(matches[0]), true
	}
	if len(matches[2]) != 0 {
		return 0, false
	}
	if len(matches[4]) != 0 {
		tCT.Helper = string(matches[4])
	}
	if len(matches[6]) != 0 {
		tCT.Timeout = string(matches[6])
	}
	tCT.Events = []CTEvent{}
	if len(matches[8]) != 0 {
		elems := strings.Split(string(matches[8]), ",")
		for _, elem := range elems {
			switch elem {
			case "new":
				tCT.Events = append(tCT.Events, CTEventNEW)
			case "related":
				tCT.Events = append(tCT.Events, CTEventRELATED)
			case "destroy":
				tCT.Events = append(tCT.Events, CTEventDESTROY)
			case "reply":
				tCT.Events = append(tCT.Events, CTEventREPLY)
			case "assured":
				tCT.Events = append(tCT.Events, CTEventASSURED)
			case "protoinfo":
				tCT.Events = append(tCT.Events, CTEventPROTOINFO)
			case "helper":
				tCT.Events = append(tCT.Events, CTEventHELPER)
			case "mark":
				tCT.Events = append(tCT.Events, CTEventMARK)
			case "natseqinfo":
				tCT.Events = append(tCT.Events, CTEventNATSEQADJ)
			case "secmark":
				tCT.Events = append(tCT.Events, CTEventSECMARK)
			}
		}
	}
	tCT.ExpectEvents = []CTExpectEvent{}
	if len(matches[10]) != 0 {
		elems := strings.Split(string(matches[8]), ",")
		for _, elem := range elems {
			switch elem {
			case "new":
				tCT.ExpectEvents = append(tCT.ExpectEvents, CTExpectEventNEW)
			case "destroy":
				tCT.ExpectEvents = append(tCT.ExpectEvents, CTExpectEventDESTORY)
			}
		}
	}
	switch string(matches[12]) {
	case "zone":
		tCT.Zone = CTZoneBoth
	case "zone-orig":
		tCT.Zone = CTZoneOrig
	case "zone-reply":
		tCT.Zone = CTZoneReply
	}
	if len(matches[13]) != 0 {
		tCT.Mark = true
	}
	if len(matches[15]) != 0 {
		id, err := strconv.Atoi(string(matches[15]))
		if err != nil {
			tCT.ZoneID = id
		}
	}
	return len(matches[0]), true
}

type OptionTargetDNAT func(*TargetDNAT)

func WithTargetDNATToAddr(addr network.Address, port int) OptionTargetDNAT {
	return func(tDNAT *TargetDNAT) {
		tDNAT.AddrMin = addr
		tDNAT.AddrMax = nil
		tDNAT.PortMin = port
		tDNAT.PortMax = -1
	}
}

// To set addr nil or port -1 means empty.
func WithTargetDNATToAddrs(addrMin, addrMax network.Address, portMin, portMax int) OptionTargetDNAT {
	return func(tDNAT *TargetDNAT) {
		tDNAT.AddrMin = addrMin
		tDNAT.AddrMax = addrMax
		tDNAT.PortMin = portMin
		tDNAT.PortMax = portMax
	}
}

func WithTargetDNATRandom() OptionTargetDNAT {
	return func(tDNAT *TargetDNAT) {
		tDNAT.Random = true
	}
}

func WithTargetDNATPersistent() OptionTargetDNAT {
	return func(tDNAT *TargetDNAT) {
		tDNAT.Persistent = true
	}
}

func newTargetDNAT(opts ...OptionTargetDNAT) (*TargetDNAT, error) {
	target := &TargetDNAT{
		baseTarget: &baseTarget{
			targetType: TargetTypeDNAT,
		},
		PortMin:  -1,
		PortMax:  -1,
		PortBase: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetDNAT struct {
	*baseTarget
	AddrMin    network.Address
	AddrMax    network.Address
	PortMin    int
	PortMax    int
	PortBase   int
	Random     bool
	Persistent bool
}

func (tDNAT *TargetDNAT) Short() string {
	return strings.Join(tDNAT.ShortArgs(), " ")
}

func (tDNAT *TargetDNAT) ShortArgs() []string {
	args := make([]string, 0, 6)
	args = append(args, "-j", tDNAT.targetType.String())
	if tDNAT.AddrMin != nil {
		dst := tDNAT.AddrMin.String()
		if tDNAT.AddrMax != nil {
			dst += "-" + tDNAT.AddrMax.String()
		}
		if tDNAT.PortMin > -1 {
			dst += ":" + strconv.Itoa(tDNAT.PortMin)
		}
		if tDNAT.PortMax > -1 {
			dst += "-" + strconv.Itoa(tDNAT.PortMax)
		}
		args = append(args, "--to-destination", dst)
	}
	if tDNAT.Random {
		args = append(args, "--random")
	}
	if tDNAT.Persistent {
		args = append(args, "--persistent")
	}
	return args
}

func (tDNAT *TargetDNAT) Long() string {
	return tDNAT.Short()
}

func (tDNAT *TargetDNAT) LongArgs() []string {
	return tDNAT.ShortArgs()
}

func (tDNAT *TargetDNAT) Parse(main []byte) (int, bool) {
	// 1. "^to:"
	// 2. "(\[?(([0-9A-Za-z_.]+(?:::)*)+)(-(([0-9A-Za-z_.]+(?:::)*)+)\]?)?)" #1 #2 #3 #4 #5 #6
	// 3. "(:([0-9]+)(-([0-9A-Za-z]+))?(/([0-9]+))?)?" #7 #8 #9 #10 #11 #12
	// 4. "( random)?" #13
	// 5. "( persistent)?" #14
	pattern := `^to:` +
		`(\[?(([0-9A-Za-z_.]+(?:::)*)+)(-(([0-9A-Za-z_.]+(?:::)*)+)\]?)?)` +
		`(:([0-9]+)(-([0-9A-Za-z]+))?(/([0-9]+))?)?` +
		`( random)?` +
		`( persistent)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 15 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		addr, err := network.ParseAddress(string(matches[2]))
		if err != nil {
			return 0, false
		}
		tDNAT.AddrMin = addr
	}
	if len(matches[5]) != 0 {
		addr, err := network.ParseAddress(string(matches[5]))
		if err != nil {
			return 0, false
		}
		tDNAT.AddrMax = addr
	}
	if len(matches[8]) != 0 {
		min, err := strconv.Atoi(string(matches[8]))
		if err != nil {
			return 0, false
		}
		tDNAT.PortMin = min
	}
	if len(matches[10]) != 0 {
		max, err := strconv.Atoi(string(matches[10]))
		if err != nil {
			return 0, false
		}
		tDNAT.PortMax = max
	}
	if len(matches[12]) != 0 {
		base, err := strconv.Atoi(string(matches[12]))
		if err != nil {
			return 0, false
		}
		tDNAT.PortBase = base
	}
	if len(matches[13]) != 0 {
		tDNAT.Random = true
	}
	if len(matches[14]) != 0 {
		tDNAT.Persistent = true
	}
	return len(matches[0]), true
}

type OptionTargetDNPT func(*TargetDNPT)

func WithTargetDNPTSrcPrefix(prefix *net.IPNet) OptionTargetDNPT {
	return func(tDNAT *TargetDNPT) {
		tDNAT.SrcPrefix = prefix
	}
}

func WithTargetDNPTDstPrefix(prefix *net.IPNet) OptionTargetDNPT {
	return func(tDNAT *TargetDNPT) {
		tDNAT.DstPrefix = prefix
	}
}

func newTargetDNPT(opts ...OptionTargetDNPT) (*TargetDNPT, error) {
	target := &TargetDNPT{
		baseTarget: &baseTarget{
			targetType: TargetTypeDNPT,
		},
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

// IPv6 specific
type TargetDNPT struct {
	*baseTarget
	SrcPrefix *net.IPNet
	DstPrefix *net.IPNet
}

func (tDNPT *TargetDNPT) Short() string {
	return strings.Join(tDNPT.ShortArgs(), " ")
}

func (tDNPT *TargetDNPT) ShortArgs() []string {
	args := make([]string, 0, 6)
	args = append(args, "-j", tDNPT.targetType.String())
	if tDNPT.SrcPrefix != nil {
		args = append(args, "--src-pfx", tDNPT.SrcPrefix.String())
	}
	if tDNPT.DstPrefix != nil {
		args = append(args, "--dst-pfx", tDNPT.DstPrefix.String())
	}
	return args
}

func (tDNPT *TargetDNPT) Long() string {
	return tDNPT.Short()
}

func (tDNPT *TargetDNPT) LongArgs() []string {
	return tDNPT.ShortArgs()
}

func (tDNPT *TargetDNPT) Parse(main []byte) (int, bool) {
	// 1. "^DNPT"
	// 2. " src-pfx ([0-9A-Za-z_.:]+/[0-9]+) dst-pfx ([0-9A-Za-z_.:]+/[0-9]+)"
	pattern := `^DNPT` +
		` src-pfx ([0-9A-Za-z_.:]+/[0-9]+) dst-pfx ([0-9A-Za-z_.:]+/[0-9]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		_, ipNet, err := net.ParseCIDR(string(matches[1]))
		if err != nil {
			return 0, false
		}
		tDNPT.SrcPrefix = ipNet
	}
	if len(matches[2]) != 0 {
		_, ipNet, err := net.ParseCIDR(string(matches[2]))
		if err != nil {
			return 0, false
		}
		tDNPT.DstPrefix = ipNet
	}
	return len(matches[0]), true
}

type OptionTargetDSCP func(*TargetDSCP)

// Target against a numeric value [0-63].
func WithTargetDSCPValue(value int) OptionTargetDSCP {
	return func(mDSCP *TargetDSCP) {
		mDSCP.Value = value
	}
}

func WithTargetDSCPClass(class DSCPClass) OptionTargetDSCP {
	return func(mDSCP *TargetDSCP) {
		mDSCP.Value = int(class)
	}
}

func newTargetDSCP(opts ...OptionTargetDSCP) (*TargetDSCP, error) {
	target := &TargetDSCP{
		baseTarget: &baseTarget{
			targetType: TargetTypeDSCP,
		},
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetDSCP struct {
	*baseTarget
	Value int
}

func (tDSCP *TargetDSCP) Short() string {
	return strings.Join(tDSCP.ShortArgs(), " ")
}

func (tDSCP *TargetDSCP) ShortArgs() []string {
	args := make([]string, 0, 4)
	args = append(args, "-j", tDSCP.targetType.String())
	args = append(args, "--set-dscp", strconv.Itoa(tDSCP.Value))
	return args
}

func (tDSCP *TargetDSCP) Long() string {
	return tDSCP.Short()
}

func (tDSCP *TargetDSCP) LongArgs() []string {
	return tDSCP.ShortArgs()
}

func (tDSCP *TargetDSCP) Parse(main []byte) (int, bool) {
	pattern := `^DSCP set 0x([0-9A-Za-z]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 2 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		value, err := strconv.ParseInt(string(matches[1]), 16, 64)
		if err != nil {
			return 0, false
		}
		tDSCP.Value = int(value)
	}
	return len(matches[0]), true
}

type OptionTargetECN func(*TargetECN)

func WithTargetECNRemove() OptionTargetECN {
	return func(tECN *TargetECN) {
		tECN.TCPRemove = true
	}
}

func newTargetECN(opts ...OptionTargetECN) (*TargetECN, error) {
	target := &TargetECN{
		baseTarget: &baseTarget{
			targetType: TargetTypeECN,
		},
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

// IPv4 specific
type TargetECN struct {
	*baseTarget
	TCPRemove bool
}

func (tECN *TargetECN) Short() string {
	return strings.Join(tECN.ShortArgs(), " ")
}

func (tECN *TargetECN) ShortArgs() []string {
	args := make([]string, 0, 3)
	args = append(args, "-j", tECN.targetType.String())
	if tECN.TCPRemove {
		args = append(args, "--ecn-tcp-remove")
	}
	return args
}

func (tECN *TargetECN) Long() string {
	return tECN.Short()
}

func (tECN *TargetECN) LongArgs() []string {
	return tECN.ShortArgs()
}

func (tECN *TargetECN) Parse(main []byte) (int, bool) {
	pattern := `^ECN( TCP remove)?` +
		`( ECE=[0-9]+)?( CWR=[0-9]+)?( ECT codepoint=[0-9]+)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		tECN.TCPRemove = true
	}
	return len(matches[0]), true
}

type OptionTargetHL func(*TargetHL)

func WithTargetHLSet(value int) OptionTargetHL {
	return func(tHL *TargetHL) {
		tHL.Operator = xtables.OperatorSET
		tHL.Value = value
	}
}

func WithTargetHLDec(value int) OptionTargetHL {
	return func(tHL *TargetHL) {
		tHL.Operator = xtables.OperatorDEC
		tHL.Value = value
	}
}

func WithTargetHLInc(value int) OptionTargetHL {
	return func(tHL *TargetHL) {
		tHL.Operator = xtables.OperatorINC
		tHL.Value = value
	}
}

func newTargetHL(opts ...OptionTargetHL) (*TargetHL, error) {
	target := &TargetHL{
		baseTarget: &baseTarget{
			targetType: TargetTypeHL,
		},
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

// IPv6 specific
type TargetHL struct {
	*baseTarget
	Operator xtables.Operator
	Value    int
}

func (tHL *TargetHL) Short() string {
	return strings.Join(tHL.ShortArgs(), " ")
}

func (tHL *TargetHL) ShortArgs() []string {
	args := make([]string, 0, 4)
	args = append(args, "-j", tHL.targetType.String())
	switch tHL.Operator {
	case xtables.OperatorSET:
		args = append(args, "--hl-set", strconv.Itoa(tHL.Value))
	case xtables.OperatorDEC:
		args = append(args, "--hl-dec", strconv.Itoa(tHL.Value))
	case xtables.OperatorINC:
		args = append(args, "--hl-inc", strconv.Itoa(tHL.Value))
	}
	return args
}

func (tHL *TargetHL) Long() string {
	return tHL.Short()
}

func (tHL *TargetHL) LongArgs() []string {
	return tHL.ShortArgs()
}

func (tHL *TargetHL) Parse(main []byte) (int, bool) {
	pattern := `^HL ` +
		`(set to)?` +
		`(decrement by)?` +
		`(increment by)?` +
		` ([0-9]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		tHL.Operator = xtables.OperatorSET
	}
	if len(matches[2]) != 0 {
		tHL.Operator = xtables.OperatorDEC
	}
	if len(matches[3]) != 0 {
		tHL.Operator = xtables.OperatorINC
	}
	value, err := strconv.Atoi(string(matches[4]))
	if err != nil {
		return 0, false
	}
	tHL.Value = value
	return len(matches[0]), true
}

type HMarkTuple int8

func (tuple HMarkTuple) String() string {
	switch tuple {
	case HMarkTupleSrc:
		return "src"
	case HMarkTupleDst:
		return "dst"
	case HMarkTupleSport:
		return "sport"
	case HMarkTupleDport:
		return "dport"
	case HMarkTupleSPI:
		return "spi"
	case HMarkTupleCT:
		return "ct"
	default:
		return ""
	}
}

const (
	HMarkTupleSrc HMarkTuple = 1 << iota
	HMarkTupleDst
	HMarkTupleSport
	HMarkTupleDport
	HMarkTupleSPI
	HMarkTupleCT
)

type OptionTargetHMark func(*TargetHMark)

func WithTargetHMarkTuple(tuple HMarkTuple) OptionTargetHMark {
	return func(tHMark *TargetHMark) {
		tHMark.Tuple = tuple
	}
}

// Modulus for hash calculation (to limit the range of possible marks).
func WithTargetHMarkModulus(modulus int) OptionTargetHMark {
	return func(tHMark *TargetHMark) {
		tHMark.Modulus = modulus
	}
}

// Offset to start marks from.
func WithTargetHMarkOffset(offset int) OptionTargetHMark {
	return func(tHMark *TargetHMark) {
		tHMark.Offset = offset
	}
}

// The source address mask in CIDR notation.
func WithTargetHMarkSrcPrefix(prefix int) OptionTargetHMark {
	return func(tHMark *TargetHMark) {
		tHMark.SrcPrefix = prefix
	}
}

// The destination address mask in CIDR notation.
func WithTargetHMarkDstPrefix(prefix int) OptionTargetHMark {
	return func(tHMark *TargetHMark) {
		tHMark.DstPrefix = prefix
	}
}

// A 16 bit source port mask in hexadecimal.
func WithTargetHMarkSrcPortMask(mask int) OptionTargetHMark {
	return func(tHMark *TargetHMark) {
		tHMark.SrcPortMask = mask
	}
}

// A 16 bit destination port mask in hexadecimal.
func WithTargetHMarkDstPortMask(mask int) OptionTargetHMark {
	return func(tHMark *TargetHMark) {
		tHMark.DstPortMask = mask
	}
}

// A 32 bit field with spi mask.
func WithTargetHMarkSPIMask(mask int) OptionTargetHMark {
	return func(tHMark *TargetHMark) {
		tHMark.SPIMask = mask
	}
}

// An 8 bit field with layer 4 protocol number.
func WithTargetHMarkProtoMask(mask int) OptionTargetHMark {
	return func(tHMark *TargetHMark) {
		tHMark.ProtoMask = mask
	}
}

// A 32 bit random custom value to feed hash calculation.
func WithTargetHMarkRandom(rnd int) OptionTargetHMark {
	return func(tHMark *TargetHMark) {
		tHMark.Random = rnd
	}
}

func newTargetHMark(opts ...OptionTargetHMark) (*TargetHMark, error) {
	target := &TargetHMark{
		baseTarget: &baseTarget{
			targetType: TargetTypeHMark,
		},
		Modulus:     -1,
		Offset:      -1,
		Tuple:       -1,
		SrcPrefix:   -1,
		DstPrefix:   -1,
		SrcPortMask: -1,
		DstPortMask: -1,
		SPIMask:     -1,
		SrcPort:     -1,
		DstPort:     -1,
		SPI:         -1,
		ProtoMask:   -1,
		Random:      -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetHMark struct {
	*baseTarget
	Modulus     int
	Offset      int
	Tuple       HMarkTuple
	SrcPrefix   int
	DstPrefix   int
	SrcPortMask int
	DstPortMask int
	SPIMask     int
	SrcPort     int
	DstPort     int
	SPI         int
	ProtoMask   int
	Random      int
}

func (tHMark *TargetHMark) Short() string {
	return strings.Join(tHMark.ShortArgs(), " ")
}

func (tHMark *TargetHMark) ShortArgs() []string {
	args := make([]string, 0, 22)
	args = append(args, "-j", tHMark.targetType.String())
	if tHMark.Tuple > -1 {
		args = append(args, "--hmark-tuple", tHMark.Tuple.String())
	}
	if tHMark.Modulus > -1 {
		args = append(args, "--hmark-mod", strconv.Itoa(tHMark.Modulus))
	}
	if tHMark.Offset > -1 {
		args = append(args, "--hmark-offset", strconv.Itoa(tHMark.Offset))
	}
	if tHMark.SrcPrefix > -1 {
		args = append(args, "--hmark-src-prefix", strconv.Itoa(tHMark.SrcPrefix))
	}
	if tHMark.DstPrefix > -1 {
		args = append(args, "--hmark-dst-prefix", strconv.Itoa(tHMark.DstPrefix))
	}
	if tHMark.SrcPortMask > -1 {
		args = append(args, "--hmark-sport-mask", strconv.Itoa(tHMark.SrcPortMask))
	}
	if tHMark.DstPortMask > -1 {
		args = append(args, "--hmark-dport-mask", strconv.Itoa(tHMark.DstPortMask))
	}
	if tHMark.SPI > -1 {
		args = append(args, "--hmark-spi-mask", strconv.Itoa(tHMark.SPI))
	}
	if tHMark.ProtoMask > -1 {
		args = append(args, "--hmark-proto-mask", strconv.Itoa(tHMark.ProtoMask))
	}
	if tHMark.Random > -1 {
		args = append(args, "--hmark-proto-mask", strconv.Itoa(tHMark.ProtoMask))
	}
	return args
}

func (tHMark *TargetHMark) Long() string {
	return tHMark.Short()
}

func (tHMark *TargetHMark) LongArgs() []string {
	return tHMark.ShortArgs()
}

func (tHMark *TargetHMark) Parse(main []byte) (int, bool) {
	// 1. "^HMARK "
	// 2. "(mod ([0-9]+) )?" #1 #2
	// 3. "(+ 0x([0-9A-Za-z]+) )?" #3 #4
	// 4. "(ct, )?" #5
	// 5. "(src-prefix /?([0-9A-Za-z]+) )?" #6 #7
	// 6. "(dst-prefix /?([0-9A-Za-z]+) )?" #8 #9
	// 7. "(sport-mask 0x([0-9A-Za-z]+) )?" #10 #11
	// 8. "(dport-mask 0x([0-9A-Za-z]+) )?" #12 #13
	// 9. "(spi-mask 0x([0-9A-Za-z]+) )?" #14 #15
	// 10. "(sport 0x([0-9A-Za-z]+) )?" #16 #17
	// 11. "(dport 0x([0-9A-Za-z]+) )?" #18 #19
	// 12. "(spi 0x([0-9A-Za-z]+) )?" #20 #21
	// 13. "(proto-mask 0x([0-9A-Za-z]+) )?" #22 #23
	// 14. "(rnd 0x([0-9A-Za-z]+) )?" #24 #25
	pattern := `^HMARK ` +
		`(mod ([0-9]+) )?` +
		`(\+ 0x([0-9A-Za-z]+) )?` +
		`(ct, )?` +
		`(src-prefix /?([0-9A-Za-z]+) )?` +
		`(dst-prefix /?([0-9A-Za-z]+) )?` +
		`(sport-mask 0x([0-9A-Za-z]+) )?` +
		`(dport-mask 0x([0-9A-Za-z]+) )?` +
		`(spi-mask 0x([0-9A-Za-z]+) )?` +
		`(sport 0x([0-9A-Za-z]+) )?` +
		`(dport 0x([0-9A-Za-z]+) )?` +
		`(spi 0x([0-9A-Za-z]+) )?` +
		`(proto-mask 0x([0-9A-Za-z]+) )?` +
		`(rnd 0x([0-9A-Za-z]+) )? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 26 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		mod, err := strconv.Atoi(string(matches[2]))
		if err != nil {
			return 0, false
		}
		tHMark.Modulus = mod
	}
	if len(matches[4]) != 0 {
		offset, err := strconv.ParseInt(string(matches[4]), 16, 64)
		if err != nil {
			return 0, false
		}
		tHMark.Offset = int(offset)
	}
	if len(matches[5]) != 0 {
		// TODO
		tHMark.Tuple |= HMarkTupleSrc
	}
	if len(matches[7]) != 0 {
		prefix, err := strconv.ParseInt(string(matches[7]), 16, 64)
		if err != nil {
			return 0, false
		}
		tHMark.SrcPrefix = int(prefix)
	}
	if len(matches[9]) != 0 {
		prefix, err := strconv.ParseInt(string(matches[9]), 16, 64)
		if err != nil {
			return 0, false
		}
		tHMark.DstPrefix = int(prefix)
	}
	if len(matches[11]) != 0 {
		mask, err := strconv.ParseInt(string(matches[11]), 16, 64)
		if err != nil {
			return 0, false
		}
		tHMark.SrcPortMask = int(mask)
	}
	if len(matches[13]) != 0 {
		mask, err := strconv.ParseInt(string(matches[13]), 16, 64)
		if err != nil {
			return 0, false
		}
		tHMark.DstPortMask = int(mask)
	}
	if len(matches[15]) != 0 {
		mask, err := strconv.ParseInt(string(matches[15]), 16, 64)
		if err != nil {
			return 0, false
		}
		tHMark.SPIMask = int(mask)
	}
	if len(matches[17]) != 0 {
		port, err := strconv.ParseInt(string(matches[17]), 16, 64)
		if err != nil {
			return 0, false
		}
		tHMark.SrcPort = int(port)
	}
	if len(matches[19]) != 0 {
		port, err := strconv.ParseInt(string(matches[17]), 16, 64)
		if err != nil {
			return 0, false
		}
		tHMark.DstPort = int(port)
	}
	if len(matches[21]) != 0 {
		spi, err := strconv.ParseInt(string(matches[21]), 16, 64)
		if err != nil {
			return 0, false
		}
		tHMark.SPI = int(spi)
	}
	if len(matches[23]) != 0 {
		mask, err := strconv.ParseInt(string(matches[23]), 16, 64)
		if err != nil {
			return 0, false
		}
		tHMark.ProtoMask = int(mask)
	}
	if len(matches[25]) != 0 {
		rnd, err := strconv.ParseInt(string(matches[25]), 16, 64)
		if err != nil {
			return 0, false
		}
		tHMark.Random = int(rnd)
	}
	return len(matches[0]), true
}

type OptionTargetIdleTimer func(*TargetIdleTimer)

// This is the time in seconds that will trigger the notification.
func WithTargetIdleTimerTimeout(timeout int) OptionTargetIdleTimer {
	return func(tIdleTimer *TargetIdleTimer) {
		tIdleTimer.Timeout = timeout
	}
}

// This is a unique identifier for the timer.
// The maximum length for the label string is 27 characters.
func WithTargetIdleTimerLabel(label string) OptionTargetIdleTimer {
	return func(tIdleTimer *TargetIdleTimer) {
		tIdleTimer.Label = label
	}
}

func newTargetIdleTimer(opts ...OptionTargetIdleTimer) (*TargetIdleTimer, error) {
	target := &TargetIdleTimer{
		baseTarget: &baseTarget{
			targetType: TargetTypeIdleTimer,
		},
		Timeout: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetIdleTimer struct {
	*baseTarget
	Timeout int
	Label   string
	Alarm   bool
}

func (tIdleTimer *TargetIdleTimer) Short() string {
	return strings.Join(tIdleTimer.ShortArgs(), " ")
}

func (tIdleTimer *TargetIdleTimer) ShortArgs() []string {
	args := make([]string, 0, 6)
	args = append(args, "-j", tIdleTimer.targetType.String())
	if tIdleTimer.Timeout > -1 {
		args = append(args, "--timeout", strconv.Itoa(tIdleTimer.Timeout))
	}
	if tIdleTimer.Label != "" {
		args = append(args, "--label", tIdleTimer.Label)
	}
	return args
}

func (tIdleTimer *TargetIdleTimer) Long() string {
	return tIdleTimer.Short()
}

func (tIdleTimer *TargetIdleTimer) LongArgs() []string {
	return tIdleTimer.ShortArgs()
}

func (tIdleTimer *TargetIdleTimer) Parse(main []byte) (int, bool) {
	// 1. "timeout:([0-9]+)"
	// 2. " label:([0-9A-Za-z-._]+)"
	// 3. "( alarm)?"
	pattern := `^timeout:([0-9]+)` +
		` label:([0-9A-Za-z-._]+)` +
		`( alarm)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 4 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		timeout, err := strconv.Atoi(string(matches[1]))
		if err != nil {
			return 0, false
		}
		tIdleTimer.Timeout = timeout
	}
	if len(matches[2]) != 0 {
		tIdleTimer.Label = string(matches[2])
	}
	if len(matches[3]) != 0 {
		tIdleTimer.Alarm = true
	}
	return len(matches[0]), true
}

type OptionTargetLED func(*TargetLED)

// This is the name given to the LED trigger.
// The actual name of the trigger will be prefixed with "netfilter-".
func WithTargetLEDTriggerID(name string) OptionTargetLED {
	return func(tLED *TargetLED) {
		tLED.TriggerID = name
	}
}

// This indicates how long (in milliseconds) the LED should be left
// illuminated when a packet arrives before being switched off again.
func WithTargetLEDDelay(delay int) OptionTargetLED {
	return func(tLED *TargetLED) {
		tLED.Delay = delay
	}
}

// Always make the LED blink on packet arrival, even if the LED is already on.
func WithTargetLEDAlwaysBlink() OptionTargetLED {
	return func(tLED *TargetLED) {
		tLED.AlwaysBlink = true
	}
}

func newTargetLED(opts ...OptionTargetLED) (*TargetLED, error) {
	target := &TargetLED{
		baseTarget: &baseTarget{
			targetType: TargetTypeLED,
		},
		Delay: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetLED struct {
	*baseTarget
	TriggerID   string
	Delay       int // -1 meaning infinite
	AlwaysBlink bool
}

func (tLED *TargetLED) Short() string {
	return strings.Join(tLED.ShortArgs(), " ")
}

func (tLED *TargetLED) ShortArgs() []string {
	args := make([]string, 0, 7)
	args = append(args, "-j", tLED.targetType.String())
	if tLED.TriggerID != "" {
		args = append(args, "--led-trigger-id", tLED.TriggerID)
	}
	if tLED.Delay > -1 {
		args = append(args, "--led-delay", strconv.Itoa(tLED.Delay))
	} else if tLED.Delay == -1 {
		args = append(args, "--led-delay", "inf")
	}
	if tLED.AlwaysBlink {
		args = append(args, "--led-always-blink")
	}
	return args
}

func (tLED *TargetLED) Long() string {
	return tLED.Short()
}

func (tLED *TargetLED) LongArgs() []string {
	return tLED.ShortArgs()
}

func (tLED *TargetLED) Parse(main []byte) (int, bool) {
	// 1. "^led-trigger-id:\"([!-~]+)\"" #1
	// 2. "( led-delay:inf)?" #2
	// 3. "( led-delay:([0-9]+)ms)?" #3 #4
	// 4. "( led-always-blink)?" #5
	pattern := `^led-trigger-id:\"([!-~]+)\"` +
		`( led-delay:inf)?` +
		`( led-delay:([0-9]+)ms)?` +
		`( led-always-blink)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 6 {
		return 0, false
	}
	str := string(matches[1])
	str = strings.ReplaceAll(str, `\\`, `\`)
	tLED.TriggerID = strings.ReplaceAll(str, `\"`, `"`)
	if len(matches[2]) != 0 {
		tLED.Delay = -1
	}
	if len(matches[4]) != 0 {
		delay, err := strconv.Atoi(string(matches[4]))
		if err != nil {
			return 0, false
		}
		tLED.Delay = delay
	}
	if len(matches[5]) != 0 {
		tLED.AlwaysBlink = true
	}
	return len(matches[0]), true
}

type LOGFlag uint32

const (
	LOGFlagTCPSEQ    LOGFlag = 0x01
	LOGFlagTCPOPT    LOGFlag = 0x02
	LOGFlagIPOPT     LOGFlag = 0x04
	LOGFlagUID       LOGFlag = 0x08
	LOGFlagNFLOG     LOGFlag = 0x10
	LOGFlagMACDECODE LOGFlag = 0x20
	LOGFlagMASK      LOGFlag = 0x2f
)

type LOGLevel int8

const (
	LOGLevelEMERG   LOGLevel = 0 /* system is unusable */
	LOGLevelALERT   LOGLevel = 1 /* action must be taken immediately */
	LOGLevelCRIT    LOGLevel = 2 /* critical conditions */
	LOGLevelERR     LOGLevel = 3 /* error conditions */
	LOGLevelWARNING LOGLevel = 4 /* warning conditions */
	LOGLevelNOTICE  LOGLevel = 5 /* normal but significant condition */
	LOGLevelINFO    LOGLevel = 6 /* informational */
	LOGLevelDEBUG   LOGLevel = 7 /* debug-level messages */
)

type OptionTargetLog func(*TargetLog)

func WithTargetLogLevel(level LOGLevel) OptionTargetLog {
	return func(tLOG *TargetLog) {
		tLOG.Level = level
	}
}

func WithTargetLogPrefix(prefix string) OptionTargetLog {
	return func(tLOG *TargetLog) {
		tLOG.Prefix = prefix
	}
}

func WithTargetLogTCPSequence() OptionTargetLog {
	return func(tLOG *TargetLog) {
		tLOG.TCPSequence = true
	}
}

func WithTargetLogTCPOptions() OptionTargetLog {
	return func(tLOG *TargetLog) {
		tLOG.TCPOptions = true
	}
}

func WithTargetLogIPOptions() OptionTargetLog {
	return func(tLOG *TargetLog) {
		tLOG.IPOptions = true
	}
}

func WithTargetLogUID() OptionTargetLog {
	return func(tLOG *TargetLog) {
		tLOG.UID = true
	}
}

func newTargetLog(opts ...OptionTargetLog) (*TargetLog, error) {
	target := &TargetLog{
		baseTarget: &baseTarget{
			targetType: TargetTypeLog,
		},
		Level: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetLog struct {
	*baseTarget
	Level       LOGLevel
	Prefix      string
	TCPSequence bool
	TCPOptions  bool
	IPOptions   bool
	UID         bool
}

func (tLOG *TargetLog) Short() string {
	return strings.Join(tLOG.ShortArgs(), " ")
}

func (tLOG *TargetLog) ShortArgs() []string {
	args := make([]string, 0, 10)
	args = append(args, "-j", tLOG.targetType.String())
	if tLOG.Level > -1 {
		args = append(args, "--log-level", strconv.Itoa(int(tLOG.Level)))
	}
	if tLOG.Prefix != "" {
		args = append(args, "--log-prefix", tLOG.Prefix)
	}
	if tLOG.TCPSequence {
		args = append(args, "--log-tcp-sequence")
	}
	if tLOG.TCPOptions {
		args = append(args, "--log-tcp-options")
	}
	if tLOG.IPOptions {
		args = append(args, "--log-ip-options")
	}
	if tLOG.UID {
		args = append(args, "--log-uid")
	}
	return args
}

func (tLOG *TargetLog) Long() string {
	return tLOG.Short()
}

func (tLOG *TargetLog) LongArgs() []string {
	return tLOG.ShortArgs()
}

func (tLOG *TargetLog) Parse(main []byte) (int, bool) {
	// 1. "^LOG"
	// 2. "( flags ([0-9]+) level ([0-9]+))?" #1 #2 #3
	// 3. "( level (alert|crit|debug|emerg|error|info|notice|panic|warning))?" #4 #5
	// 4. "( UNKNOWN level ([0-9]+))?" #6 #7
	// 5. "( tcp-sequence)?" #8
	// 6. "( tcp-options)?" #9
	// 7. "( ip-options)?" #10
	// 8. "( uid)?" #11
	// 9. "( macdecode)?" #12
	// 10. "( unknown-flags)?" #13
	// 11. "( prefix \"([ -~]+)\")?" #14 #15
	pattern := `^LOG` +
		`( flags ([0-9]+) level ([0-9]+))?` +
		`( level (alert|crit|debug|emerg|error|info|notice|panic|warning))?` +
		`( UNKNOWN level ([0-9]+))?` +
		`( tcp-sequence)?` +
		`( tcp-options)?` +
		`( ip-options)?` +
		`( uid)?` +
		`( macdecode)?` +
		`( unknown-flags)?` +
		`( prefix \"([ -~]+)\")? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 16 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		flags, err := strconv.Atoi(string(matches[2]))
		if err != nil {
			return 0, false
		}
		flags32 := LOGFlag(uint32(flags))
		if flags32&LOGFlagTCPSEQ != 0 {
			tLOG.TCPSequence = true
		}
		if flags32&LOGFlagTCPOPT != 0 {
			tLOG.TCPOptions = true
		}
		if flags32&LOGFlagIPOPT != 0 {
			tLOG.IPOptions = true
		}
		if flags32&LOGFlagUID != 0 {
			tLOG.UID = true
		}
	}
	if len(matches[3]) != 0 {
		level, err := strconv.Atoi(string(matches[3]))
		if err != nil {
			return 0, false
		}
		tLOG.Level = LOGLevel(int8(level))
	}
	if len(matches[5]) != 0 {
		switch string(matches[5]) {
		case "alert":
			tLOG.Level = LOGLevelALERT
		case "crit":
			tLOG.Level = LOGLevelCRIT
		case "debug":
			tLOG.Level = LOGLevelDEBUG
		case "emerg":
			tLOG.Level = LOGLevelEMERG
		case "error":
			tLOG.Level = LOGLevelERR
		case "info":
			tLOG.Level = LOGLevelINFO
		case "notice":
			tLOG.Level = LOGLevelNOTICE
		case "warning":
			tLOG.Level = LOGLevelWARNING
		}
	}
	if len(matches[7]) != 0 {
		level, err := strconv.Atoi(string(matches[7]))
		if err != nil {
			return 0, false
		}
		tLOG.Level = LOGLevel(uint8(level))
	}
	if len(matches[8]) != 0 {
		tLOG.TCPSequence = true
	}
	if len(matches[9]) != 0 {
		tLOG.TCPOptions = true
	}
	if len(matches[10]) != 0 {
		tLOG.IPOptions = true
	}
	if len(matches[11]) != 0 {
		tLOG.UID = true
	}
	if len(matches[15]) != 0 {
		tLOG.Prefix = string(matches[15])
	}
	return len(matches[0]), true
}

type OptionTargetMark func(*TargetMark)

// This option takes mostly 2 value, (value) or (value, mask)
// Zero out the bits given by mask and XOR value into the ctmark.
func WithTargetMarkSetX(mark ...int) OptionTargetMark {
	return func(tMark *TargetMark) {
		switch len(mark) {
		case 1:
			tMark.Mark = mark[0]
		case 2:
			tMark.Mark = mark[0]
			tMark.Mask = mark[1]
		}
		tMark.Operator = xtables.OperatorXSET
	}
}

// Zeroes out the bits given by mask and ORs value into the packet mark.
func WithTargetMarkSet(mark ...int) OptionTargetMark {
	return func(tMark *TargetMark) {
		switch len(mark) {
		case 1:
			tMark.Mark = mark[0]
		case 2:
			tMark.Mark = mark[0]
			tMark.Mask = mark[1]
		}
		tMark.Operator = xtables.OperatorSET
	}
}

// Binary AND the ctmark with bits.
func WithTargetMarkAnd(mark int) OptionTargetMark {
	return func(tMark *TargetMark) {
		tMark.Mark = mark
		tMark.Operator = xtables.OperatorAND
	}
}

// Binary OR the ctmark with bits.
func WithTargetMarkOr(mark int) OptionTargetMark {
	return func(tMark *TargetMark) {
		tMark.Mark = mark
		tMark.Operator = xtables.OperatorOR
	}
}

// Binary XOR the ctmark with bits.
func WithTargetMarkXor(mark int) OptionTargetMark {
	return func(tMark *TargetMark) {
		tMark.Mark = mark
		tMark.Operator = xtables.OperatorXOR
	}
}

func newTargetMark(opts ...OptionTargetMark) (*TargetMark, error) {
	target := &TargetMark{
		baseTarget: &baseTarget{
			targetType: TargetTypeMark,
		},
		Mark: -1,
		Mask: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetMark struct {
	*baseTarget
	Operator xtables.Operator
	Mark     int
	Mask     int
}

func (tMark *TargetMark) Short() string {
	return strings.Join(tMark.ShortArgs(), " ")
}

func (tMark *TargetMark) ShortArgs() []string {
	args := make([]string, 0, 12)
	args = append(args, "-j", tMark.targetType.String())
	switch tMark.Operator {
	case xtables.OperatorXSET:
		if tMark.Mask > -1 {
			args = append(args, "--set-xmark",
				strconv.Itoa(tMark.Mark)+"/"+strconv.Itoa(tMark.Mask))
		} else {
			args = append(args, "--set-xmark", strconv.Itoa(tMark.Mark))
		}
	case xtables.OperatorSET:
		if tMark.Mask > -1 {
			args = append(args, "--set-mark",
				strconv.Itoa(tMark.Mark)+"/"+strconv.Itoa(tMark.Mask))
		} else {
			args = append(args, "--set-mark", strconv.Itoa(tMark.Mark))
		}
	case xtables.OperatorAND:
		args = append(args, "--and-mark", strconv.Itoa(tMark.Mark))
	case xtables.OperatorOR:
		args = append(args, "--or-mark", strconv.Itoa(tMark.Mark))
	case xtables.OperatorXOR:
		args = append(args, "--xor-mark", strconv.Itoa(tMark.Mark))
	}
	return args
}

func (tMark *TargetMark) Long() string {
	return tMark.Short()
}

func (tMark *TargetMark) LongArgs() []string {
	return tMark.ShortArgs()
}

func (tMark *TargetMark) Parse(main []byte) (int, bool) {
	// 1. "^MARK"
	// 2. " (set|and|or|xor|xset)" #1
	// 3. " 0x([0-9A-Za-z]+)(/0x([0-9A-Za-z]+))?" #2 #3 #4
	pattern := `^MARK` +
		` (set|and|or|xor|xset)` +
		` 0x([0-9A-Za-z]+)(/0x([0-9A-Za-z]+))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	switch string(matches[1]) {
	case "set":
		tMark.Operator = xtables.OperatorSET
	case "and":
		tMark.Operator = xtables.OperatorAND
	case "or":
		tMark.Operator = xtables.OperatorOR
	case "xor":
		tMark.Operator = xtables.OperatorXOR
	case "xset":
		tMark.Operator = xtables.OperatorXSET
	}
	if len(matches[2]) != 0 {
		value, err := strconv.ParseInt(string(matches[2]), 16, 64)
		if err != nil {
			return 0, false
		}
		tMark.Mark = int(value)
	}
	if len(matches[4]) != 0 {
		mask, err := strconv.ParseInt(string(matches[4]), 16, 64)
		if err != nil {
			return 0, false
		}
		tMark.Mask = int(mask)
	}
	return len(matches[0]), true
}

type OptionTargetMasquerade func(*TargetMasquerade)

// This option takes mostly 2 ports, (min) or (min, max)
func WithTargetMasqueradeToPort(port ...int) OptionTargetMasquerade {
	return func(tMasquerade *TargetMasquerade) {
		switch len(port) {
		case 1:
			tMasquerade.PortMin = port[0]
		case 2:
			tMasquerade.PortMin = port[0]
			tMasquerade.PortMax = port[1]
		}
	}
}

func WithTargetMasqueradeRandom() OptionTargetMasquerade {
	return func(tMasquerade *TargetMasquerade) {
		tMasquerade.Random = true
	}
}

func WithTargetMasqueradeRandomFully() OptionTargetMasquerade {
	return func(tMasquerade *TargetMasquerade) {
		tMasquerade.RandomFully = true
	}
}

func newTargetMasquerade(opts ...OptionTargetMasquerade) (*TargetMasquerade, error) {
	target := &TargetMasquerade{
		baseTarget: &baseTarget{
			targetType: TargetTypeMasquerade,
		},
		PortMin: -1,
		PortMax: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetMasquerade struct {
	*baseTarget
	PortMin     int
	PortMax     int
	Random      bool
	RandomFully bool
}

func (tMasquerade *TargetMasquerade) Short() string {
	return strings.Join(tMasquerade.ShortArgs(), " ")
}

func (tMasquerade *TargetMasquerade) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-j", tMasquerade.targetType.String())
	if tMasquerade.PortMin > -1 {
		if tMasquerade.PortMax > -1 {
			args = append(args, "--to-ports",
				strconv.Itoa(tMasquerade.PortMin)+"-"+strconv.Itoa(tMasquerade.PortMax))
		} else {
			args = append(args, "--to-ports", strconv.Itoa(tMasquerade.PortMin))
		}
	}
	if tMasquerade.Random {
		args = append(args, "--random")
	}
	return args
}

func (tMasquerade *TargetMasquerade) Long() string {
	return tMasquerade.Short()
}

func (tMasquerade *TargetMasquerade) LongArgs() []string {
	return tMasquerade.ShortArgs()
}

func (tMasquerade *TargetMasquerade) Parse(main []byte) (int, bool) {
	atLeastOne := false
	index := 0
	pattern := `^masq ports: ([0-9]+)(-([0-9]+))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) == 4 {
		if len(matches[1]) != 0 {
			min, err := strconv.Atoi(string(matches[1]))
			if err != nil {
				return 0, false
			}
			tMasquerade.PortMin = min
			atLeastOne = true
		}
		if len(matches[3]) != 0 {
			max, err := strconv.Atoi(string(matches[3]))
			if err != nil {
				return 0, false
			}
			tMasquerade.PortMax = max
			atLeastOne = true
		}
		index = len(matches[0])
		main = main[index:]
	}
	pattern = `^random-fully *`
	reg = regexp.MustCompile(pattern)
	matches = reg.FindSubmatch(main)
	if len(matches) == 1 {
		tMasquerade.RandomFully = true
		atLeastOne = true
		index += len(matches[0])
		main = main[index:]
	}
	pattern = `^random *`
	reg = regexp.MustCompile(pattern)
	matches = reg.FindSubmatch(main)
	if len(matches) == 1 {
		tMasquerade.Random = true
		atLeastOne = true
		index += len(matches[0])
	}
	if !atLeastOne {
		return 0, false
	}
	return index, true
}

type OptionTargetNetmap func(*TargetNetmap)

// Network address to map to.
func WithTargetNetmapAddr(addr network.Address) OptionTargetNetmap {
	return func(tNetmap *TargetNetmap) {
		tNetmap.Addr = addr
	}
}

func newTargetNetmap(opts ...OptionTargetNetmap) (*TargetNetmap, error) {
	target := &TargetNetmap{
		baseTarget: &baseTarget{
			targetType: TargetTypeNetmap,
		},
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetNetmap struct {
	*baseTarget
	Addr network.Address
}

func (tNetmap *TargetNetmap) Short() string {
	return strings.Join(tNetmap.ShortArgs(), " ")
}

func (tNetmap *TargetNetmap) ShortArgs() []string {
	args := make([]string, 0, 4)
	args = append(args, "-j", tNetmap.targetType.String())
	if tNetmap.Addr != nil {
		args = append(args, "--to", tNetmap.Addr.String())
	}
	return args
}

func (tNetmap *TargetNetmap) Long() string {
	return tNetmap.Short()
}

func (tNetmap *TargetNetmap) LongArgs() []string {
	return tNetmap.ShortArgs()
}

func (tNetmap *TargetNetmap) Parse(main []byte) (int, bool) {
	// 1. "to:([0-9A-Za-z.:]+)"
	// 2. "/([0-9A-Za-z.:]+)"
	pattern := `to:([0-9A-Za-z.:]+)` +
		`/([0-9A-Za-z.:]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	addr, err := network.ParseAddress(string(matches[1]))
	if err != nil {
		return 0, false
	}
	tNetmap.Addr = addr
	if len(matches[2]) != 0 {
		addr, err = network.ParseAddress(string(matches[1]) + string(matches[2]))
		if err == nil {
			tNetmap.Addr = addr
		}
	}
	return len(matches[0]), true
}

type OptionTargetNFLog func(*TargetNFLog)

// The netlink group (0 - 2^16-1) to which packets are (only applicable for nfnetlink_log).
// The default value is 0.
func WithTargetNFLogGroup(group int) OptionTargetNFLog {
	return func(tNFLog *TargetNFLog) {
		tNFLog.Group = group
	}
}

// A prefix string to include in the log message, up to 64 characters long,
// useful for distinguishing messages in the logs.
func WithTargetNFLogPrefix(prefix string) OptionTargetNFLog {
	return func(tNFLog *TargetNFLog) {
		tNFLog.Prefix = prefix
	}
}

// This option has never worked, use NFLogSize instead.
func WithTargetNFLogRange(rg int) OptionTargetNFLog {
	return func(tNFLog *TargetNFLog) {
		tNFLog.Range = rg
	}
}

// The number of bytes to be copied to userspace (only applicable for nfnetlink_log).
// nfnetlink_log instances may specify their own range, this option overrides it.
func WithTargetNFLogSize(size int) OptionTargetNFLog {
	return func(tNFLog *TargetNFLog) {
		tNFLog.Size = size
	}
}

// Number of packets to queue inside the kernel before sending them to userspace
// (only applicable for nfnetlink_log). Higher values result in less overhead
// per packet, but increase delay until the packets reach userspace. The default value is 1.
func WithTargetNFLogThreshold(threshold int) OptionTargetNFLog {
	return func(tNFLog *TargetNFLog) {
		tNFLog.Threshold = threshold
	}
}

func newTargetNFLog(opts ...OptionTargetNFLog) (*TargetNFLog, error) {
	target := &TargetNFLog{
		baseTarget: &baseTarget{
			targetType: TargetTypeNFLog,
		},
		Group:     -1,
		Range:     -1,
		Size:      -1,
		Threshold: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetNFLog struct {
	*baseTarget
	Prefix    string
	Group     int
	Range     int
	Size      int
	Threshold int
}

func (tNFLog *TargetNFLog) Short() string {
	return strings.Join(tNFLog.ShortArgs(), " ")
}

func (tNFLog *TargetNFLog) ShortArgs() []string {
	args := make([]string, 0, 10)
	args = append(args, "-j", tNFLog.targetType.String())
	if tNFLog.Group > -1 {
		args = append(args, "--nflog-group", strconv.Itoa(tNFLog.Group))
	}
	if tNFLog.Prefix != "" {
		args = append(args, "--nflog-prefix", tNFLog.Prefix)
	}
	if tNFLog.Range > -1 {
		args = append(args, "--nflog-range", strconv.Itoa(tNFLog.Range))
	}
	if tNFLog.Threshold > -1 {
		args = append(args, "--nflog-threshold", strconv.Itoa(tNFLog.Threshold))
	}
	return args
}

func (tNFLog *TargetNFLog) Long() string {
	return tNFLog.Short()
}

func (tNFLog *TargetNFLog) LongArgs() []string {
	return tNFLog.ShortArgs()
}

func (tNFLog *TargetNFLog) Parse(main []byte) (int, bool) {
	// 1. "^(snflog-prefix|nflog-group|nflog-size|nflog-range|nflog-threshold)"
	// 2. "( ([!-~]+))"
	pattern := `^(nflog-prefix|nflog-group|nflog-size|nflog-range|nflog-threshold)` +
		`( +([!-~]+)) *`
	reg := regexp.MustCompile(pattern)
	index := 0
	for len(main) > 0 {
		matches := reg.FindSubmatch(main)
		if len(matches) != 4 {
			goto END
		}

		switch string(matches[1]) {
		case "nflog-prefix":
			str := string(matches[3])
			str = strings.ReplaceAll(str, `\\`, `\`)
			tNFLog.Prefix = strings.ReplaceAll(str, `\"`, `"`)
		case "nflog-group":
			group, err := strconv.Atoi(string(matches[3]))
			if err != nil {
				goto END
			}
			tNFLog.Group = group
		case "nflog-size":
			size, err := strconv.Atoi(string(matches[3]))
			if err != nil {
				goto END
			}
			tNFLog.Size = size
		case "nflog-range":
			rg, err := strconv.Atoi(string(matches[3]))
			if err != nil {
				goto END
			}
			tNFLog.Range = rg
		case "nflog-threshold":
			threshold, err := strconv.Atoi(string(matches[3]))
			if err != nil {
				goto END
			}
			tNFLog.Threshold = threshold
		}
		index += len(matches[0])
		main = main[len(matches[0]):]
	}
END:
	if index != 0 {
		return index, true
	}
	return 0, false
}

type OptionTargetNFQueue func(*TargetNFQueue)

// This specifies the QUEUE number to use. Valid queue numbers are 0 to 65535.
// The default value is 0.
func WithTargetNFQueueNum(num int) OptionTargetNFQueue {
	return func(tNFQueue *TargetNFQueue) {
		tNFQueue.QueueMin = num
	}
}

// This specifies a range of queues to use.
// Packets are then balanced across the given queues.
// This is useful for multicore systems: start multiple
// instances of the userspace program on queues x, x+1, .. x+n
func WithTargetNFQueueBalance(min, max int) OptionTargetNFQueue {
	return func(tNFQueue *TargetNFQueue) {
		tNFQueue.QueueMin = min
		tNFQueue.QueueMax = max
	}
}

// By default, if no userspace program is listening on an NFQUEUE,
// then all packets that are to be queued are dropped.
func WithTargetNFQueueBypass() OptionTargetNFQueue {
	return func(tNFQueue *TargetNFQueue) {
		tNFQueue.Bypass = true
	}
}

// Available starting Linux kernel 3.10.
// The idea is that you can improve performance if there's a queue per CPU.
func WithTargetNFQueueCPUFanout() OptionTargetNFQueue {
	return func(tNFQueue *TargetNFQueue) {
		tNFQueue.CPUFanout = true
	}
}

func newTargetNFQueue(opts ...OptionTargetNFQueue) (*TargetNFQueue, error) {
	target := &TargetNFQueue{
		baseTarget: &baseTarget{
			targetType: TargetTypeNFQueue,
		},
		QueueMin: -1,
		QueueMax: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetNFQueue struct {
	*baseTarget
	QueueMin  int
	QueueMax  int
	Bypass    bool
	CPUFanout bool
}

func (tNFQueue *TargetNFQueue) Short() string {
	return strings.Join(tNFQueue.ShortArgs(), " ")
}

func (tNFQueue *TargetNFQueue) ShortArgs() []string {
	args := make([]string, 0, 8)
	args = append(args, "-j", tNFQueue.targetType.String())
	if tNFQueue.QueueMin > -1 {
		if tNFQueue.QueueMax > -1 {
			args = append(args, "--queue-balance",
				strconv.Itoa(tNFQueue.QueueMin)+":"+strconv.Itoa(tNFQueue.QueueMax))
		} else {
			args = append(args, "--queue-num", strconv.Itoa(tNFQueue.QueueMin))
		}
	}
	if tNFQueue.Bypass {
		args = append(args, "--queue-bypass")
	}
	if tNFQueue.CPUFanout {
		args = append(args, "--queue-cpu-fanout")
	}
	return args
}

func (tNFQueue *TargetNFQueue) Long() string {
	return tNFQueue.Short()
}

func (tNFQueue *TargetNFQueue) LongArgs() []string {
	return tNFQueue.ShortArgs()
}

func (tNFQueue *TargetNFQueue) Parse(main []byte) (int, bool) {
	// 1. "^NFQUEUE"
	// 2. " (balance|num) ([0-9]+)(:([0-9]+))?" #1 #2 #3 #4
	// 3. "( bypass)?" #5
	// 4. "( cpu-fanout)?" #6
	pattern := `^NFQUEUE` +
		` (balance|num) ([0-9]+)(:([0-9]+))?` +
		`( bypass)?` +
		`( cpu-fanout)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 7 {
		return 0, false
	}
	min, err := strconv.Atoi(string(matches[2]))
	if err != nil {
		return 0, false
	}
	tNFQueue.QueueMin = min
	if len(matches[4]) != 0 {
		max, err := strconv.Atoi(string(matches[4]))
		if err != nil {
			return 0, false
		}
		tNFQueue.QueueMax = max
	}
	if len(matches[5]) != 0 {
		tNFQueue.Bypass = true
	}
	if len(matches[6]) != 0 {
		tNFQueue.CPUFanout = true
	}
	return len(matches[0]), true
}

type OptionTargetRateEst func(*TargetRateEst)

// Count matched packets into the pool referred to by name, which is freely choosable.
func WithTargetRateEstName(name string) OptionTargetRateEst {
	return func(tRateEst *TargetRateEst) {
		tRateEst.Name = name
	}
}

// Rate measurement interval, in seconds, milliseconds or microseconds.
func WithTargetRateEstInterval(interval xtables.RateFloat) OptionTargetRateEst {
	return func(tRateEst *TargetRateEst) {
		tRateEst.Interval = interval
	}
}

// Rate measurement averaging time constant.
func WithTargetRateEstEwmalog(ewmalog float64) OptionTargetRateEst {
	return func(tRateEst *TargetRateEst) {
		tRateEst.Ewmalog = ewmalog
	}
}

func newTargetRateEst(opts ...OptionTargetRateEst) (*TargetRateEst, error) {
	target := &TargetRateEst{
		baseTarget: &baseTarget{
			targetType: TargetTypeRateEst,
		},
		Ewmalog: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetRateEst struct {
	*baseTarget
	Name     string
	Interval xtables.RateFloat
	Ewmalog  float64
}

func (tRateEst *TargetRateEst) Short() string {
	return strings.Join(tRateEst.ShortArgs(), " ")
}

func (tRateEst *TargetRateEst) ShortArgs() []string {
	args := make([]string, 0, 8)
	args = append(args, "-j", tRateEst.targetType.String())
	if tRateEst.Name != "" {
		args = append(args, "--rateest-name", tRateEst.Name)
	}
	if (tRateEst.Interval != xtables.RateFloat{}) {
		args = append(args, "--rateest-interval", tRateEst.Interval.Sting())
	}
	if tRateEst.Ewmalog > -1 {
		args = append(args, "--rateest-ewmalog",
			strconv.FormatFloat(tRateEst.Ewmalog, 'f', 2, 64))
	}
	return args
}

func (tRateEst *TargetRateEst) Long() string {
	return tRateEst.Short()
}

func (tRateEst *TargetRateEst) LongArgs() []string {
	return tRateEst.ShortArgs()
}

func (tRateEst *TargetRateEst) Parse(main []byte) (int, bool) {
	// 1. "^name ([!-~]+)" #1
	// 2. " interval ([0-9.]+)(us|ms|s)" #2 #3
	// 3. " ewmalog ([0-9.]+)(us|ms|s)" #4 #5
	pattern := `^name ([!-~]+)` +
		` interval ([0-9.]+)(us|ms|s)` +
		` ewmalog ([0-9.]+)(us|ms|s)`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 6 {
		return 0, false
	}
	tRateEst.Name = string(matches[1])
	interval, err := strconv.ParseFloat(string(matches[2]), 64)
	if err != nil {
		return 0, false
	}
	unit := xtables.Second
	switch string(matches[3]) {
	case "us":
		unit = xtables.Microsecond
	case "ms":
		unit = xtables.Millisecond
	case "s":
		unit = xtables.Second
	}
	tRateEst.Interval = xtables.RateFloat{
		Rate: interval,
		Unit: unit,
	}
	ewmalog, err := strconv.ParseFloat(string(matches[4]), 64)
	switch string(matches[5]) {
	case "us":
		unit = xtables.Microsecond
	case "ms":
		unit = xtables.Millisecond
	case "s":
		unit = xtables.Second
	}
	tRateEst.Ewmalog = ewmalog
	return len(matches[0]), true
}

type OptionTargetRedirect func(*TargetRedirect)

// This option takes mostly 2 ports, (min) or (min, max)
func WithTargetRedirectToPort(port ...int) OptionTargetRedirect {
	return func(tRedirect *TargetRedirect) {
		switch len(port) {
		case 1:
			tRedirect.PortMin = port[0]
		case 2:
			tRedirect.PortMin = port[0]
			tRedirect.PortMax = port[1]
		}
	}
}

func WithTargetRedirectRandom() OptionTargetRedirect {
	return func(tRedirect *TargetRedirect) {
		tRedirect.Random = true
	}
}

func newTargetRedirect(opts ...OptionTargetRedirect) (*TargetRedirect, error) {
	target := &TargetRedirect{
		baseTarget: &baseTarget{
			targetType: TargetTypeRedirect,
		},
		PortMin: -1,
		PortMax: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetRedirect struct {
	*baseTarget
	PortMin int
	PortMax int
	Random  bool
}

func (tRedirect *TargetRedirect) Short() string {
	return strings.Join(tRedirect.ShortArgs(), " ")
}

func (tRedirect *TargetRedirect) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-j", tRedirect.targetType.String())
	if tRedirect.PortMin > -1 {
		if tRedirect.PortMax > -1 {
			args = append(args, "--to-ports",
				strconv.Itoa(tRedirect.PortMin)+"-"+strconv.Itoa(tRedirect.PortMax))
		} else {
			args = append(args, "--to-ports", strconv.Itoa(tRedirect.PortMin))
		}
	}
	if tRedirect.Random {
		args = append(args, "--random")
	}
	return args
}

func (tRedirect *TargetRedirect) Long() string {
	return tRedirect.Short()
}

func (tRedirect *TargetRedirect) LongArgs() []string {
	return tRedirect.ShortArgs()
}

func (tRedirect *TargetRedirect) Parse(main []byte) (int, bool) {
	index := 0
	pattern := `^redir ports ([0-9]+)(-([0-9]+))? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) == 4 {
		if len(matches[1]) != 0 {
			min, err := strconv.Atoi(string(matches[1]))
			if err != nil {
				return 0, false
			}
			tRedirect.PortMin = min
		}
		if len(matches[3]) != 0 {
			max, err := strconv.Atoi(string(matches[3]))
			if err != nil {
				return 0, false
			}
			tRedirect.PortMax = max
		}
		index = len(matches[0])
		main = main[index:]
	}
	// TODO some mistakes in iptables.git
	pattern = `^random *`
	reg = regexp.MustCompile(pattern)
	matches = reg.FindSubmatch(main)
	if len(matches) == 1 {
		tRedirect.Random = true
		index += len(matches[0])
	}
	return index, true
}

type RejectType int8

func (rejectType RejectType) String() string {
	switch rejectType {
	case Icmp6NoRoute:
		return "icmp6-no-route"
	case NoRoute:
		return "no-route"
	case Icmp6AdmProhibited:
		return "icmp6-adm-prohibited"
	case AdmProhibited:
		return "addr-unreach"
	case Icmp6AddrUnreachable:
		return "icmp6-addr-unreachable"
	case AddrUnreachable:
		return "addr-unreach"
	case Icmp6PortUnreachable:
		return "icmp6-port-unreachable"
	case IcmpNetUnreachable:
		return "icmp-net-unreachable"
	case IcmpHostUnreachable:
		return "icmp-host-unreachable"
	case IcmpPortUnreachable:
		return "icmp-port-unreachable"
	case IcmpProtoUnreachable:
		return "icmp-proto-unreachable"
	case IcmpNetProhibited:
		return "icmp-net-prohibited"
	case IcmpHostProhibited:
		return "icmp-host-prohibited"
	case IcmpAdminProhibited:
		return "icmp-admin-prohibited"
	case TcpReset:
		return "tcp-reset"
	default:
		return ""
	}
}

const (
	_ RejectType = iota
	// IPv6
	Icmp6NoRoute
	NoRoute
	Icmp6AdmProhibited
	AdmProhibited
	Icmp6AddrUnreachable
	AddrUnreachable
	Icmp6PortUnreachable
	// IPv4
	IcmpNetUnreachable
	IcmpHostUnreachable
	IcmpPortUnreachable
	IcmpProtoUnreachable
	IcmpNetProhibited
	IcmpHostProhibited
	IcmpAdminProhibited
	// Both
	TcpReset
)

var (
	RejectTypeMap = map[string]RejectType{
		"icmp6-no-route":         Icmp6NoRoute,
		"no-route":               NoRoute,
		"icmp6-adm-prohibited":   Icmp6AdmProhibited,
		"adm-prohibited":         Icmp6AdmProhibited,
		"icmp6-addr-unreachable": Icmp6AddrUnreachable,
		"addr-unreach":           Icmp6AddrUnreachable,
		"icmp6-port-unreachable": Icmp6PortUnreachable,
		"icmp-net-unreachable":   IcmpNetUnreachable,
		"icmp-host-unreachable":  IcmpHostUnreachable,
		"icmp-port-unreachable":  IcmpPortUnreachable,
		"icmp-proto-unreachable": IcmpProtoUnreachable,
		"icmp-net-prohibited":    IcmpNetProhibited,
		"icmp-host-prohibited":   IcmpHostProhibited,
		"icmp-admin-prohibited":  IcmpAdminProhibited,
		"tcp-reset":              TcpReset,
	}
)

type OptionTargetReject func(*TargetReject)

func WithTargetRejectType(typ RejectType) OptionTargetReject {
	return func(tReject *TargetReject) {
		tReject.RejectType = typ
	}
}

func newTargetReject(opts ...OptionTargetReject) (*TargetReject, error) {
	target := &TargetReject{
		baseTarget: &baseTarget{
			targetType: TargetTypeReject,
		},
		RejectType: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetReject struct {
	*baseTarget
	RejectType RejectType
}

func (tReject *TargetReject) Short() string {
	return strings.Join(tReject.ShortArgs(), " ")
}

func (tReject *TargetReject) ShortArgs() []string {
	args := make([]string, 0, 4)
	args = append(args, "-j", tReject.targetType.String())
	if tReject.RejectType > -1 {
		args = append(args, "--reject-with", tReject.RejectType.String())
	}
	return args
}

func (tReject *TargetReject) Long() string {
	return tReject.Short()
}

func (tReject *TargetReject) LongArgs() []string {
	return tReject.ShortArgs()
}

func (tReject *TargetReject) Parse(main []byte) (int, bool) {
	// 1. "^reject-with ([!-~]+)"
	pattern := `^reject-with ([!-~]+)`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 2 {
		return 0, false
	}
	typ, ok := RejectTypeMap[string(matches[1])]
	if !ok {
		return 0, false
	}
	tReject.RejectType = typ
	return len(matches[0]), true
}

type OptionTargetSame func(*TargetSame)

// This option takes mostly 2 addrs, (min) or (min, max)
func WithTargetSameAddr(addr ...network.Address) OptionTargetSame {
	return func(tSame *TargetSame) {
		switch len(addr) {
		case 1:
			tSame.AddrMin = addr[0]
		case 2:
			tSame.AddrMin = addr[0]
			tSame.AddrMax = addr[1]
		}
	}
}

func WithTargetSameNoDst() OptionTargetSame {
	return func(tSame *TargetSame) {
		tSame.NoDst = true
	}
}

func WithTargetSameNoRandom() OptionTargetSame {
	return func(tSame *TargetSame) {
		tSame.Random = true
	}
}

func newTargetSame(opts ...OptionTargetSame) (*TargetSame, error) {
	target := &TargetSame{
		baseTarget: &baseTarget{
			targetType: TargetTypeSame,
		},
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

// TODO untested in the real world
// IPv4 specific
type TargetSame struct {
	*baseTarget
	AddrMin network.Address
	AddrMax network.Address
	NoDst   bool
	Random  bool
}

func (tSame *TargetSame) Short() string {
	return strings.Join(tSame.ShortArgs(), " ")
}

func (tSame *TargetSame) ShortArgs() []string {
	args := make([]string, 0, 6)
	args = append(args, "-j", tSame.targetType.String())
	if tSame.AddrMin != nil {
		if tSame.AddrMax != nil {
			args = append(args, "--to",
				tSame.AddrMin.String()+"-"+tSame.AddrMax.String())
		} else {
			args = append(args, "--to", tSame.AddrMin.String())
		}
	}
	if tSame.NoDst {
		args = append(args, "--nodes")
	}
	if tSame.Random {
		args = append(args, "--random")
	}
	return args
}

func (tSame *TargetSame) Long() string {
	return tSame.Short()
}

func (tSame *TargetSame) LongArgs() []string {
	return tSame.ShortArgs()
}

func (tSame *TargetSame) Parse(main []byte) (int, bool) {
	// 1. "^same:"
	// 2. "(([!-~]+)(-([!-~]+))? )?" #1 #2 #3 #4
	// 3. "(nodst )?" #5
	// 4. "(random )?" #6
	pattern := `^same: ` +
		`(([0-9.]+)(-([0-9.]+))? )?` +
		`(nodst )?` +
		`(random )? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 7 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		addr, err := network.ParseAddress(string(matches[2]))
		if err != nil {
			return 0, false
		}
		tSame.AddrMin = addr
	}
	if len(matches[4]) != 0 {
		addr, err := network.ParseAddress(string(matches[2]))
		if err != nil {
			return 0, false
		}
		tSame.AddrMax = addr
	}
	if len(matches[5]) != 0 {
		tSame.NoDst = true
	}
	if len(matches[6]) != 0 {
		tSame.Random = true
	}
	return len(matches[0]), true
}

type OptionTargetSecMark func(*TargetSecMark)

func WithTargetSecMarkSelCtx(selCtx string) OptionTargetSecMark {
	return func(tSecMark *TargetSecMark) {
		tSecMark.SelCtx = selCtx
	}
}

func newTargetSecMark(opts ...OptionTargetSecMark) (*TargetSecMark, error) {
	target := &TargetSecMark{
		baseTarget: &baseTarget{
			targetType: TargetTypeSecMark,
		},
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

// TODO untested in the real world
type TargetSecMark struct {
	*baseTarget
	SelCtx string
}

func (tSecMark *TargetSecMark) Short() string {
	return strings.Join(tSecMark.ShortArgs(), " ")
}

func (tSecMark *TargetSecMark) ShortArgs() []string {
	args := make([]string, 0, 4)
	args = append(args, "-j", tSecMark.targetType.String())
	if tSecMark.SelCtx != "" {
		args = append(args, "--selctx", tSecMark.SelCtx)
	}
	return args
}

func (tSecMark *TargetSecMark) Long() string {
	return tSecMark.Short()
}

func (tSecMark *TargetSecMark) LongArgs() []string {
	return tSecMark.ShortArgs()
}

func (tSecMark *TargetSecMark) Parse(main []byte) (int, bool) {
	// 1. "^SECMARK "
	// 2. "selctx ([!-~]+)|invalid mode [0-9]+"
	pattern := `^SECMARK ` +
		`(selctx ([!-~]+)|invalid mode [0-9]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		tSecMark.SelCtx = string(matches[2])
	}
	return len(matches[0]), true
}

type SetMode uint8

const (
	SetModeAdd SetMode = 1 << iota
	SetModeDel
	SetModeMap
)

type SetFlag uint8

func (setFlag SetFlag) String() string {
	switch setFlag {
	case SetFlagSrc:
		return "src"
	case SetFlagDst:
		return "dst"
	default:
		return ""
	}
}

const (
	SetFlagSrc SetFlag = 1 << iota
	SetFlagDst
)

type OptionTargetSet func(*TargetSet)

func WithTargetSetAdd(name string, flags ...SetFlag) OptionTargetSet {
	return func(tSet *TargetSet) {
		tSet.Mode = SetModeAdd
		tSet.Name = name
		tSet.Flags = flags
	}
}

func WithTargetSetDel(name string, flags ...SetFlag) OptionTargetSet {
	return func(tSet *TargetSet) {
		tSet.Mode = SetModeDel
		tSet.Name = name
		tSet.Flags = flags
	}
}

func WithTargetSetMap(name string, flags ...SetFlag) OptionTargetSet {
	return func(tSet *TargetSet) {
		tSet.Mode = SetModeMap
		tSet.Name = name
		tSet.Flags = flags
	}
}

func WithTargetSetTimeout(timeout int) OptionTargetSet {
	return func(tSet *TargetSet) {
		tSet.Timeout = timeout
	}
}

func WithTargetSetExist() OptionTargetSet {
	return func(tSet *TargetSet) {
		tSet.Exist = true
	}
}

func WithTargetSetMapMark() OptionTargetSet {
	return func(tSet *TargetSet) {
		tSet.MapMark = true
	}
}

func WithTargetSetMapPrio() OptionTargetSet {
	return func(tSet *TargetSet) {
		tSet.MapPrio = true
	}
}

func WithTargetSetMapQueue() OptionTargetSet {
	return func(tSet *TargetSet) {
		tSet.MapQueue = true
	}
}

func newTargetSet(opts ...OptionTargetSet) (*TargetSet, error) {
	target := &TargetSet{
		baseTarget: &baseTarget{
			targetType: TargetTypeSet,
		},
		Timeout: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetSet struct {
	*baseTarget
	Mode     SetMode
	Name     string
	Flags    []SetFlag
	Timeout  int
	Exist    bool
	MapMark  bool
	MapPrio  bool
	MapQueue bool
}

func (tSet *TargetSet) Short() string {
	return strings.Join(tSet.ShortArgs(), " ")
}

func (tSet *TargetSet) ShortArgs() []string {
	args := make([]string, 0, 9)
	args = append(args, "-j", tSet.targetType.String())

	flags := ""
	sep := ""
	if tSet.Flags != nil && len(tSet.Flags) != 0 {
		for _, flag := range tSet.Flags {
			flags += sep + flag.String()
			sep = ","
		}
	}
	switch tSet.Mode {
	case SetModeAdd:
		args = append(args, "--add-set", tSet.Name, flags)
	case SetModeDel:
		args = append(args, "--del-set", tSet.Name, flags)
	}
	if tSet.Timeout > -1 {
		args = append(args, "--timeout", strconv.Itoa(tSet.Timeout))
	}
	if tSet.Exist {
		args = append(args, "--exist")
	}
	return args
}

func (tSet *TargetSet) Long() string {
	return tSet.Short()
}

func (tSet *TargetSet) LongArgs() []string {
	return tSet.ShortArgs()
}

func (tSet *TargetSet) Parse(main []byte) (int, bool) {
	// 1. "^(add-set|del-set|map-set) ([!-~]+) *(,?(src|dst)+)*" #1 #2 #3 #4 #5
	// 2. "( exist)?" #6
	// 3. "( timeout ([0-9]+))?" #7 #8
	// 4. "( map-mark)?" #9
	// 5. "( map-prio)?" #10
	// 6. "( map-queue)?" #11
	pattern := `^(add-set|del-set|map-set) ([!-~]+) *((,?(src|dst))+)` +
		`( exist)?` +
		`( timeout ([0-9]+))?` +
		`( map-mark)?` +
		`( map-prio)?` +
		`( map-queue)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 12 {
		return 0, false
	}
	// mode
	switch string(matches[1]) {
	case "add-set":
		tSet.Mode = SetModeAdd
	case "del-set":
		tSet.Mode = SetModeDel
	case "map-set":
		tSet.Mode = SetModeMap
	}
	// name
	tSet.Name = string(matches[2])
	// flags
	tSet.Flags = []SetFlag{}
	elems := strings.Split(string(matches[3]), ",")
	for _, elem := range elems {
		if elem == "src" {
			tSet.Flags = append(tSet.Flags, SetFlagSrc)
		} else if elem == "dst" {
			tSet.Flags = append(tSet.Flags, SetFlagDst)
		}
	}
	// exists
	if len(matches[6]) != 0 {
		tSet.Exist = true
	}
	// timeout
	if len(matches[8]) != 0 {
		timeout, err := strconv.Atoi(string(matches[8]))
		if err != nil {
			return 0, false
		}
		tSet.Timeout = timeout
	}
	if len(matches[9]) != 0 {
		tSet.MapMark = true
	}
	if len(matches[10]) != 0 {
		tSet.MapPrio = true
	}
	if len(matches[11]) != 0 {
		tSet.MapQueue = true
	}
	return len(matches[0]), true
}

type OptionTargetSNAT func(*TargetSNAT)

// To set addr nil or port -1 means empty.
func WithTargetSNATToAddr(addrMin, addrMax network.Address, portMin, portMax int) OptionTargetSNAT {
	return func(tSNAT *TargetSNAT) {
		tSNAT.AddrMin = addrMin
		tSNAT.AddrMax = addrMax
		tSNAT.PortMin = portMin
		tSNAT.PortMax = portMax
	}
}

func WithTargetSNATRandom() OptionTargetSNAT {
	return func(tSNAT *TargetSNAT) {
		tSNAT.Random = true
	}
}

func WithTargetSNATPersistent() OptionTargetSNAT {
	return func(tSNAT *TargetSNAT) {
		tSNAT.Persistent = true
	}
}

func newTargetSNAT(opts ...OptionTargetSNAT) (*TargetSNAT, error) {
	target := &TargetSNAT{
		baseTarget: &baseTarget{
			targetType: TargetTypeSNAT,
		},
		PortMin:  -1,
		PortMax:  -1,
		PortBase: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetSNAT struct {
	*baseTarget
	AddrMin    network.Address
	AddrMax    network.Address
	PortMin    int
	PortMax    int
	PortBase   int
	Random     bool
	Persistent bool
}

func (tSNAT *TargetSNAT) Short() string {
	return strings.Join(tSNAT.ShortArgs(), " ")
}

func (tSNAT *TargetSNAT) ShortArgs() []string {
	args := make([]string, 0, 6)
	args = append(args, "-j", tSNAT.targetType.String())
	if tSNAT.AddrMin != nil {
		source := tSNAT.AddrMin.String()
		if tSNAT.AddrMax != nil {
			source += "-" + tSNAT.AddrMax.String()
		}
		if tSNAT.PortMin > -1 {
			source += ":" + strconv.Itoa(tSNAT.PortMin)
		}
		if tSNAT.PortMax > -1 {
			source += "-" + strconv.Itoa(tSNAT.PortMax)
		}
	}
	if tSNAT.Random {
		args = append(args, "--random")
	}
	if tSNAT.Persistent {
		args = append(args, "--persistent")
	}
	return args
}

func (tSNAT *TargetSNAT) Long() string {
	return tSNAT.Short()
}

func (tSNAT *TargetSNAT) LongArgs() []string {
	return tSNAT.ShortArgs()
}

func (tSNAT *TargetSNAT) Parse(main []byte) (int, bool) {
	// 1. "^to:"
	// 2. "(\[?(([0-9A-Za-z_.]+(?:::)*)+)(-(([0-9A-Za-z_.]+(?:::)*)+)\]?)?)" #1 #2 #3 #4 #5 #6
	// 3. "(:([0-9]+)(-([0-9A-Za-z]+))?(/([0-9]+))?)?" #7 #8 #9 #10 #11 #12
	// 4. "( random)?" #13
	// 5. "( persistent)?" #14
	pattern := `^to:` +
		`(\[?(([0-9A-Za-z_.]+(?:::)*)+)(-(([0-9A-Za-z_.]+(?:::)*)+)\]?)?)` +
		`(:([0-9]+)(-([0-9A-Za-z]+))?(/([0-9]+))?)?` +
		`( random)?` +
		`( persistent)? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 15 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		addr, err := network.ParseAddress(string(matches[2]))
		if err != nil {
			return 0, false
		}
		tSNAT.AddrMin = addr
	}
	if len(matches[5]) != 0 {
		addr, err := network.ParseAddress(string(matches[5]))
		if err != nil {
			return 0, false
		}
		tSNAT.AddrMax = addr
	}
	if len(matches[8]) != 0 {
		min, err := strconv.Atoi(string(matches[8]))
		if err != nil {
			return 0, false
		}
		tSNAT.PortMin = min
	}
	if len(matches[10]) != 0 {
		max, err := strconv.Atoi(string(matches[10]))
		if err != nil {
			return 0, false
		}
		tSNAT.PortMax = max
	}
	if len(matches[12]) != 0 {
		base, err := strconv.Atoi(string(matches[12]))
		if err != nil {
			return 0, false
		}
		tSNAT.PortBase = base
	}
	if len(matches[13]) != 0 {
		tSNAT.Random = true
	}
	if len(matches[14]) != 0 {
		tSNAT.Persistent = true
	}
	return len(matches[0]), true
}

type OptionTargetSNPT func(*TargetSNPT)

func WithTargetSNPTSrcPrefix(prefix *net.IPNet) OptionTargetSNPT {
	return func(tDNAT *TargetSNPT) {
		tDNAT.SrcPrefix = prefix
	}
}

func WithTargetSNPTDstPrefix(prefix *net.IPNet) OptionTargetSNPT {
	return func(tDNAT *TargetSNPT) {
		tDNAT.DstPrefix = prefix
	}
}

func newTargetSNPT(opts ...OptionTargetSNPT) (*TargetSNPT, error) {
	target := &TargetSNPT{
		baseTarget: &baseTarget{
			targetType: TargetTypeSNPT,
		},
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

// IPv6 specific
type TargetSNPT struct {
	*baseTarget
	SrcPrefix *net.IPNet
	DstPrefix *net.IPNet
}

func (tSNPT *TargetSNPT) Short() string {
	return strings.Join(tSNPT.ShortArgs(), " ")
}

func (tSNPT *TargetSNPT) ShortArgs() []string {
	args := make([]string, 0, 6)
	args = append(args, "-j", tSNPT.targetType.String())
	if tSNPT.SrcPrefix != nil {
		args = append(args, "--src-pfx", tSNPT.SrcPrefix.String())
	}
	if tSNPT.DstPrefix != nil {
		args = append(args, "--dst-pfx", tSNPT.DstPrefix.String())
	}
	return args
}

func (tSNPT *TargetSNPT) Long() string {
	return tSNPT.Short()
}

func (tSNPT *TargetSNPT) LongArgs() []string {
	return tSNPT.ShortArgs()
}

func (tSNPT *TargetSNPT) Parse(main []byte) (int, bool) {
	// 1. "^SNPT"
	// 2. " src-pfx ([0-9A-Za-z_.:]+/[0-9]+) dst-pfx ([0-9A-Za-z_.:]+/[0-9]+)"
	pattern := `^SNPT` +
		` src-pfx ([0-9A-Za-z_.:]+/[0-9]+) dst-pfx ([0-9A-Za-z_.:]+/[0-9]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		_, ipNet, err := net.ParseCIDR(string(matches[1]))
		if err != nil {
			return 0, false
		}
		tSNPT.SrcPrefix = ipNet
	}
	if len(matches[2]) != 0 {
		_, ipNet, err := net.ParseCIDR(string(matches[2]))
		if err != nil {
			return 0, false
		}
		tSNPT.DstPrefix = ipNet
	}
	return len(matches[0]), true
}

type OptionTargetSYNProxy func(*TargetSYNProxy)

// Maximum segment size announced to clients. This must match the backend.
func WithTargetSYNProxyMSS(mss int) OptionTargetSYNProxy {
	return func(tSYNProxy *TargetSYNProxy) {
		tSYNProxy.MSS = mss
	}
}

// Window scale announced to clients. This must match the backend.
func WithTargetSYNProxyWindowScale(scale int) OptionTargetSYNProxy {
	return func(tSYNProxy *TargetSYNProxy) {
		tSYNProxy.WindowScale = scale
	}
}

// Pass client selective acknowledgement option to backend (will be disabled if not present).
func WithTargetSYNProxySockPerm() OptionTargetSYNProxy {
	return func(tSYNProxy *TargetSYNProxy) {
		tSYNProxy.SockPerm = true
	}
}

//  Pass client timestamp option to backend (will be disabled if not present,
// also needed for selective acknowledgement and window scaling).
func WithTargetSYNProxyTimestamp() OptionTargetSYNProxy {
	return func(tSYNProxy *TargetSYNProxy) {
		tSYNProxy.Timestamp = true
	}
}

func WithTargetSYNProxyECN() OptionTargetSYNProxy {
	return func(tSYNProxy *TargetSYNProxy) {
		tSYNProxy.ECN = true
	}
}

func newTargetSYNProxy(opts ...OptionTargetSYNProxy) (*TargetSYNProxy, error) {
	target := &TargetSYNProxy{
		baseTarget: &baseTarget{
			targetType: TargetTypeSYNProxy,
		},
		WindowScale: -1,
		MSS:         -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetSYNProxy struct {
	*baseTarget
	WindowScale int
	MSS         int
	SockPerm    bool
	Timestamp   bool
	ECN         bool
}

func (tSYNProxy *TargetSYNProxy) Short() string {
	return strings.Join(tSYNProxy.ShortArgs(), " ")
}

func (tSYNProxy *TargetSYNProxy) ShortArgs() []string {
	args := make([]string, 0, 8)
	args = append(args, "-j", tSYNProxy.targetType.String())
	if tSYNProxy.MSS > -1 {
		args = append(args, "--mss", strconv.Itoa(tSYNProxy.MSS))
	}
	if tSYNProxy.WindowScale > -1 {
		args = append(args, "--wscale", strconv.Itoa(tSYNProxy.WindowScale))
	}
	if tSYNProxy.SockPerm {
		args = append(args, "--sack-perm")
	}
	if tSYNProxy.Timestamp {
		args = append(args, "--timestamps")
	}
	return args
}

func (tSYNProxy *TargetSYNProxy) Long() string {
	return tSYNProxy.Short()
}

func (tSYNProxy *TargetSYNProxy) LongArgs() []string {
	return tSYNProxy.ShortArgs()
}

func (tSYNProxy *TargetSYNProxy) Parse(main []byte) (int, bool) {
	// 1. "^SYNPROXY "
	// 2. "(sack-perm )?"
	// 3. "(timestamp )?"
	// 4. "(wscale ([0-9]+) )?"
	// 5. "(mss ([0-9]+) )?"
	// 6. "(ecn )?"
	pattern := `^SYNPROXY ` +
		`(sack-perm )?` +
		`(timestamp )?` +
		`(wscale ([0-9]+) )?` +
		`(mss ([0-9]+) )?` +
		`(ecn )? *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 8 {
		return 0, false
	}
	if len(matches[1]) != 0 {
		tSYNProxy.SockPerm = true
	}
	if len(matches[2]) != 0 {
		tSYNProxy.Timestamp = true
	}
	if len(matches[4]) != 0 {
		wscale, err := strconv.Atoi(string(matches[4]))
		if err != nil {
			return 0, false
		}
		tSYNProxy.WindowScale = wscale
	}
	if len(matches[6]) != 0 {
		mss, err := strconv.Atoi(string(matches[6]))
		if err != nil {
			return 0, false
		}
		tSYNProxy.MSS = mss
	}
	if len(matches[7]) != 0 {
		tSYNProxy.ECN = true
	}
	return len(matches[0]), true
}

type OptionTargetTCPMSS func(*TargetTCPMSS)

// Explicitly sets MSS option to specified value.
func WithTargetTCPMSS(mss int) OptionTargetTCPMSS {
	return func(tTCPMSS *TargetTCPMSS) {
		tTCPMSS.MSS = mss
	}
}

func WithTargetTCPMSSClampMssToPmtu() OptionTargetTCPMSS {
	return func(tTCPMSS *TargetTCPMSS) {
		tTCPMSS.ClampMssToPmtu = true
	}
}

func newTargetTCPMSS(opts ...OptionTargetTCPMSS) (*TargetTCPMSS, error) {
	target := &TargetTCPMSS{
		baseTarget: &baseTarget{
			targetType: TargetTypeTCPMSS,
		},
		MSS: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetTCPMSS struct {
	*baseTarget
	MSS            int
	ClampMssToPmtu bool
}

func (tTCPMSS *TargetTCPMSS) Short() string {
	return strings.Join(tTCPMSS.ShortArgs(), " ")
}

func (tTCPMSS *TargetTCPMSS) ShortArgs() []string {
	args := make([]string, 0, 5)
	args = append(args, "-j", tTCPMSS.targetType.String())
	if tTCPMSS.MSS > -1 {
		args = append(args, "--set-mss", strconv.Itoa(tTCPMSS.MSS))
	}
	if tTCPMSS.ClampMssToPmtu {
		args = append(args, "--clamp-mss-to-pmtu")
	}
	return args
}

func (tTCPMSS *TargetTCPMSS) Long() string {
	return tTCPMSS.Short()
}

func (tTCPMSS *TargetTCPMSS) LongArgs() []string {
	return tTCPMSS.ShortArgs()
}

func (tTCPMSS *TargetTCPMSS) Parse(main []byte) (int, bool) {
	// 1. "^TCPMSS "
	// 2. "(clamp to PMTU|set ([0-9]+))"
	pattern := `^TCPMSS ` +
		`(clamp to PMTU|set ([0-9]+)) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	if len(matches[2]) != 0 {
		mss, err := strconv.Atoi(string(matches[2]))
		if err != nil {
			return 0, false
		}
		tTCPMSS.MSS = mss
	} else {
		tTCPMSS.ClampMssToPmtu = true
	}
	return len(matches[0]), true
}

type OptionTargetTCPOptStrip func(*TargetTCPOptStrip)

// Strip the given option(s).
// The options may be specified by TCP option number or by symbolic name.
func WithTargetTCPOptStripOpts(opts ...network.TCPOpt) OptionTargetTCPOptStrip {
	return func(tTCPOptStrip *TargetTCPOptStrip) {
		tTCPOptStrip.Opts = opts
	}
}

func newTargetTCPOptStrip(opts ...OptionTargetTCPOptStrip) (*TargetTCPOptStrip, error) {
	target := &TargetTCPOptStrip{
		baseTarget: &baseTarget{
			targetType: TargetTypeTCPOptStrip,
		},
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetTCPOptStrip struct {
	*baseTarget
	Opts []network.TCPOpt
}

func (tTCPOptStrip *TargetTCPOptStrip) Short() string {
	return strings.Join(tTCPOptStrip.ShortArgs(), " ")
}

func (tTCPOptStrip *TargetTCPOptStrip) ShortArgs() []string {
	args := make([]string, 0, 4)
	args = append(args, "-j", tTCPOptStrip.targetType.String())
	if tTCPOptStrip.Opts != nil && len(tTCPOptStrip.Opts) != 0 {
		opts := ""
		sep := ""
		for _, opt := range tTCPOptStrip.Opts {
			sep += sep + opt.String()
		}
		args = append(args, "--strip-options", opts)
	}
	return args
}

func (tTCPOptStrip *TargetTCPOptStrip) Long() string {
	return tTCPOptStrip.Short()
}

func (tTCPOptStrip *TargetTCPOptStrip) LongArgs() []string {
	return tTCPOptStrip.ShortArgs()
}

func (tTCPOptStrip *TargetTCPOptStrip) Parse(main []byte) (int, bool) {
	// 1. "^TCPOPTSTRIP options "
	// 2. "((,?(mss|wscale|sack-permitted|sack|md5|([0-9]+)))+)"
	pattern := `^TCPOPTSTRIP options ` +
		`((,?(mss|wscale|sack-permitted|sack|md5|([0-9]+)))+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 5 {
		return 0, false
	}
	tTCPOptStrip.Opts = []network.TCPOpt{}
	elems := strings.Split(string(matches[1]), ",")
	for _, elem := range elems {
		opt, ok := network.TCPOpts[elem]
		if ok {
			tTCPOptStrip.Opts = append(tTCPOptStrip.Opts, opt)
		} else {
			option, err := strconv.Atoi(elem)
			if err != nil {
				return 0, false
			}
			tTCPOptStrip.Opts = append(tTCPOptStrip.Opts, network.TCPOpt(option))
		}
	}
	return len(matches[0]), true
}

func newTargetTEE(gateway net.IP) (*TargetTEE, error) {
	target := &TargetTEE{
		baseTarget: &baseTarget{
			targetType: TargetTypeTEE,
		},
		Gateway: gateway,
	}
	target.setChild(target)
	return target, nil
}

type TargetTEE struct {
	*baseTarget
	Gateway net.IP
}

func (tTEE *TargetTEE) Short() string {
	return strings.Join(tTEE.ShortArgs(), " ")
}

func (tTEE *TargetTEE) ShortArgs() []string {
	args := make([]string, 0, 4)
	args = append(args, "-j", tTEE.targetType.String())
	if tTEE.Gateway != nil {
		args = append(args, "--gateway", tTEE.Gateway.String())
	}
	return args
}

func (tTEE *TargetTEE) Long() string {
	return tTEE.Short()
}

func (tTEE *TargetTEE) LongArgs() []string {
	return tTEE.ShortArgs()
}

func (tTEE *TargetTEE) Parse(main []byte) (int, bool) {
	pattern := `^TEE gw:([0-9A-Za-z.:]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 2 {
		return 0, false
	}
	tTEE.Gateway = net.ParseIP(string(matches[1]))
	return len(matches[0]), true
}

type OptionTargetTOS func(*TargetTOS)

// This option takes mostly 2 tos, (value) or (value/mask)
func WithTargetTOSSet(tos ...network.TOS) OptionTargetTOS {
	return func(tTOS *TargetTOS) {
		switch len(tos) {
		case 1:
			tTOS.Value = tos[0]
		case 2:
			tTOS.Value = tos[0]
			tTOS.Mask = tos[1]
		}
		tTOS.Operator = xtables.OperatorSET
	}
}

func WithTargetTOSAnd(tos network.TOS) OptionTargetTOS {
	return func(tTOS *TargetTOS) {
		tTOS.Value = tos
		tTOS.Operator = xtables.OperatorAND
	}
}

func WithTargetTOSOr(tos network.TOS) OptionTargetTOS {
	return func(tTOS *TargetTOS) {
		tTOS.Value = tos
		tTOS.Operator = xtables.OperatorOR
	}
}

func WithTargetTOSXor(tos network.TOS) OptionTargetTOS {
	return func(tTOS *TargetTOS) {
		tTOS.Value = tos
		tTOS.Operator = xtables.OperatorXOR
	}
}

func newTargetTOS(opts ...OptionTargetTOS) (*TargetTOS, error) {
	target := &TargetTOS{
		baseTarget: &baseTarget{
			targetType: TargetTypeTOS,
		},
		Value: -1,
		Mask:  -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetTOS struct {
	*baseTarget
	Operator xtables.Operator
	Value    network.TOS
	Mask     network.TOS
}

func (tTOS *TargetTOS) Short() string {
	return strings.Join(tTOS.ShortArgs(), " ")
}

func (tTOS *TargetTOS) ShortArgs() []string {
	args := make([]string, 0, 4)
	args = append(args, "-j", tTOS.targetType.String())
	switch tTOS.Operator {
	case xtables.OperatorSET:
		if tTOS.Mask > -1 {
			args = append(args, "--set-tos",
				strconv.Itoa(int(tTOS.Value))+"/"+strconv.Itoa(int(tTOS.Mask)))
		} else {
			args = append(args, "--set-tos", strconv.Itoa(int(tTOS.Value)))
		}
	case xtables.OperatorAND:
		args = append(args, "--and-tos", strconv.Itoa(int(tTOS.Value)))
	case xtables.OperatorOR:
		args = append(args, "--or-tos", strconv.Itoa(int(tTOS.Value)))
	case xtables.OperatorXOR:
		args = append(args, "--xor-tos", strconv.Itoa(int(tTOS.Value)))
	}
	return args
}

func (tTOS *TargetTOS) Long() string {
	return tTOS.Short()
}

func (tTOS *TargetTOS) LongArgs() []string {
	return tTOS.ShortArgs()
}

func (tTOS *TargetTOS) Parse(main []byte) (int, bool) {
	// 1. "^TOS (set|and|or|xor)"
	// 2. "( (Minimize-Delay|Maximize-Throughput|Maximize-Reliability|Minimize-Cost|Normal-Service))?"
	// 3. "( 0x([0-9A-Za-z]+)/0x([0-9A-Za-z]+))?"
	pattern := `^TOS (set|and|or|xor)` +
		`( (Minimize-Delay|Maximize-Throughput|Maximize-Reliability|Minimize-Cost|Normal-Service))?` +
		`( 0x([0-9A-Za-z]+)(/0x([0-9A-Za-z]+))?)?`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 8 {
		return 0, false
	}
	switch string(matches[1]) {
	case "set":
		tTOS.Operator = xtables.OperatorSET
	case "and":
		tTOS.Operator = xtables.OperatorAND
	case "or":
		tTOS.Operator = xtables.OperatorOR
	case "xor":
		tTOS.Operator = xtables.OperatorXOR
	}
	if len(matches[3]) != 0 {
		tos, ok := network.TOSMap[string(matches[3])]
		if ok {
			tTOS.Value = tos
		}
		tTOS.Mask = network.TOS(0x3f)
	}
	if len(matches[5]) != 0 {
		value, err := strconv.ParseInt(string(matches[5]), 16, 8)
		if err != nil {
			return 0, false
		}
		tTOS.Value = network.TOS(value)
	}
	if len(matches[7]) != 0 {
		mask, err := strconv.ParseInt(string(matches[7]), 16, 8)
		if err != nil {
			return 0, false
		}
		tTOS.Mask = network.TOS(mask)
	}
	return len(matches[0]), true
}

type OptionTargetTProxy func(*TargetTProxy)

// This specifies a destination port to use.
func WithTargetTProxyOnPort(port int) OptionTargetTProxy {
	return func(tTProxy *TargetTProxy) {
		tTProxy.Port = port
	}
}

// This specifies a destination address to use.
func WithTargetTProxyOnIP(ip net.IP) OptionTargetTProxy {
	return func(tTProxy *TargetTProxy) {
		tTProxy.IP = ip
	}
}

func WithTargetTProxyMark(mark ...int) OptionTargetTProxy {
	return func(tTProxy *TargetTProxy) {
		switch len(mark) {
		case 1:
			tTProxy.Value = mark[0]
		case 2:
			tTProxy.Value = mark[0]
			tTProxy.Mask = mark[1]
		}
	}
}

func newTargetTProxy(opts ...OptionTargetTProxy) (*TargetTProxy, error) {
	target := &TargetTProxy{
		baseTarget: &baseTarget{
			targetType: TargetTypeTProxy,
		},
		Port:  -1,
		Value: -1,
		Mask:  -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

type TargetTProxy struct {
	*baseTarget
	IP    net.IP
	Port  int
	Value int
	Mask  int
}

func (tTProxy *TargetTProxy) Short() string {
	return strings.Join(tTProxy.ShortArgs(), " ")
}

func (tTProxy *TargetTProxy) ShortArgs() []string {
	args := make([]string, 0, 8)
	args = append(args, "-j", tTProxy.targetType.String())
	if tTProxy.IP != nil {
		args = append(args, "--on-ip", tTProxy.IP.String())
	}
	if tTProxy.Port > -1 {
		args = append(args, "--on-port", strconv.Itoa(tTProxy.Port))
	}
	if tTProxy.Value > -1 {
		if tTProxy.Mask > -1 {
			args = append(args, "--tproxy-mark",
				strconv.Itoa(tTProxy.Value)+"/"+strconv.Itoa(tTProxy.Mask))
		} else {
			args = append(args, "--tproxy-mark", strconv.Itoa(tTProxy.Value))
		}
	}
	return args
}

func (tTProxy *TargetTProxy) Long() string {
	return tTProxy.Short()
}

func (tTProxy *TargetTProxy) LongArgs() []string {
	return tTProxy.ShortArgs()
}

func (tTProxy *TargetTProxy) Parse(main []byte) (int, bool) {
	pattern := `^TPROXY redirect ` +
		`([!-~]+) ` +
		`mark 0x([0-9A-Za-z]+)/0x([0-9A-Za-z]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 4 {
		return 0, false
	}
	// ip
	ipPort := string(matches[1])
	index := strings.LastIndex(ipPort, ":")
	ip := net.ParseIP(ipPort[:index])
	if ip == nil {
		return 0, false
	}
	tTProxy.IP = ip
	// port
	port, err := strconv.Atoi(ipPort[index+1:])
	if err != nil {
		return 0, false
	}
	tTProxy.Port = port
	if len(matches[2]) != 0 {
		value, err := strconv.ParseUint(string(matches[2]), 16, 8)
		if err != nil {
			return 0, false
		}
		tTProxy.Value = int(value)
	}
	if len(matches[3]) != 0 {
		mask, err := strconv.ParseUint(string(matches[3]), 16, 8)
		if err != nil {
			return 0, false
		}
		tTProxy.Mask = int(mask)
	}
	return len(matches[0]), true
}

func newTargetTrace() (*TargetTrace, error) {
	target := &TargetTrace{
		baseTarget: &baseTarget{
			targetType: TargetTypeTrace,
		},
	}
	target.setChild(target)
	return target, nil
}

type TargetTrace struct {
	*baseTarget
}

func (tTrace *TargetTrace) Short() string {
	return strings.Join(tTrace.ShortArgs(), " ")
}

func (tTrace *TargetTrace) ShortArgs() []string {
	args := make([]string, 0, 2)
	args = append(args, "-j", tTrace.targetType.String())
	return args
}

func (tTrace *TargetTrace) Long() string {
	return tTrace.Short()
}

func (tTrace *TargetTrace) LongArgs() []string {
	return tTrace.ShortArgs()
}

type OptionTargetTTL func(*TargetTTL)

func WithTargetTTLSet(value int) OptionTargetTTL {
	return func(tTTL *TargetTTL) {
		tTTL.Value = value
		tTTL.Operator = xtables.OperatorSET
	}
}

func WithTargetTTLDec(value int) OptionTargetTTL {
	return func(tTTL *TargetTTL) {
		tTTL.Value = value
		tTTL.Operator = xtables.OperatorDEC
	}
}

func WithTargetTTLInc(value int) OptionTargetTTL {
	return func(tTTL *TargetTTL) {
		tTTL.Value = value
		tTTL.Operator = xtables.OperatorINC
	}
}

func newTargetTTL(opts ...OptionTargetTTL) (*TargetTTL, error) {
	target := &TargetTTL{
		baseTarget: &baseTarget{
			targetType: TargetTypeTTL,
		},
		Value: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

// IPv4 specific
type TargetTTL struct {
	*baseTarget
	Operator xtables.Operator
	Value    int
}

func (tTTL *TargetTTL) Short() string {
	return strings.Join(tTTL.ShortArgs(), " ")
}

func (tTTL *TargetTTL) ShortArgs() []string {
	args := make([]string, 0, 4)
	args = append(args, "-j", tTTL.targetType.String())
	switch tTTL.Operator {
	case xtables.OperatorSET:
		args = append(args, "--ttl-set", strconv.Itoa(tTTL.Value))
	case xtables.OperatorDEC:
		args = append(args, "--ttl-dec", strconv.Itoa(tTTL.Value))
	case xtables.OperatorINC:
		args = append(args, "--ttl-inc", strconv.Itoa(tTTL.Value))
	}
	return args
}

func (tTTL *TargetTTL) Long() string {
	return tTTL.Short()
}

func (tTTL *TargetTTL) LongArgs() []string {
	return tTTL.ShortArgs()
}

func (tTTL *TargetTTL) Parse(main []byte) (int, bool) {
	// 1. "^TTL "
	// 2. "(set to|decrement by|increment by)"
	// 3. "([0-9]+)"
	pattern := `^TTL` +
		` (set to|decrement by|increment by)` +
		` ([0-9]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 3 {
		return 0, false
	}
	switch string(matches[1]) {
	case "set to":
		tTTL.Operator = xtables.OperatorSET
	case "decrement to":
		tTTL.Operator = xtables.OperatorDEC
	case "increment to":
		tTTL.Operator = xtables.OperatorINC
	}
	ttl, err := strconv.Atoi(string(matches[2]))
	if err != nil {
		return 0, false
	}
	tTTL.Value = ttl
	return len(matches[0]), true
}

type OptionTargetULog func(*TargetULog)

// This specifies the netlink group (1-32) to which the packet is sent.
// Default value is 1.
func WithTargetULogNetlinkGroup(group int) OptionTargetULog {
	return func(tULog *TargetULog) {
		tULog.NetlinkGroup = group
	}
}

// Prefix log messages with the specified prefix; up to 32 characters long,
// and useful for distinguishing messages in the logs.
func WithTargetULogPrefix(prefix string) OptionTargetULog {
	return func(tULog *TargetULog) {
		tULog.Prefix = prefix
	}
}

// Number of bytes to be copied to userspace.
// A value of 0 always copies the entire packet,
// regardless of its size.  Default is 0.
func WithTargetULogCopyRange(rg int) OptionTargetULog {
	return func(tULog *TargetULog) {
		tULog.CopyRange = rg
	}
}

// Number of packet to queue inside kernel.
func WithTargetULogQueueThreshold(threshold int) OptionTargetULog {
	return func(tULog *TargetULog) {
		tULog.QueueThreshold = threshold
	}
}

func newTargetULog(opts ...OptionTargetULog) (*TargetULog, error) {
	target := &TargetULog{
		baseTarget: &baseTarget{
			targetType: TargetTypeULog,
		},
		NetlinkGroup:   -1,
		CopyRange:      -1,
		QueueThreshold: -1,
	}
	for _, opt := range opts {
		opt(target)
	}
	target.setChild(target)
	return target, nil
}

// TODO untested in the real world
// IPv4 specific
// Deprecated
type TargetULog struct {
	*baseTarget
	NetlinkGroup   int
	Prefix         string
	CopyRange      int
	QueueThreshold int
}

func (tULog *TargetULog) Short() string {
	return strings.Join(tULog.ShortArgs(), " ")
}

func (tULog *TargetULog) ShortArgs() []string {
	args := make([]string, 0, 10)
	args = append(args, "-j", tULog.targetType.String())
	if tULog.NetlinkGroup > -1 {
		args = append(args, "--ulog-nlgroup", strconv.Itoa(tULog.NetlinkGroup))
	}
	if tULog.Prefix != "" {
		args = append(args, "--ulog-prefix", tULog.Prefix)
	}
	if tULog.CopyRange > -1 {
		args = append(args, "--ulog-cprange", strconv.Itoa(tULog.CopyRange))
	}
	if tULog.QueueThreshold > -1 {
		args = append(args, "--ulog-qthreshold", strconv.Itoa(tULog.QueueThreshold))
	}
	return args
}

func (tULog *TargetULog) Long() string {
	return tULog.Short()
}

func (tULog *TargetULog) LongArgs() []string {
	return tULog.ShortArgs()
}

func (tULog *TargetULog) Parse(main []byte) (int, bool) {
	// 1. "^ULOG"
	// 2. " copy_range ([0-9]+) nlgroup ([0-9]+)"
	// 3. "( prefix "([!-~]+)")?"
	// 4. " queue_threshold ([0-9]+)"
	pattern := `^ULOG` +
		` copy_range ([0-9]+) nlgroup ([0-9]+)` +
		`( prefix "([!-~]+)")?` +
		` queue_threshold ([0-9]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(main)
	if len(matches) != 6 {
		return 0, false
	}
	// range
	rg, err := strconv.Atoi(string(matches[1]))
	if err != nil {
		return 0, false
	}
	tULog.CopyRange = rg
	// group
	group, err := strconv.Atoi(string(matches[2]))
	if err != nil {
		return 0, false
	}
	tULog.NetlinkGroup = group
	// prefix
	if len(matches[4]) != 0 {
		str := string(matches[4])
		str = strings.ReplaceAll(str, `\\`, `\`)
		tULog.Prefix = strings.ReplaceAll(str, `\"`, `"`)
	}
	// threshold
	threshold, err := strconv.Atoi(string(matches[5]))
	if err != nil {
		return 0, false
	}
	tULog.QueueThreshold = threshold
	return len(matches[0]), true
}
