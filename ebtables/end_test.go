package ebtables

import (
	"net"
	"os"
	"runtime"
	"strings"
	"testing"

	"bou.ke/monkey"
	"github.com/singchia/go-xtables"
	"github.com/singchia/go-xtables/pkg/cmd"
	"github.com/singchia/go-xtables/pkg/network"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netns"
)

var (
	originns netns.NsHandle
	newns    netns.NsHandle
)

func set() {
	sandboxAddr := os.Getenv("SANDBOX_ADDR")
	if sandboxAddr != "" {
		sandboxUser := os.Getenv("SANDBOX_USER")
		sandboxPassword := os.Getenv("SANDBOX_PASSWORD")

		monkey.Patch(cmd.Cmd, func(name string, arg ...string) ([]byte, []byte, error) {
			return cmd.SSHCmdPassword(sandboxAddr, sandboxUser, sandboxPassword,
				name, arg...)
		})
	} else {
		runtime.LockOSThread()
		originns, _ = netns.Get()
		newns, _ = netns.New()
	}
}

func unset() {
	sandboxAddr := os.Getenv("SANDBOX_ADDR")
	if sandboxAddr != "" {
		monkey.UnpatchAll()
	} else {
		runtime.UnlockOSThread()
		newns.Close()
		originns.Close()
	}
}

func initEBTables(t *testing.T) {
	err := NewEBTables().Flush()
	assert.Equal(t, nil, err)

	err = NewEBTables().DeleteChain()
	assert.Equal(t, nil, err)

	err = NewEBTables().Policy(TargetTypeAccept)
	assert.Equal(t, nil, err)
}

func TestFlush(t *testing.T) {
	set()
	defer unset()

	err := NewEBTables().Flush()
	assert.Equal(t, nil, err)
}

func TestListRules(t *testing.T) {
	set()
	defer unset()

	err := NewEBTables().Flush()
	assert.Equal(t, nil, err)

	rules, err := NewEBTables().Table(TableTypeFilter).ListRules()
	assert.Equal(t, nil, err)
	assert.Equal(t, 0, len(rules))
}

func TestListChains(t *testing.T) {
	set()
	defer unset()

	err := NewEBTables().Flush()
	assert.Equal(t, nil, err)

	chains, err := NewEBTables().Table(TableTypeFilter).ListChains()
	assert.Equal(t, nil, err)
	assert.Equal(t, 3, len(chains))
}

func TestAppend(t *testing.T) {
	set()
	defer unset()
	initEBTables(t)

	err := NewEBTables().Table(TableTypeFilter).
		Chain(ChainTypeINPUT).
		MatchProtocol(false, network.EthernetTypeARP).
		MatchARP(WithMatchARPOpCode(false, network.ARPOpCodeInARPRequest)).
		TargetAccept().
		Append()
	assert.Equal(t, nil, err)
}

func TestChangeCounters(t *testing.T) {
	set()
	defer unset()

	dip := net.ParseIP("2001:db8:3333:4444:5555:6666:7777:8888")

	ebtables := NewEBTables().
		Table(TableTypeFilter).
		Chain(ChainTypeOUTPUT).
		MatchProtocol(false, network.EthernetTypeIPv6).
		MatchIPv6(WithMatchIPv6Destination(false, network.NewIP(dip))).
		TargetAccept()

	err := ebtables.
		DeleteAll()

	err = ebtables.
		OptionCounters(0, 0).
		Insert()
	assert.Equal(t, nil, err)

	err = ebtables.
		ChangeCounters(WithCommandChangeCountersByteCount(1024, xtables.OperatorNull),
			WithCommandChangeCountersPacketCount(1024, xtables.OperatorNull))
	assert.Equal(t, nil, err)

	rules, err := ebtables.
		OptionCounters(1024, 1024).
		FindRules()
	assert.Equal(t, nil, err)
	assert.Equal(t, 1, len(rules))
}

func BenchmarkChangeCounters(b *testing.B) {
	dip := net.ParseIP("2001:db8:3333:4444:5555:6666:7777:8888")

	ebtables := NewEBTables().
		Table(TableTypeFilter).
		Chain(ChainTypeOUTPUT).
		MatchProtocol(false, network.EthernetTypeIPv6).
		MatchIPv6(WithMatchIPv6Destination(false, network.NewIP(dip))).
		TargetAccept()
	for i := 0; i < b.N; i++ {
		ebtables.MatchLogicalIn(false, "eth0")
	}
}

func TestDelete(t *testing.T) {
	set()
	defer unset()

	sip := net.ParseIP("192.168.0.2")

	err := NewEBTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchProtocol(false, network.EthernetTypeIPv4).
		MatchIP(WithMatchIPSource(false, network.NewIP(sip))).
		TargetAccept().
		Insert()
	assert.Equal(t, nil, err)

	err = NewEBTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchProtocol(false, network.EthernetTypeIPv4).
		MatchIP(WithMatchIPSource(false, network.NewIP(sip))).
		TargetAccept().
		Delete()
	assert.Equal(t, nil, err)
}

func TestDeleteAll(t *testing.T) {
	set()
	defer unset()

	var err error
	sip := net.ParseIP("192.168.0.2")

	iptables := NewEBTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchProtocol(false, network.EthernetTypeIPv4).
		MatchIP(WithMatchIPSource(false, network.NewIP(sip))).
		TargetAccept()

	for i := 0; i < 10; i++ {
		err = iptables.
			Insert()
		assert.Equal(t, nil, err)
	}

	err = iptables.
		DeleteAll()
	assert.Equal(t, nil, err)

	rules, err := iptables.
		FindRules()
	assert.Equal(t, nil, err)
	assert.Equal(t, 0, len(rules))
}

func TestInsert(t *testing.T) {
	set()
	defer unset()

	sip := net.ParseIP("192.168.0.1")

	err := NewEBTables().Table(TableTypeFilter).
		Chain(ChainTypeINPUT).
		MatchProtocol(false, network.EthernetTypeIPv4).
		MatchIP(WithMatchIPSource(false, network.NewIP(sip))).
		TargetAccept().
		Insert()
	assert.Equal(t, nil, err)
}

func TestPolicy(t *testing.T) {
	set()
	defer unset()

	err := NewEBTables().
		Table(TableTypeFilter).
		Chain(ChainTypeFORWARD).
		Policy(TargetTypeDrop)
	assert.Equal(t, nil, err)

	chains, err := NewEBTables().
		Table(TableTypeFilter).
		Chain(ChainTypeFORWARD).
		FindChains()
	assert.Equal(t, nil, err)
	assert.Equal(t, 1, len(chains))
	//assert.Equal(t, TargetTypeDrop, chains[0].policy.Type())
}

func TestZero(t *testing.T) {
	set()
	defer unset()

	err := NewEBTables().
		Table(TableTypeFilter).
		Chain(ChainTypeOUTPUT).Zero()
	assert.Equal(t, nil, err)

	rules, err := NewEBTables().Table(TableTypeFilter).Chain(ChainTypeOUTPUT).FindRules()
	assert.Equal(t, nil, err)

	for _, rule := range rules {
		assert.Equal(t, int64(0), rule.packetCounter)
		assert.Equal(t, int64(0), rule.byteCounter)
	}
}

func TestDump(t *testing.T) {
	set()
	defer unset()

	rules, err := NewEBTables().Table(TableTypeFilter).Dump()
	assert.Equal(t, nil, err)
	t.Log(strings.Join(rules, "; "))
}

func TestNewChain(t *testing.T) {
	set()
	defer unset()

	err := NewEBTables().Table(TableTypeFilter).NewChain("AustinZhai")
	assert.Equal(t, nil, err)

	userDefined := ChainTypeUserDefined
	userDefined.name = "AustinZhai"
	chains, err := NewEBTables().Table(TableTypeFilter).Chain(userDefined).FindChains()
	assert.Equal(t, nil, err)
	assert.Equal(t, 1, len(chains))
}

func TestDeleteChain(t *testing.T) {
	set()
	defer unset()

	chainName := "AustinZhai2"

	err := NewEBTables().Table(TableTypeFilter).NewChain(chainName)
	assert.Equal(t, nil, err)

	userDefined := ChainTypeUserDefined
	userDefined.name = chainName
	err = NewEBTables().Table(TableTypeFilter).Chain(userDefined).DeleteChain()
	assert.Equal(t, nil, err)

	chains, err := NewEBTables().Table(TableTypeFilter).Chain(userDefined).FindChains()
	assert.Equal(t, nil, err)
	assert.Equal(t, 0, len(chains))
}

func TestRenameChain(t *testing.T) {
	set()
	defer unset()

	chainName := "AustinZhai3"
	chainNameNew := "AustinZhai4"
	err := NewEBTables().Table(TableTypeFilter).NewChain(chainName)
	assert.Equal(t, nil, err)

	userDefinedOld := ChainTypeUserDefined
	userDefinedOld.name = chainName
	err = NewEBTables().Table(TableTypeFilter).Chain(userDefinedOld).RenameChain(chainNameNew)
	assert.Equal(t, nil, err)

	userDefinedNew := ChainTypeUserDefined
	userDefinedNew.name = chainNameNew
	chains, err := NewEBTables().Table(TableTypeFilter).Chain(userDefinedNew).FindChains()
	assert.Equal(t, nil, err)
	assert.Equal(t, 1, len(chains))
}

func TestInitTable(t *testing.T) {
	set()
	defer unset()

	err := NewEBTables().Table(TableTypeFilter).InitTable()
	assert.Equal(t, nil, err)

	rules, err := NewEBTables().Table(TableTypeFilter).FindRules()
	assert.Equal(t, nil, err)
	assert.Equal(t, 0, len(rules))
}

func TestAtomicInit(t *testing.T) {
	set()
	defer unset()

	err := NewEBTables().Table(TableTypeFilter).OptionAtomicFile("~/ebtable.init").
		AtomicInit()
	assert.Equal(t, nil, err)
}

func TestAtomicSave(t *testing.T) {
	set()
	defer unset()

	err := NewEBTables().Table(TableTypeFilter).OptionAtomicFile("~/ebtable.save").
		AtomicSave()
	assert.Equal(t, nil, err)
}

func TestAtomicCommit(t *testing.T) {
	set()
	defer unset()

	sip := net.ParseIP("192.168.0.1")

	err := NewEBTables().Table(TableTypeFilter).
		Chain(ChainTypeINPUT).
		MatchProtocol(false, network.EthernetTypeIPv4).
		MatchIP(WithMatchIPSource(false, network.NewIP(sip))).
		TargetAccept().
		Insert()
	assert.Equal(t, nil, err)

	err = NewEBTables().Table(TableTypeFilter).OptionAtomicFile("~/ebtable.save").
		AtomicSave()
	assert.Equal(t, nil, err)

	err = NewEBTables().Table(TableTypeFilter).InitTable()
	assert.Equal(t, nil, err)

	err = NewEBTables().Table(TableTypeFilter).OptionAtomicFile("~/ebtable.save").
		AtomicCommit()
	assert.Equal(t, nil, err)

	rules, err := NewEBTables().Table(TableTypeFilter).
		Chain(ChainTypeINPUT).
		MatchProtocol(false, network.EthernetTypeIPv4).
		MatchIP(WithMatchIPSource(false, network.NewIP(sip))).
		TargetAccept().
		FindRules()
	assert.Equal(t, nil, err)
	assert.Equal(t, 1, len(rules))
}

func TestDryrun(t *testing.T) {
	set()
	defer unset()

	err := NewEBTables().Dryrun(os.Stdout).Policy(TargetTypeAccept)
	assert.Equal(t, nil, err)
}
