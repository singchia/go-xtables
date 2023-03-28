package ebtables

import (
	"net"
	"os"
	"runtime"
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

func TestDump(t *testing.T) {
	set()
	defer unset()

	NewEBTables().Table(TableTypeFilter).Dump()
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

	err := NewEBTables().
		Table(TableTypeFilter).
		Chain(ChainTypeOUTPUT).
		MatchProtocol(false, network.EthernetTypeIPv6).
		MatchIPv6(WithMatchIPv6Destination(false, network.NewIP(dip))).
		TargetAccept().
		DeleteAll()

	err = NewEBTables().
		Table(TableTypeFilter).
		Chain(ChainTypeOUTPUT).
		MatchProtocol(false, network.EthernetTypeIPv6).
		MatchIPv6(WithMatchIPv6Destination(false, network.NewIP(dip))).
		TargetAccept().
		OptionCounters(0, 0).
		Insert()
	assert.Equal(t, nil, err)

	err = NewEBTables().
		Table(TableTypeFilter).
		Chain(ChainTypeOUTPUT).
		MatchProtocol(false, network.EthernetTypeIPv6).
		MatchIPv6(WithMatchIPv6Destination(false, network.NewIP(dip))).
		TargetAccept().
		ChangeCounters(WithCommandChangeCountersByteCount(1024, xtables.OperatorNull),
			WithCommandChangeCountersPacketCount(1024, xtables.OperatorNull))
	assert.Equal(t, nil, err)

	rules, err := NewEBTables().
		Table(TableTypeFilter).
		Chain(ChainTypeOUTPUT).
		MatchProtocol(false, network.EthernetTypeIPv6).
		MatchIPv6(WithMatchIPv6Destination(false, network.NewIP(dip))).
		OptionCounters(1024, 1024).
		TargetAccept().
		FindRules()
	assert.Equal(t, nil, err)
	assert.Equal(t, 1, len(rules))
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

	for i := 0; i < 10; i++ {
		err = NewEBTables().Table(TableTypeNat).
			Chain(ChainTypePREROUTING).
			MatchProtocol(false, network.EthernetTypeIPv4).
			MatchIP(WithMatchIPSource(false, network.NewIP(sip))).
			TargetAccept().
			Insert()
		assert.Equal(t, nil, err)
	}

	err = NewEBTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchProtocol(false, network.EthernetTypeIPv4).
		MatchIP(WithMatchIPSource(false, network.NewIP(sip))).
		TargetAccept().
		DeleteAll()
	assert.Equal(t, nil, err)

	rules, err := NewEBTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchProtocol(false, network.EthernetTypeIPv4).
		MatchIP(WithMatchIPSource(false, network.NewIP(sip))).
		TargetAccept().
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
