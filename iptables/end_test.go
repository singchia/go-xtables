package iptables

import (
	"os"
	"runtime"
	"testing"

	"bou.ke/monkey"
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

func initIPTables(t *testing.T) {
	err := NewIPTables().Flush()
	assert.Equal(t, nil, err)

	err = NewIPTables().DeleteChain()
	assert.Equal(t, nil, err)

	err = NewIPTables().Policy(TargetTypeAccept)
	assert.Equal(t, nil, err)
}

func TestFlush(t *testing.T) {
	set()
	defer unset()

	err := NewIPTables().Flush()
	assert.Equal(t, nil, err)
}

func TestNewChain(t *testing.T) {
	set()
	defer unset()

	iptables := NewIPTables().Table(TableTypeFilter)

	chainName := "AustinZhai"
	err := iptables.NewChain(chainName)
	assert.Equal(t, nil, err)

	userDefined := ChainTypeUserDefined
	userDefined.name = chainName
	chains, err := iptables.Chain(userDefined).FindChains()
	assert.Equal(t, nil, err)
	assert.Equal(t, 1, len(chains))
}

func TestDeleteChain(t *testing.T) {
	set()
	defer unset()

	iptables := NewIPTables().Table(TableTypeFilter)

	chainName := "AustinZhai2"
	err := iptables.NewChain(chainName)
	assert.Equal(t, nil, err)

	userDefined := ChainTypeUserDefined
	userDefined.name = chainName
	err = iptables.Chain(userDefined).DeleteChain()
	assert.Equal(t, nil, err)

	chains, err := iptables.Chain(userDefined).FindChains()
	assert.Equal(t, nil, err)
	assert.Equal(t, 0, len(chains))
}

func TestAppend(t *testing.T) {
	set()
	defer unset()

	iptables := NewIPTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchIPv4().
		MatchProtocol(false, network.ProtocolTCP).
		MatchTCP(WithMatchTCPDstPort(false, 2432)).
		TargetDNAT(WithTargetDNATToAddr(network.ParseIP("192.168.100.230"), 2433))

	err := iptables.Append()
	assert.Equal(t, nil, err)

	rules, err := iptables.FindRules()
	assert.Equal(t, nil, err)
	assert.Greater(t, len(rules), 0)
}

func TestCheck(t *testing.T) {
	set()
	defer unset()

	iptables := NewIPTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchIPv4().
		MatchProtocol(false, network.ProtocolTCP).
		MatchTCP(WithMatchTCPDstPort(false, 2432)).
		TargetDNAT(WithTargetDNATToAddr(network.ParseIP("192.168.100.230"), 2433))

	err := iptables.Append()
	assert.Equal(t, nil, err)

	ok, err := iptables.Check()
	assert.Equal(t, nil, err)
	assert.Equal(t, true, ok)
}

func TestDelete(t *testing.T) {
	set()
	defer unset()

	iptables := NewIPTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchIPv4().
		TargetAccept()

	err := iptables.Insert(1)
	assert.Equal(t, nil, err)

	err = iptables.Delete(1)
	assert.Equal(t, nil, err)
}

func TestInsert(t *testing.T) {
	set()
	defer unset()

	err := NewIPTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchIPv4().
		TargetAccept().
		Insert(1)
	assert.Equal(t, nil, err)

	ok, err := NewIPTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchIPv4().
		TargetAccept().
		Check()
	assert.Equal(t, true, ok)
	assert.Equal(t, nil, err)
}

func TestReplace(t *testing.T) {
	set()
	defer unset()

	err := NewIPTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchIPv4().
		TargetAccept().
		Insert(1)
	assert.Equal(t, nil, err)

	err = NewIPTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchIPv4().
		MatchProtocol(false, network.ProtocolTCP).
		TargetAccept().
		Replace(1)
	assert.Equal(t, nil, err)

	ok, err := NewIPTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchIPv4().
		TargetAccept().
		Check()
	assert.NotEqual(t, true, ok)
	assert.NotEqual(t, nil, err)

	ok, err = NewIPTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchIPv4().
		MatchProtocol(false, network.ProtocolTCP).
		TargetAccept().
		Check()
	assert.Equal(t, true, ok)
	assert.Equal(t, nil, err)
}

func TestListRules(t *testing.T) {
	set()
	defer unset()

	err := NewIPTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchIPv4().
		TargetAccept().
		Insert(1)
	assert.Equal(t, nil, err)

	rules, err := NewIPTables().Table(TableTypeNat).ListRules()
	assert.Equal(t, nil, err)
	assert.Len(t, rules, 1)
	assert.Equal(t, TableTypeNat, rules[0].Table())
	assert.Equal(t, ChainTypePREROUTING, rules[0].Chain())
	assert.Equal(t, TargetTypeAccept, rules[0].Target().Type())
}

func TestDumpRules(t *testing.T) {
	set()
	defer unset()

	rules := []string{"-P INPUT ACCEPT"}
	data, err := NewIPTables().Table(TableTypeFilter).Chain(ChainTypeINPUT).ListRules()
	assert.Equal(t, nil, err)
	assert.Equal(t, rules, data)

	rules = []string{"-P INPUT ACCEPT", "-P FORWARD ACCEPT", "-P OUTPUT ACCEPT"}
	data, err = NewIPTables().Table(TableTypeFilter).ListRules()
	assert.Equal(t, nil, err)
	assert.Equal(t, rules, data)
}

func TestFind(t *testing.T) {
	set()
	defer unset()
}
