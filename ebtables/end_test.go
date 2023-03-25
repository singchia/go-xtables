package ebtables

import (
	"net"
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

func initEBTables(t *testing.T) {
	err := NewEBTables().Flush()
	assert.Equal(t, nil, err)

	err = NewEBTables().DeleteChain()
	assert.Equal(t, nil, err)

	err = NewEBTables().Policy(TargetTypeAccept)
	assert.Equal(t, nil, err)
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

func TestDelete(t *testing.T) {
	set()
	defer unset()
	initEBTables(t)

	sip := net.ParseIP("192.168.0.2")

	err := NewEBTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchProtocol(false, network.EthernetTypeIPv4).
		MatchIP(WithMatchIPSource(false, network.NewIP(sip))).
		TargetAccept().
		Insert(1)
	assert.Equal(t, nil, err)

	err = NewEBTables().Table(TableTypeNat).
		Chain(ChainTypePREROUTING).
		MatchProtocol(false, network.EthernetTypeIPv4).
		MatchIP(WithMatchIPSource(false, network.NewIP(sip))).
		TargetAccept().
		Delete(0)
	assert.Equal(t, nil, err)
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
		Insert(1)
	assert.Equal(t, nil, err)
}
