package iptables

import (
	"testing"
)

func TestIptables(t *testing.T) {
	iptables := NewIPTables()
	err := iptables.
		TableType(TableTypeFilter).
		ChainType(ChainTypeINPUT).
		OptionFragment(true).
		MatchIPv4().
		TargetAccept().Insert(0)
	if err != nil {
		t.Error(err)
		return
	}

	str, err := iptables.statement.String()
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(str)
}

func TestList(t *testing.T) {
	iptables := NewIPTables()
	err := iptables.
		TableType(TableTypeFilter).
		ChainType(ChainTypeINPUT).
		List()
	if err != nil {
		t.Error(err)
		return
	}

	str, err := iptables.statement.String()
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(str)
}

func TestChain(t *testing.T) {
	iptables := NewIPTables()
	_, err := iptables.
		TableType(TableTypeFilter).
		Chain(ChainTypeINPUT)
	if err != nil {
		t.Error(err)
		return
	}
}
