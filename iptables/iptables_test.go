package iptables

import (
	"testing"
)

func TestIptables(t *testing.T) {
	iptables := NewIPTables()
	err := iptables.
		Table(TableTypeFilter).
		Chain(ChainTypeINPUT).
		OptionFragment(true).
		MatchIPv4().
		TargetAccetp().Insert(0)
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
		Table(TableTypeFilter).
		Chain(ChainTypeINPUT).
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
