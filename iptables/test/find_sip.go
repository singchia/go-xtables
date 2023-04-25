package main

import (
	"fmt"

	"github.com/singchia/go-xtables/iptables"
)

func FindSIP() {
	set()
	defer unset()

	rules, err := iptables.NewIPTables().
		Table(iptables.TableTypeFilter).
		Chain(iptables.ChainTypeINPUT).
		MatchSource(false, "192.168.1.100").
		TargetAccept().
		FindRules()
	fmt.Println(len(rules), err)
}
