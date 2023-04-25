package main

import (
	"fmt"

	"github.com/singchia/go-xtables/iptables"
)

func AllowSIPAccept() {
	set()
	defer unset()

	err := iptables.NewIPTables().
		Table(iptables.TableTypeFilter).
		Chain(iptables.ChainTypeINPUT).
		MatchSource(false, "192.168.1.100").
		TargetAccept().
		Append()
	fmt.Println(err)
}
