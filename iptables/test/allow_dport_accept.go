package main

import (
	"fmt"

	"github.com/singchia/go-xtables/iptables"
	"github.com/singchia/go-xtables/pkg/network"
)

func AllowDPortAccept() {
	set()
	defer unset()

	err := iptables.NewIPTables().
		Table(iptables.TableTypeFilter).
		Chain(iptables.ChainTypeINPUT).
		MatchProtocol(false, network.ProtocolTCP).
		MatchTCP(iptables.WithMatchTCPDstPort(false, 2432)).
		TargetDrop().
		Append()
	fmt.Println(err)
}
