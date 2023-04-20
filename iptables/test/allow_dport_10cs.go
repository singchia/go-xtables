package main

import (
	"fmt"

	"github.com/singchia/go-xtables"
	"github.com/singchia/go-xtables/iptables"
	"github.com/singchia/go-xtables/pkg/network"
)

func AllowDPort10CS() {
	set()
	defer unset()

	err := iptables.NewIPTables().
		Table(iptables.TableTypeFilter).
		Chain(iptables.ChainTypeINPUT).
		MatchProtocol(false, network.ProtocolTCP).
		MatchTCP(iptables.WithMatchTCPDstPort(false, 80)).
		MatchLimit(iptables.WithMatchLimit(xtables.Rate{Rate: 10, Unit: xtables.Minute})).
		TargetAccept().
		Append()
	fmt.Println(err)
}
