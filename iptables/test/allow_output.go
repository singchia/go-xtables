package main

import (
	"github.com/singchia/go-xtables/iptables"
	"github.com/singchia/go-xtables/pkg/network"
)

func main() {
	set()
	defer unset()

	ipt := iptables.NewIPTables().Table(iptables.TableTypeFilter)
	ipt.Chain(iptables.ChainTypeINPUT).
		MatchInInterface(false, "lo").
		TargetAccept().
		Append()
	ipt.Chain(iptables.ChainTypeINPUT).
		MatchState(iptables.ESTABLISHED | iptables.RELATED).
		TargetAccept().
		Append()
	ipt.Chain(iptables.ChainTypeINPUT).
		MatchProtocol(false, network.ProtocolTCP).
		MatchTCP(iptables.WithMatchTCPDstPort(false, 22)).
		TargetAccept().
		Append()
	ipt.Chain(iptables.ChainTypeINPUT).Policy(iptables.TargetTypeDrop)
	ipt.Chain(iptables.ChainTypeFORWARD).Policy(iptables.TargetTypeDrop)
	ipt.Chain(iptables.ChainTypeOUTPUT).Policy(iptables.TargetTypeAccept)
}
