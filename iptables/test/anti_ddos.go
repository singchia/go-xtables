package main

import (
	"github.com/singchia/go-xtables"
	"github.com/singchia/go-xtables/iptables"
	"github.com/singchia/go-xtables/pkg/network"
)

func AntiDDOS() {
	set()
	defer unset()

	custom := "SYN_FLOOD"
	ipt := iptables.NewIPTables().Table(iptables.TableTypeFilter)
	ipt.NewChain(custom)
	ipt.Chain(iptables.ChainTypeINPUT).
		MatchProtocol(false, network.ProtocolTCP).
		MatchTCP(iptables.WithMatchTCPSYN(false)).
		TargetJumpChain(custom).
		Append()

	userDefined := iptables.ChainTypeUserDefined
	userDefined.SetName(custom)
	rate := xtables.Rate{1, xtables.Second}
	ipt.Chain(userDefined).
		MatchLimit(
			iptables.WithMatchLimit(rate),
			iptables.WithMatchLimitBurst(3)).
		TargetReturn().
		Append()
	ipt.Chain(userDefined).
		TargetDrop().
		Append()
}
