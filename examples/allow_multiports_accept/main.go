package main

import (
	"log"

	"github.com/singchia/go-xtables/iptables"
	"github.com/singchia/go-xtables/pkg/network"
)

func main() {
	ipt := iptables.NewIPTables().
		Table(iptables.TableTypeFilter).
		Chain(iptables.ChainTypeINPUT).
		MatchProtocol(false, network.ProtocolTCP)

	// allow ssh, http and https
	err := ipt.MatchMultiPort(
		iptables.WithMatchMultiPortDstPorts(false, 22, 80, 443)).
		TargetAccept().Insert()
	if err != nil {
		log.Fatal(err)
		return
	}
	// drop others
	err = iptables.NewIPTables().Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeINPUT).Policy(iptables.TargetTypeDrop)
	if err != nil {
		log.Fatal(err)
		return
	}
}
