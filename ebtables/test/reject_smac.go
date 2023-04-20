package main

import (
	"fmt"

	"github.com/singchia/go-xtables/ebtables"
)

func RejectSMAC() {
	set()
	defer unset()

	err := ebtables.NewEBTables().
		Table(ebtables.TableTypeFilter).
		Chain(ebtables.ChainTypeINPUT).
		MatchSource(false, "00:11:22:33:44:55").
		TargetDrop().
		Append()
	fmt.Println(err)
}
