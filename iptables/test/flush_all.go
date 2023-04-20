package main

import (
	"fmt"

	"github.com/singchia/go-xtables/iptables"
)

func main() {
	set()
	defer unset()

	err := iptables.NewIPTables().Flush()
	fmt.Println(err)
}
