package iptables

import (
	"fmt"
	"testing"
)

func TestNFields(t *testing.T) {
	line := "ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED"
	fields, index := NFields([]byte(line), 5)
	fmt.Printf("%v, %v", fields, line[index:])
}
