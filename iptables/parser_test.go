package iptables

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/singchia/go-xtables/internal/xutil"
)

func TestUnfoldDecimal(t *testing.T) {
	test := []string{
		"12",
		"34K",
		"56M",
		"78G",
		"910T",
		"1011P",
		"1112Z",
	}
	for _, elem := range test {
		num, err := xutil.UnfoldDecimal(elem)
		if err != nil {
			t.Error(err)
			return
		}
		t.Log(num)
	}

	test = []string{
		"1a2",
		"foo",
	}
	for _, elem := range test {
		num, err := xutil.UnfoldDecimal(elem)
		if err == nil {
			t.Error("err")
			return
		}
		t.Log(num)
	}
}

func TestParseChain(t *testing.T) {
	data, err := ioutil.ReadFile("../test/stdout/list_iptables_filter")
	if err != nil {
		t.Error(err)
		return
	}
	buf := bytes.NewBuffer(data)
	scanner := bufio.NewScanner(buf)

	for scanner.Scan() {
		line := scanner.Bytes()
		if bytes.HasPrefix(line, []byte("Chain")) {
			chain, err := ParseChain(line)
			if err != nil {
				t.Error(err)
				return
			}
			t.Log(chain.chainType, chain.userDefined, chain.name,
				chain.references, chain.policy, chain.packets, chain.bytes)
		}
	}
}
