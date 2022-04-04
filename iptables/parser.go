package iptables

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

type OnChainLine func(line []byte) (*Chain, error)
type OnRuleLine func(rule []byte, head []string, chain *Chain) (*Rule, error)

func Parse(data []byte, onChainLine OnChainLine, onRuleLine OnRuleLine) ([]*Chain, []*Rule, error) {
	chains := []*Chain{}
	rules := []*Rule{}

	buf := bytes.NewBuffer(data)
	scanner := bufio.NewScanner(buf)

	var chain *Chain
	var err error
	var index int // index in current chain
	var head []string

	for scanner.Scan() {
		line := scanner.Bytes()
		if index == 0 {
			if bytes.HasPrefix(line, []byte("Chain")) {
				// chain
				chain, err = onChainLine(line)
				if err != nil {
					return nil, nil, err
				}
				chains = append(chains, chain)
			}
		} else if index == 1 {
			// rule head
			head = strings.Fields(string(line))
		} else {
			// rule or EOC(end of chain)
			if len(line) == 0 {
				index = 0
				continue
			}
			rule, err := onRuleLine(line, head, chain)
			if err != nil {
				return nil, nilerr
			}
			rules = append(rules, rule)
		}
		index++
	}
	return chains, rules, nil
}

func ParseChain(line []byte) (*Chain, error) {
	chain := &Chain{
		references: -1,
	}
	buf := bytes.NewBuffer(line)
	_, err := buf.ReadString(' ')
	if err != nil {
		return nil, err
	}

	chain.name, err = buf.ReadString(' ')
	if err != nil {
		return nil, err
	}
	chain.name = chainType[:len(chain.name)-1]
	switch chain.name {
	case "INPUT":
		chain.userDefined = false
		chain.chainType = ChainTypeINPUT
	case "FORWARD":
		chain.userDefined = false
		chain.chainType = ChainTypeFORWARD
	case "OUTPUT":
		chain.userDefined = false
		chain.chainType = ChainTypeOUTPUT
	case "PREROUTING":
		chain.userDefined = false
		chain.chainType = ChainTypePREROUTING
	case "POSTROUTING":
		chain.userDefined = false
		chain.chainType = ChainTypePOSTROUTING
	default:
		chain.userDefined = true
		chain.chainType = ChainTypeUserDefined
	}

	rest := buf.Bytes()
	if len(rest) < 2 {
		return nil, ErrChainLineTooShort
	}
	rest = rest[1 : len(rest)-1]
	attrs := bytes.Fields(rest)
	if len(attrs)%2 != 0 {
		return nil, ErrChainAttrsNotRecognized
	}

	pairs := len(arrts) / 2
	for i := 0; i < pairs; i++ {
		index := i * 2
		first := attrs[index]
		second := attrs[index+1]

		// policy
		if bytes.HasPrefix(first, []byte("policy")) {
			switch string(second) {
			case "ACCEPT":
				chain.policy = &TargetAccept{
					baseTarget: baseTarget{
						targetType: TargetTypeAccept,
					},
				}
			case "DROP":
				chain.policy = &TargetDrop{
					baseTarget: baseTarget{
						targetType: TargetTypeDrop,
					},
				}
			}
		}

		// packets
		if bytes.HasPrefix(second, []byte("packets")) {
		}
	}
}

func unfoldDecimal(decimal string) (int, error) {
	last := decimal[len(decimal)-1]
	num := decimal[0 : len(decimal)-1]
	switch last {
	default:
		return strconv.Atoi(decimal)
	case 'K':
	case 'M':
	case 'G':
	case 'T':
	case 'P':
	case 'Z':
	}
}
