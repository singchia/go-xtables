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
				return nil, nil, err
			}
			rules = append(rules, rule)
		}
		index++
	}
	return chains, rules, nil
}

func ParseRule(line []byte, head []string, chain *Chain) (*Rule, error) {
	rule := &Rule{
		chain:   chain,
		packets: -1,
		bytes:   -1,
	}
	fields, index := NFields(line, len(head))
	for i, name := range head {
		field := string(fields[i])
		switch name {
		case "pkts":
			num, err := unfoldDecimal(field)
			if err != nil {
				return nil, err
			}
			rule.packets = num
		case "bytes":
			num, err := unfoldDecimal(field)
			if err != nil {
				return nil, err
			}
			rule.bytes = num
		case "target":
			value, ok := TargetValueType[field]
			if !ok {
				// user defined chain, wait to see concrete details
				target, err := NewTarget(TargetTypeUnknown, field)
				if err != nil {
					return nil, err
				}
				rule.target = target
			} else {
				target, err := NewTarget(value, field)
				if err != nil {
					return nil, err
				}
				rule.target = target
			}
		case "prot":
			prot, ok := ProtocolUpperNameType[field]
			if ok {
				rule.prot = prot
			} else {
				id, err := strconv.Atoi(field)
				if err != nil {
					return nil, err
				}
				rule.prot = Protocol(id)
			}
		case "opt":
			rule.opt = field
		case "in":
			yes := true
			iface := field
			if field[0] == '!' {
				yes = false
				iface = field[1:]
			}
			match, err := NewMatchInInterface(yes, iface)
			if err != nil {
				return nil, err
			}
			rule.matches = append(rule.matches, match)
			rule.matchMap[MatchTypeInInterface] = match
		case "out":
			yes := true
			iface := field
			if field[0] == '!' {
				yes = false
				iface = field[1:]
			}
			match, err := NewMatchOutInterface(yes, iface)
			if err != nil {
				return nil, err
			}
			rule.matches = append(rule.matches, match)
			rule.matchMap[MatchTypeOutInterface] = match
		case "source":
			yes := true
			source := field
			if field[0] == '!' {
				yes = false
				source = field[1:]
			}

			ads, err := ParseAddress(source)
			if err != nil {
				return nil, err
			}
			match, err := NewMatchSource(yes, ads)
			if err != nil {
				return nil, err
			}
			rule.matches = append(rule.matches, match)
			rule.matchMap[MatchTypeSource] = match
		case "destination":
			yes := true
			destination := field
			if field[0] == '!' {
				yes = false
				destination = field[1:]
			}

			ads, err := ParseAddress(destination)
			if err != nil {
				return nil, err
			}
			match, err := NewMatchDestination(yes, ads)
			if err != nil {
				return nil, err
			}
			rule.matches = append(rule.matches, match)
			rule.matchMap[MatchTypeDestination] = match
		}
	}
	jump := true
	// matches or target params
	params := line[index:]
	if len(params) > 0 {
		// see https://git.netfilter.org/iptables/tree/iptables/iptables.c
		// the [goto] clause should be before matches
		p0, next := NFields(params, 1)
		if bytes.Compare(p0[0], []byte("[goto]")) == 0 {
			jump = false
			params = params[next:]
		}
	}

	if rule.target.Type() == TargetTypeUnknown {
		if jump {
			target, err := NewTarget(TargetTypeJumpChain,
				rule.target.(*TargetUnknown).Unknown())
			if err != nil {
				return nil, err
			}
			rule.target = target
		} else {
			target, err := NewTarget(TargetTypeGotoChain,
				rule.target.(*TargetUnknown).Unknown())
			if err != nil {
				return nil, err
			}
			rule.target = target
		}
	}

	// then matches
	matches, err := ParseMatch(params)
	if err != nil {
		return nil, err
	}
	rule.matches = append(rule.matches, matches...)
	for _, match := range matches {
		rule.matchMap[match.Type()] = match
	}

	// then target
	return rule, nil
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
	chain.name = chain.name[:len(chain.name)-1]
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

	pairs := len(attrs) / 2
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
			num, err := unfoldDecimal(string(first))
			if err != nil {
				return nil, err
			}
			chain.packets = num
		}

		// bytes
		if bytes.HasPrefix(second, []byte("bytes")) {
			num, err := unfoldDecimal(string(first))
			if err != nil {
				return nil, err
			}
			chain.bytes = num
		}

		// references
		if bytes.HasPrefix(second, []byte("references")) {
			num, err := unfoldDecimal(string(first))
			if err != nil {
				return nil, err
			}
			chain.references = int(num)
		}
	}
	return chain, nil
}

func unfoldDecimal(decimal string) (int64, error) {
	lastPart := decimal[len(decimal)-1]
	numPart := decimal[0 : len(decimal)-1]
	switch lastPart {
	case 'k', 'K':
		num, err := strconv.ParseInt(numPart, 10, 64)
		if err != nil {
			return num, err
		}
		return num * 1024, nil
	case 'm', 'M':
		num, err := strconv.ParseInt(numPart, 10, 64)
		if err != nil {
			return num, err
		}
		return num * 1024 * 1024, nil
	case 'g', 'G':
		num, err := strconv.ParseInt(numPart, 10, 64)
		if err != nil {
			return num, err
		}
		return num * 1024 * 1024 * 1024, nil
	case 't', 'T':
		num, err := strconv.ParseInt(numPart, 10, 64)
		if err != nil {
			return num, err
		}
		return num * 1024 * 1024 * 1024 * 1024, nil
	case 'p', 'P':
		num, err := strconv.ParseInt(numPart, 10, 64)
		if err != nil {
			return num, err
		}
		return num * 1024 * 1024 * 1024 * 1024 * 1024, nil
	case 'z', 'Z':
		num, err := strconv.ParseInt(numPart, 10, 64)
		if err != nil {
			return num, err
		}
		return num * 1024 * 1024 * 1024 * 1024 * 1024 * 1024, nil
	}
	return strconv.ParseInt(decimal, 10, 64)
}
