package iptables

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"

	"github.com/singchia/go-xtables"
	"github.com/singchia/go-xtables/internal/xutil"
	"github.com/singchia/go-xtables/pkg/network"
)

type onChainLine func(line []byte) (*Chain, error)
type onRuleLine func(rule []byte, head []string, chain *Chain) (*Rule, error)

func parse(data []byte, table TableType, onChainLine onChainLine, onRuleLine onRuleLine) (
	[]*Chain, []*Rule, error) {

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
				if onChainLine == nil {
					continue
				}
				chain, err = onChainLine(line)
				if err != nil {
					return nil, nil, err
				}
				chain.tableType = table
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
			if onRuleLine == nil {
				continue
			}
			rule, err := onRuleLine(line, head, chain)
			if err != nil {
				return nil, nil, err
			}
			rule.tableType = table
			rules = append(rules, rule)
		}
		index++
	}
	return chains, rules, nil
}

func parseRule(line []byte, head []string, chain *Chain) (*Rule, error) {
	rule := &Rule{
		chain:      chain,
		lineNumber: -1,
		packets:    -1,
		bytes:      -1,
		matches:    []Match{},
		options:    []Option{},
		matchMap:   map[MatchType]Match{},
		optionMap:  map[OptionType]Option{},
	}
	fields, index := xutil.NFields(line, len(head))
	for i, name := range head {
		field := string(fields[i])
		switch name {
		case "num":
			num, err := strconv.Atoi(strings.TrimSpace(field))
			if err != nil {
				return nil, err
			}
			rule.lineNumber = num

		case "pkts":
			num, err := xutil.UnfoldDecimal(field)
			if err != nil {
				return nil, err
			}
			rule.packets = num
		case "bytes":
			num, err := xutil.UnfoldDecimal(field)
			if err != nil {
				return nil, err
			}
			rule.bytes = num
		case "target":
			value, ok := targetValueType[field]
			if !ok {
				// user defined chain, wait to see concrete details
				target, err := targetFactory(TargetTypeNull, field)
				if err != nil {
					return nil, err
				}
				rule.target = target
			} else {
				target, err := targetFactory(value)
				if err != nil {
					return nil, err
				}
				rule.target = target
			}
		case "prot":
			field = strings.ToUpper(field)
			invert := false
			if len(field) > 1 && field[0] == '!' {
				invert = true
				field = field[1:]
			}
			prot := network.GetProtocolByName(strings.ToUpper(field))
			if prot != network.ProtocolUnknown {
				match := newMatchProtocol(invert, prot)
				rule.matches = append(rule.matches, match)
				rule.matchMap[MatchTypeProtocol] = match
			} else {
				id, err := strconv.Atoi(field)
				if err != nil {
					return nil, err
				}
				match := newMatchProtocol(invert, network.Protocol(id))
				rule.matches = append(rule.matches, match)
				rule.matchMap[MatchTypeProtocol] = match
			}
		case "opt":
			rule.opt = field
		case "in":
			invert := false
			iface := field
			if len(field) > 1 && field[0] == '!' {
				invert = true
				iface = field[1:]
			}
			match, err := newMatchInInterface(invert, iface)
			if err != nil {
				return nil, err
			}
			rule.matches = append(rule.matches, match)
			rule.matchMap[MatchTypeInInterface] = match
		case "out":
			invert := false
			iface := field
			if len(field) > 1 && field[0] == '!' {
				invert = false
				iface = field[1:]
			}
			match, err := newMatchOutInterface(invert, iface)
			if err != nil {
				return nil, err
			}
			rule.matches = append(rule.matches, match)
			rule.matchMap[MatchTypeOutInterface] = match
		case "source":
			invert := false
			source := field
			if len(field) > 1 && field[0] == '!' {
				invert = true
				source = field[1:]
			}

			ads, err := network.ParseAddress(source)
			if err != nil {
				return nil, err
			}
			match, err := newMatchSource(invert, ads)
			if err != nil {
				return nil, err
			}
			rule.matches = append(rule.matches, match)
			rule.matchMap[MatchTypeSource] = match
		case "destination":
			invert := false
			destination := field
			if len(field) > 1 && field[0] == '!' {
				invert = true
				destination = field[1:]
			}

			ads, err := network.ParseAddress(destination)
			if err != nil {
				return nil, err
			}
			match, err := newMatchDestination(invert, ads)
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
		p0, next := xutil.NFields(params, 1)
		if bytes.Compare(p0[0], []byte("[goto]")) == 0 {
			jump = false
			params = params[next:]
		}
	}

	if rule.target.Type() == TargetTypeNull {
		if jump {
			target, err := targetFactory(TargetTypeJumpChain,
				rule.target.(*TargetUnknown).Unknown())
			if err != nil {
				return nil, err
			}
			rule.target = target
		} else {
			target, err := targetFactory(TargetTypeGotoChain,
				rule.target.(*TargetUnknown).Unknown())
			if err != nil {
				return nil, err
			}
			rule.target = target
		}
	}

	// then matches
	matches, index, err := ParseMatch(params)
	if err != nil {
		return nil, err
	}
	rule.matches = append(rule.matches, matches...)
	for _, match := range matches {
		rule.matchMap[match.Type()] = match
	}
	params = params[index:]

	// then target
	_, ok := rule.target.Parse(bytes.TrimSpace(params))
	if !ok {
		return nil, xtables.ErrTargetParseFailed
	}
	return rule, nil
}

func parseChain(line []byte) (*Chain, error) {
	chain := &Chain{
		references: -1,
	}
	buf := bytes.NewBuffer(line)
	_, err := buf.ReadString(' ')
	if err != nil {
		return nil, err
	}

	chain.chainType.name, err = buf.ReadString(' ')
	if err != nil {
		return nil, err
	}

	chain.chainType.name = strings.TrimSpace(chain.chainType.name[:len(chain.chainType.name)-1])
	switch chain.chainType.name {
	case "INPUT":
		chain.chainType = ChainTypeINPUT
	case "FORWARD":
		chain.chainType = ChainTypeFORWARD
	case "OUTPUT":
		chain.chainType = ChainTypeOUTPUT
	case "PREROUTING":
		chain.chainType = ChainTypePREROUTING
	case "POSTROUTING":
		chain.chainType = ChainTypePOSTROUTING
	default:
		userDefined := ChainTypeUserDefined
		userDefined.name = chain.chainType.name
		chain.chainType = userDefined
	}

	rest := buf.Bytes()
	if len(rest) < 2 {
		return nil, xtables.ErrChainLineTooShort
	}
	rest = rest[1 : len(rest)-1]
	attrs := bytes.Fields(rest)
	if len(attrs)%2 != 0 {
		return nil, xtables.ErrChainAttrsNotRecognized
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
				chain.policy = newTargetAccept()
			case "DROP":
				chain.policy = newTargetDrop()
			case "RETURN":
				chain.policy = newTargetReturn()
			}
		}

		// packets
		if bytes.HasPrefix(second, []byte("packets")) {
			num, err := xutil.UnfoldDecimal(string(first))
			if err != nil {
				return nil, err
			}
			chain.packets = num
		}

		// bytes
		if bytes.HasPrefix(second, []byte("bytes")) {
			num, err := xutil.UnfoldDecimal(string(first))
			if err != nil {
				return nil, err
			}
			chain.bytes = num
		}

		// references
		if bytes.HasPrefix(second, []byte("references")) {
			num, err := xutil.UnfoldDecimal(string(first))
			if err != nil {
				return nil, err
			}
			chain.references = int(num)
		}
	}
	return chain, nil
}
