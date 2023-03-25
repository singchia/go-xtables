package arptables

import (
	"bufio"
	"bytes"
	"regexp"
	"strconv"

	"github.com/singchia/go-xtables"
	"github.com/singchia/go-xtables/internal/xutil"
)

type OnChainLine func(line []byte) (*Chain, error)
type OnRuleLine func(rule []byte, chain *Chain) (*Rule, error)

func Parse(data []byte, onChainLine OnChainLine, onRuleLine OnRuleLine) (
	[]*Chain, []*Rule, error) {

	chains := []*Chain{}
	rules := []*Rule{}

	buf := bytes.NewBuffer(data)
	scanner := bufio.NewScanner(buf)

	tableType := TableTypeFilter
	var chain *Chain
	var err error
	var index int // index in current chain

	for scanner.Scan() {
		line := scanner.Bytes()
		if index == 0 {
			if bytes.HasPrefix(line, []byte("Chain")) {
				chain, err = onChainLine(line)
				if err != nil {
					return nil, nil, err
				}
				chain.tableType = tableType
				chains = append(chains, chain)
			}
		} else {
			// rule or EOC(end of chain)
			if len(line) == 0 {
				index = 0
				continue
			}
			rule, err := onRuleLine(line, chain)
			if err != nil {
				return nil, nil, err
			}
			rule.tableType = tableType
			rules = append(rules, rule)
		}
		index++
	}
	return chains, rules, nil
}

func ParseChain(line []byte) (*Chain, error) {
	chain := &Chain{}
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
	default:
		chain.userDefined = true
		chain.chainType = ChainTypeUserDefined
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
				chain.policy = NewTargetAccept()
			case "DROP":
				chain.policy = NewTargetDrop()
			case "RETURN":
				chain.policy = NewTargetReturn()
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
	}
	return chain, nil
}

func ParseRule(line []byte, chain *Chain) (*Rule, error) {
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

	index := bytes.Index(line, []byte{' '})
	if index > 0 && index < len(line) {
		ln, err := strconv.Atoi(string(line[:index]))
		if err == nil {
			rule.lineNumber = ln
			line = line[index+1:]
		}
	}

	// target
	target, index, err := ParseTarget(line)
	if err != nil {
		if err == xtables.ErrTargetNotFound {
			target = chain.policy
		} else {
			return nil, err
		}
	}
	line = line[index:]

	// then matches
	matches, index, err := ParseMatch(line)
	if err != nil {
		return nil, err
	}
	rule.matches = append(rule.matches, matches...)
	for _, match := range matches {
		rule.matchMap[match.Type()] = match
	}
	line = line[index:]

	// then target parse
	if target.Type() == TargetTypeClassify ||
		target.Type() == TargetTypeMangle {

		index, ok := target.Parse(line)
		if !ok {
			return nil, xtables.ErrMatchParams
		}
		line = line[index:]
	}
	rule.target = target

	// then pkt and bytes count
	pcnt, bcnt, ok := parsePktsAndBytes(line)
	if ok {
		rule.packets = pcnt
		rule.bytes = bcnt
	}
	return rule, nil
}

func parsePktsAndBytes(params []byte) (int64, int64, bool) {
	pattern := `,? *pcnt=([0-9A-Za-z]+) -- bcnt=([0-9A-Za-z]+) *`
	reg := regexp.MustCompile(pattern)
	matches := reg.FindSubmatch(params)
	if len(matches) != 3 {
		return 0, 0, false
	}
	pcnt, err := xutil.UnfoldDecimal(string(matches[1]))
	if err != nil {
		return 0, 0, false
	}
	bcnt, err := xutil.UnfoldDecimal(string(matches[2]))
	if err != nil {
		return 0, 0, false
	}
	return pcnt, bcnt, true
}
