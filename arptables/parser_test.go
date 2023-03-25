package arptables

import (
	"encoding/json"
	"io/ioutil"
	"testing"
)

func TestParseChain(t *testing.T) {
	data, err := ioutil.ReadFile("../test/stdout/list_arptables_filter")
	if err != nil {
		t.Error(err)
		return
	}
	chains, rules, err := Parse(data, ParseChain, ParseRule)
	if err != nil {
		t.Error(err)
		return
	}
	iterateChains(t, chains)
	iterateRules(t, rules)
}

func iterateChains(t *testing.T, chains []*Chain) {
	for _, chain := range chains {
		t.Log(chain.chainType.String(), chain.userDefined, chain.name,
			chain.policy.Type().String(), chain.packets, chain.bytes)
	}
}

func iterateRules(t *testing.T, rules []*Rule) {
	for _, rule := range rules {
		matches, err := json.Marshal(rule.matchMap)
		if err != nil {
			continue
		}
		options, err := json.Marshal(rule.optionMap)
		if err != nil {
			continue
		}
		t.Log(rule.ChainType().String(), rule.chain.userDefined, rule.lineNumber,
			string(matches), string(options), rule.target.Type().String(),
			rule.packets, rule.bytes)
	}
}
