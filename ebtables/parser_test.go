package ebtables

import (
	"encoding/json"
	"io/ioutil"
	"testing"
)

func TestParseChain(t *testing.T) {
	data, err := ioutil.ReadFile("../test/stdout/list_ebtables_filter")
	if err != nil {
		t.Error(err)
		return
	}
	chains, rules, err := parse(data, parseTable, parseChain, parseRule)
	if err != nil {
		t.Error(err)
		return
	}
	iterateChains(t, chains)
	iterateRules(t, rules)
}

func iterateChains(t *testing.T, chains []*Chain) {
	for _, chain := range chains {
		t.Log(chain.chainType.String(), chain.userDefined,
			chain.name, chain.policy.Type().String())
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
		watchers, err := json.Marshal(rule.watcherMap)
		if err != nil {
			continue
		}
		t.Log(rule.ChainType().String(), rule.chain.userDefined, rule.lineNumber,
			string(matches), string(options), string(watchers), rule.target.Type().String(),
			rule.packets, rule.bytes)
	}
}
