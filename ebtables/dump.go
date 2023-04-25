package ebtables

import (
	"bufio"
	"bytes"
)

func dump(data []byte) ([]string, error) {
	rules := []string{}

	buf := bytes.NewBuffer(data)
	scanner := bufio.NewScanner(buf)

	for scanner.Scan() {
		line := scanner.Bytes()
		rules = append(rules, string(line))
	}
	return rules, nil
}
