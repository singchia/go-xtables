package iptables

type Statement struct {
	table   Table
	chain   Chain
	err     error
	matches map[matchType]match
}

func NewStatement() *Statement {
	return &Statement{
		table:   TableFilter,
		matches: make(map[matchType]match),
	}
}

func (statement *Statement) addMatch(match match) {
	statement.matches[match.typ()] = match
}
