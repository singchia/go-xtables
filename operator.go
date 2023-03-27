package xtables

type Operator uint32

func (operator Operator) String() string {
	switch operator {
	case OperatorNull:
		return ""
	case OperatorEQ:
		return "=="
	case OperatorNE:
		return "!="
	case OperatorLT:
		return "<"
	case OperatorGT:
		return ">"
	case OperatorINC:
		return "+"
	case OperatorDEC:
		return "-"
	case OperatorSET:
		return "="
	case OperatorXSET:
		return "^="
	case OperatorAND:
		return "&"
	case OperatorOR:
		return "|"
	case OperatorXOR:
		return "^|"
	}
	return ""
}

const (
	OperatorNull Operator = iota
	OperatorEQ            // ==
	OperatorNE            // !=
	OperatorLT            // <
	OperatorGT            // >
	OperatorINC           // +
	OperatorDEC           // -
	OperatorSET           // =
	OperatorXSET          // ^=
	OperatorAND           // &
	OperatorOR            // |
	OperatorXOR           // ^|
)
