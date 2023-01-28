package operator

type Operator uint32

const (
	_            Operator = iota
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
