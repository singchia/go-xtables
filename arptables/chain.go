package arptables

import "strconv"

type ChainType int

func (ct ChainType) Type() string {
	return "ChainType"
}

func (ct ChainType) Value() string {
	return strconv.Itoa(int(ct))
}

func (ct ChainType) String() string {
	switch ct {
	case ChainTypeINPUT:
		return "INPUT"
	case ChainTypeFORWARD:
		return "FORWARD"
	case ChainTypeOUTPUT:
		return "OUTPUT"
	case ChainTypeUserDefined:
		return "UserDefined"
	}
	return "Unknown"
}

const (
	_                    ChainType = iota
	ChainTypeINPUT                 // INPUT
	ChainTypeFORWARD               // FORWARD
	ChainTypeOUTPUT                // OUTPUT
	ChainTypeUserDefined           // USER-DEFINED
)

type Chain struct {
	tableType   TableType
	chainType   ChainType
	userDefined bool
	name        string
	policy      Target
	packets     int64
	bytes       int64
}
