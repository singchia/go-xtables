package arptables

import "strconv"

type ChainType int

func (ct ChainType) Type() string {
	return "ChainType"
}

func (ct ChainType) Value() string {
	return strconv.Itoa(int(ct))
}

const (
	_                    ChainType = iota
	ChainTypeINPUT                 // INPUT
	ChainTypeFORWARD               // FORWARD
	ChainTypeOUTPUT                // OUTPUT
	ChainTypeUserDefined           // USER-DEFINED
)

type Chain struct {
	chainType   ChainType
	userDefined bool
	name        string
	policy      Target
}
