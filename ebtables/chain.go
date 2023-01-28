package ebtables

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
	ChainTypePREROUTING            // PREROUTING
	ChainTypeINPUT                 // INPUT
	ChainTypeFORWARD               // FORWARD
	ChainTypeOUTPUT                // OUTPUT
	ChainTypeBROUTING              // BROUTING
	ChainTypePOSTROUTING           // POSTROUTING
	ChainTypeUserDefined           // USER-DEFINED
)

type Chain struct {
	chainType   ChainType
	userDefined bool
	name        string
	policy      Target
}
