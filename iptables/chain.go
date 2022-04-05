package iptables

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
	ChainTypePOSTROUTING           // POSTROUTING
	ChainTypeUserDefined           // USER-DEFINED
)

type Chain struct {
	chainType   ChainType
	userDefined bool
	name        string
	references  int
	policy      Target
	packets     int64
	bytes       int64
}
