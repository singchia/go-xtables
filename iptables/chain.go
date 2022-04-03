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
	chainType  ChainType
	tableType  TableType
	references int
	name       string
	policy     Target
	packets    int
	bytes      int
}
