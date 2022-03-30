package iptables

type ChainType int

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
