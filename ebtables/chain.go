package ebtables

import "strconv"

const (
	chainTypeNull        int = iota
	chainTypePREROUTING      // PREROUTING
	chainTypeINPUT           // INPUT
	chainTypeFORWARD         // FORWARD
	chainTypeOUTPUT          // OUTPUT
	chainTypeBROUTING        // BROUTING
	chainTypePOSTROUTING     // POSTROUTING
	chainTypeUserDefined     // USER-DEFINED
)

type ChainType struct {
	chainType   int
	userDefined bool
	name        string
}

func (ct ChainType) SetName(name string) {
	ct.name = name
}

func (ct ChainType) Type() string {
	return "ChainType"
}

func (ct ChainType) Value() string {
	return strconv.Itoa(ct.chainType)
}

func (ct ChainType) String() string {
	switch ct.chainType {
	case chainTypePREROUTING:
		return "PREROUTING"
	case chainTypeINPUT:
		return "INPUT"
	case chainTypeFORWARD:
		return "FORWARD"
	case chainTypeOUTPUT:
		return "OUTPUT"
	case chainTypeBROUTING:
		return "BROUTING"
	case chainTypePOSTROUTING:
		return "POSTROUTING"
	case chainTypeUserDefined:
		return ct.name
	}
	return "Unknown"
}

var (
	ChainTypeNull        = ChainType{chainTypeNull, false, ""}
	ChainTypePREROUTING  = ChainType{chainTypePREROUTING, false, ""}
	ChainTypeINPUT       = ChainType{chainTypeINPUT, false, ""}
	ChainTypeFORWARD     = ChainType{chainTypeFORWARD, false, ""}
	ChainTypeOUTPUT      = ChainType{chainTypeOUTPUT, false, ""}
	ChainTypeBROUTING    = ChainType{chainTypeBROUTING, false, ""}
	ChainTypePOSTROUTING = ChainType{chainTypePOSTROUTING, false, ""}
	ChainTypeUserDefined = ChainType{chainTypeUserDefined, true, ""}
)

type Chain struct {
	chainType ChainType
	tableType TableType
	policy    Target
	entries   int
}
