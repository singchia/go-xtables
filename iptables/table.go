package iptables

import "strconv"

type TableType int

func (tt TableType) Type() string {
	return "TableType"
}

func (tt TableType) Value() string {
	return strconv.Itoa(int(tt))
}

const (
	TableTypeNull     TableType = iota
	TableTypeFilter             // filter
	TableTypeNat                // nat
	TableTypeMangle             // mangle
	TableTypeRaw                // raw
	TableTypeSecurity           // security
)

var (
	TableChains = map[TableType][]ChainType{
		TableTypeFilter: {
			ChainTypeINPUT,
			ChainTypeOUTPUT,
			ChainTypeFORWARD,
		},
		TableTypeNat: {
			ChainTypeOUTPUT,
			ChainTypePREROUTING,
			ChainTypePOSTROUTING,
		},
		TableTypeMangle: {
			ChainTypeINPUT,
			ChainTypeOUTPUT,
			ChainTypeFORWARD,
			ChainTypePREROUTING,
			ChainTypePOSTROUTING,
		},
		TableTypeRaw: {
			ChainTypeOUTPUT,
			ChainTypePREROUTING,
		},
		TableTypeSecurity: {
			ChainTypeINPUT,
			ChainTypeOUTPUT,
			ChainTypeFORWARD,
		},
	}
)
