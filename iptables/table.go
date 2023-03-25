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
		TableTypeFilter: []ChainType{
			ChainTypeINPUT,
			ChainTypeOUTPUT,
			ChainTypeFORWARD,
		},
		TableTypeNat: []ChainType{
			ChainTypeOUTPUT,
			ChainTypePREROUTING,
			ChainTypePOSTROUTING,
		},
		TableTypeMangle: []ChainType{
			ChainTypeINPUT,
			ChainTypeOUTPUT,
			ChainTypeFORWARD,
			ChainTypePREROUTING,
			ChainTypePOSTROUTING,
		},
		TableTypeRaw: []ChainType{
			ChainTypeOUTPUT,
			ChainTypePREROUTING,
		},
		TableTypeSecurity: []ChainType{
			ChainTypeINPUT,
			ChainTypeOUTPUT,
			ChainTypeFORWARD,
		},
	}
)
