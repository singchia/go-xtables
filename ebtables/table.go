package ebtables

import "strconv"

type TableType int

func (tt TableType) Type() string {
	return "TableType"
}

func (tt TableType) Value() string {
	return strconv.Itoa(int(tt))
}

const (
	TableTypeNull   TableType = iota
	TableTypeFilter           // filter
	TableTypeNat              // nat
	TableTypeBRoute           // broute
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
		TableTypeBRoute: []ChainType{
			ChainTypeBROUTING,
		},
	}
)
