package ebtables

import "strconv"

type TableType int

func (tt TableType) Type() string {
	return "TableType"
}

func (tt TableType) Value() string {
	return strconv.Itoa(int(tt))
}

func (tt TableType) String() string {
	switch tt {
	case TableTypeFilter:
		return "filter"
	case TableTypeNat:
		return "nat"
	case TableTypeBRoute:
		return "broute"
	}
	return "unknown"
}

const (
	TableTypeNull   TableType = iota
	TableTypeFilter           // filter
	TableTypeNat              // nat
	TableTypeBRoute           // broute
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
		TableTypeBRoute: {
			ChainTypeBROUTING,
		},
	}
)
