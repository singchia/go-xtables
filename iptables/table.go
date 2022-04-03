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
	_                 TableType = iota
	TableTypeFilter             // filter
	TableTypeNat                // nat
	TableTypeMangle             // mangle
	TableTypeRaw                // raw
	TableTypeSecurity           // security
)
