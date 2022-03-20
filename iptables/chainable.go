package iptables

type Table string
type Chain string

const (
	TableFilter   Table = "filter"
	TableNat      Table = "nat"
	TableMangle   Table = "mangle"
	TableRaw      Table = "raw"
	TableSecutiry Table = "security"

	ChainPREROUTING  Chain = "PREROUTING"
	ChainINPUT       Chain = "INPUT"
	ChainFORWARD     Chain = "FORWARD"
	ChainOUTPUT      Chain = "OUTPUT"
	ChainPOSTROUTING Chain = "POSTROUTING"
)

func (iptables *IPTables) Table(table Table) *IPTables {
	iptables.statement.table = table
	return iptables
}

func (iptables *IPTables) Chain(chain Chain) *IPTables {
	iptables.statement.chain = chain
	return iptables
}

func (iptables *IPTables) MatchIPv4() *IPTables {
	match := &MatchIPv4{
		baseMatch: baseMatch{
			matchIPv4,
		},
	}
	iptables.statement.addMatch(match)
	return iptables
}

func (iptables *IPTables) MatchIPv6() *IPTables {
	match := &MatchIPv6{
		baseMatch: baseMatch{
			matchIPv6,
		},
	}
}

func (iptables *IPTables) MatchProtocol() *IPTables {
}
