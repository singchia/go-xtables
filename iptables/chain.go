package iptables

type ChainType int

const (
	ChainPREROUTING  ChainType = iota // PREROUTING
	ChainINPUT                        // INPUT
	ChainFORWARD                      // FORWARD
	ChainOUTPUT                       // OUTPUT
	ChainPOSTROUTING                  // POSTROUTING
	ChainUserDefined                  // USER-DEFINED
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
