package network

import "fmt"

type IPType uint8

const (
	IPv4 IPType = 1 << iota
	IPv6
	IPALL = IPv4 | IPv6
)

type TOS int8

func (tos TOS) String() string {
	return fmt.Sprintf("0x%02x", int8(tos))
}

const (
	_ TOS = 1 << iota
	TOSMinCost
	TOSMaxReliability
	TOSMaxThroughput
	TOSMinDelay
	TOSNormal TOS = 0
)

var (
	TOSMap = map[string]TOS{
		"Minimize-Delay":       TOSMinDelay,
		"Maximize-Throughput":  TOSMaxThroughput,
		"Maximize-Reliability": TOSMaxReliability,
		"Minimize-Cost":        TOSMinCost,
		"Normal-Service":       TOSNormal,
	}
)
