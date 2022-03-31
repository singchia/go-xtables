package iptables

import "errors"

var (
	ErrUnsupportedAddress = errors.New("unsupported address")
	ErrIllegalAddress     = errors.New("illegal address")
	ErrChainRequired      = errors.New("chain required")
	ErrCommandRequired    = errors.New("command required")
	ErrRulenumMustnot0    = errors.New("rulenum mustn't be 0")
)
