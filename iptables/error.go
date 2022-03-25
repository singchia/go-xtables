package iptables

import "errors"

var (
	ErrUnsupportedAddress = errors.New("unsupported address")
	ErrIllegalAddress     = errors.New("illegal address")
)
