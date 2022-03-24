/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package iptables

import (
	"net"
)

type Address struct {
	address string
}

func (address *Address) String() string {
	return address.address
}

func ParseAddress(address interface{}) (*Address, error) {
	switch value := address.(type) {
	case string:
		ads, err := parseAddress(value)
		if err != nil {
			return nil, err
		}
		return &Address{ads}, nil

	case *net.IPNet:
		ads := value.String()
		return &Address{ads}, nil
	case net.IP:
		ads := value.String()
		return &Address{ads}, nil
	}
	return nil, ErrUnsupportedAddress
}

func parseAddress(address string) (string, error) {
	length := len(address)
	// https://man7.org/linux/man-pages/man7/hostname.7.html
	if length == 0 || length > 253 {
		return "", ErrIllegalAddress
	}

	_, ipNet, err := net.ParseCIDR(address)
	if err == nil {
		return ipNet.String(), nil
	}
	ip := net.ParseIP(address)
	if ip != nil {
		return ip.String(), nil
	}

	head, tail := 0, 0
	for i := 0; i < len(address); i++ {
		t := address[i]
		if i == head {
			if t == '.' || t == '-' {
				return "", ErrIllegalAddress
			}
		}
		if i == tail+2 && tail >= 0 {
			if address[tail] == '-' {
				return "", ErrIllegalAddress
			}
		}

		if t == '.' {
			if i-head > 63 {
				return "", ErrIllegalAddress
			}
			head = i + 1
			tail = i - 1
			continue
		}

		if !((t >= 'a' && t <= 'z') ||
			(t >= 'A' && t <= 'Z') ||
			(t >= '0' && t <= '9') ||
			t == '-') {
			return "", ErrIllegalAddress
		}
	}
	return address, nil
}
