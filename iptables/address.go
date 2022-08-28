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

type addrType int

const (
	addrTypeUnknow addrType = iota
	addrTypeHost
	addrTypeIP
	addrTypeIPNet
)

type Address struct {
	addrType addrType
	ip       net.IP
	ipNet    *net.IPNet
	host     string
}

func (address *Address) SetAnywhere(ipType IPType) {
	address.addrType = addrTypeIPNet
	switch ipType {
	case IPv4:
		_, address.ipNet, _ = net.ParseCIDR("0.0.0.0/0")
	case IPv6:
		_, address.ipNet, _ = net.ParseCIDR("::/0")
	}
}

func (address *Address) String() string {
	switch address.addrType {
	case addrTypeHost:
		return address.host
	case addrTypeIP:
		return address.ip.String()
	case addrTypeIPNet:
		return address.ipNet.String()
	}
	return ""
}

func ParseAddress(address interface{}) (*Address, error) {
	switch value := address.(type) {
	case string:
		addrType, ads, err := parseAddress(value)
		if err != nil {
			return nil, err
		}
		switch addrType {
		case addrTypeHost:
			return &Address{
				addrType: addrTypeHost,
				host:     ads.(string),
			}, nil
		case addrTypeIP:
			return &Address{
				addrType: addrTypeIP,
				ip:       ads.(net.IP),
			}, nil
		case addrTypeIPNet:
			return &Address{
				addrType: addrTypeIPNet,
				ipNet:    ads.(*net.IPNet),
			}, nil
		}

	case *net.IPNet:
		return &Address{
			addrType: addrTypeIPNet,
			ipNet:    value,
		}, nil
	case net.IP:
		return &Address{
			addrType: addrTypeIP,
			ip:       value,
		}, nil
	}
	return nil, ErrUnsupportedAddress
}

func parseAddress(address string) (addrType, interface{}, error) {
	length := len(address)
	// https://man7.org/linux/man-pages/man7/hostname.7.html
	if length == 0 || length > 253 {
		return addrTypeUnknow, nil, ErrIllegalAddress
	}

	_, ipNet, err := net.ParseCIDR(address)
	if err == nil {
		return addrTypeIPNet, ipNet, nil
	}
	ip := net.ParseIP(address)
	if ip != nil {
		return addrTypeIP, ip, nil
	}

	// host
	head, tail := 0, 0
	for i := 0; i < len(address); i++ {
		t := address[i]
		if i == head {
			if t == '.' || t == '-' {
				return addrTypeUnknow, nil, ErrIllegalAddress
			}
		}
		if i == tail+2 && tail >= 0 {
			if address[tail] == '-' {
				return addrTypeUnknow, nil, ErrIllegalAddress
			}
		}

		if t == '.' {
			if i-head > 63 {
				return addrTypeUnknow, nil, ErrIllegalAddress
			}
			head = i + 1
			tail = i - 1
			continue
		}

		if !((t >= 'a' && t <= 'z') ||
			(t >= 'A' && t <= 'Z') ||
			(t >= '0' && t <= '9') ||
			t == '-') {
			return addrTypeUnknow, nil, ErrIllegalAddress
		}
	}
	return addrTypeHost, address, nil
}
