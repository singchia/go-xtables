/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package network

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

type addrType int

var (
	ErrUnsupportedAddress = errors.New("unsupported address")
	ErrIllegalAddress     = errors.New("illegal address")
)

const (
	addrTypeUnknown addrType = iota
	addrTypeHost
	addrTypeIP
	addrTypeIPNet
	addrTypeMAC
)

// IP related
type AddressType uint8

const (
	AddressTypeIPv4 AddressType = 1 << iota
	AddressTypeIPv6
	AddressTypeMAC
	AddressTypeIPALL = AddressTypeIPv4 | AddressTypeIPv6
)

type Address interface {
	String() string
	SetAnywhere(AddressType)
}

// addr type ip
type IP struct {
	ip net.IP
}

func (ip *IP) String() string {
	return ip.ip.String()
}

func (ip *IP) SetAnywhere(addrType AddressType) {
	switch addrType {
	case AddressTypeIPv4:
		ip.ip = net.ParseIP("0.0.0.0")
	case AddressTypeIPv6:
		ip.ip = net.ParseIP("::")
	}
}

func NewIP(ip net.IP) Address {
	return &IP{
		ip: ip,
	}
}

// addr type ipnet
type IPNet struct {
	ipNet *net.IPNet
}

func (ipNet *IPNet) String() string {
	return ipNet.ipNet.String()
}

func (ipNet *IPNet) SetAnywhere(addrType AddressType) {
	switch addrType {
	case AddressTypeIPv4:
		_, ipNet.ipNet, _ = net.ParseCIDR("0.0.0.0/0")
	case AddressTypeIPv6:
		_, ipNet.ipNet, _ = net.ParseCIDR("::/0")
	}
}

func NewIPNet(ipNet *net.IPNet) Address {
	return &IPNet{
		ipNet: ipNet,
	}
}

// addr type mac
type HardwareAddr struct {
	mac, mask net.HardwareAddr
}

func (mac *HardwareAddr) String() string {
	if mac.mac == nil {
		// match all unicast address
		return "00:00:00:00:00:00/01:00:00:00:00:00"
	}
	if mac.mask != nil {
		return mac.mac.String() + "/" + mac.mask.String()
	}
	return mac.mac.String()
}

func (mac *HardwareAddr) SetAnywhere(addrType AddressType) {}

func NewHardwareAddr(mac net.HardwareAddr) Address {
	return &HardwareAddr{
		mac: mac,
	}
}

func NewhardwareAddrMask(mac, mask net.HardwareAddr) Address {
	return &HardwareAddr{
		mac:  mac,
		mask: mask,
	}
}

// addr type host
type Host struct {
	hostname string
	mask     int
}

func (host *Host) String() string {
	if host.mask != 0 {
		return host.hostname + "/" + strconv.Itoa(host.mask)
	}
	return host.hostname
}

func (host *Host) SetAnywhere(AddressType) {}

func NewHost(hostname string) Address {
	return &Host{
		hostname: hostname,
	}
}

// parser
func ParseAddress(address interface{}) (Address, error) {
	switch value := address.(type) {
	case string:
		addrType, ads, err := parseAddress(value)
		if err != nil {
			return nil, err
		}
		switch addrType {
		case addrTypeHost:
			return ads.(*Host), nil
		case addrTypeIP:
			return &IP{
				ip: ads.(net.IP),
			}, nil
		case addrTypeIPNet:
			return &IPNet{
				ipNet: ads.(*net.IPNet),
			}, nil
		case addrTypeMAC:
			return &HardwareAddr{
				mac: ads.(net.HardwareAddr),
			}, nil
		}
	case net.HardwareAddr:
		return &HardwareAddr{
			mac: value,
		}, nil
	case *net.IPNet:
		return &IPNet{
			ipNet: value,
		}, nil
	case net.IP:
		return &IP{
			ip: value,
		}, nil
	}
	return nil, ErrUnsupportedAddress
}

func parseAddress(address string) (addrType, interface{}, error) {
	length := len(address)
	// https://man7.org/linux/man-pages/man7/hostname.7.html
	if length == 0 || length > 253 {
		return addrTypeUnknown, nil, ErrIllegalAddress
	}

	// ip net
	_, ipNet, err := net.ParseCIDR(address)
	if err == nil {
		return addrTypeIPNet, ipNet, nil
	}
	// ip
	ip := net.ParseIP(address)
	if ip != nil {
		return addrTypeIP, ip, nil
	}
	// mac
	mac, err := net.ParseMAC(address)
	if err == nil {
		return addrTypeMAC, mac, nil
	}
	// host
	host := &Host{}
	hostMask := strings.Split(address, "/")
	if len(hostMask) == 2 {
		mask, err := strconv.Atoi(hostMask[1])
		if err != nil {
			return addrTypeUnknown, nil, ErrIllegalAddress
		}
		host.mask = mask
	}
	hostname := hostMask[0]
	head, tail := 0, 0
	// verification
	for i := 0; i < len(hostname); i++ {
		t := hostname[i]
		if i == head {
			if t == '.' || t == '-' {
				return addrTypeUnknown, nil, ErrIllegalAddress
			}
		}
		if i == tail+2 && tail >= 0 {
			if hostname[tail] == '-' {
				return addrTypeUnknown, nil, ErrIllegalAddress
			}
		}

		if t == '.' {
			if i-head > 63 {
				return addrTypeUnknown, nil, ErrIllegalAddress
			}
			head = i + 1
			tail = i - 1
			continue
		}

		if !((t >= 'a' && t <= 'z') ||
			(t >= 'A' && t <= 'Z') ||
			(t >= '0' && t <= '9') ||
			t == '-') {
			return addrTypeUnknown, nil, ErrIllegalAddress
		}
	}
	host.hostname = hostname
	return addrTypeHost, host, nil
}
