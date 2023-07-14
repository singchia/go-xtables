# GO-XTABLES

[![Go Reference](https://pkg.go.dev/badge/badge/github.com/singchia/go-xtables.svg)](https://pkg.go.dev/badge/github.com/singchia/go-xtables)
[![Go](https://github.com/singchia/go-xtables/actions/workflows/go.yml/badge.svg)](https://github.com/singchia/go-xtables/actions/workflows/go.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/singchia/go-xtables)](https://goreportcard.com/report/github.com/singchia/go-xtables)
![Platform](https://img.shields.io/badge/platform-linux-brightgreen.svg)

English | [简体中文](./README_cn.md)

## What is go-xtables?

Go-xtables is a wrapper for the iptables, ebtables, and arptables utils. It provides full features, extensions and abstractions from Netfilter, making it very convenient to use.

Check out the [iptables godoc](https://pkg.go.dev/github.com/singchia/go-xtables/iptables) and [ebtables godoc](https://pkg.go.dev/github.com/singchia/go-xtables/ebtables)  to learn about the 70+ ```match``` capabilities, 50+ ```target``` capabilities, and 10+ ```option``` capabilities.

### Modules

![](docs/design-v2.png)

### Features

* Multiple tables(iptables, ebtables, arptables) to support.
* Full featured matches, options, watchers and other extensions.
* Addtional search.
* Chainable pattern.
* Dryrun commands to writer.
* Log control(inner log, logrus etc.).

## Usage
### Getting Started
#### Only accep ssh, http and https ports for incoming traffic
```golang
package main

import (
	"log"

	"github.com/singchia/go-xtables/iptables"
	"github.com/singchia/go-xtables/pkg/network"
)

func main() {
	ipt := iptables.NewIPTables().Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeINPUT).MatchProtocol(false, network.ProtocolTCP)

	// allow ssh, http and https
	err := ipt.MatchMultiPort(iptables.WithMatchMultiPortDstPorts(false, 22, 80, 443)).TargetAccept().Insert()
	if err != nil {
		log.Fatal(err)
	}
	// drop others
	err = iptables.NewIPTables().Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeINPUT).Policy(iptables.TargetTypeDrop)
	if err != nil {
		log.Fatal(err)
	}
}
```

### Simple Use
#### Drop all incoming traffic on specific port
```golang 
iptables.NewIPTables().
	Table(iptables.TableTypeFilter).
	Chain(iptables.ChainTypeINPUT).
	MatchProtocol(false, network.ProtocolTCP).
	MatchTCP(iptables.WithMatchTCPDstPort(false, 2432)).
	TargetDrop().
	Append()
```
#### Accept all incoming traffic from a specific source IP address
```golang
iptables.NewIPTables().
	Table(iptables.TableTypeFilter).
	Chain(iptables.ChainTypeINPUT).
	MatchSource(false, "192.168.1.100").
	TargetAccept().
	Append()
```
#### Find related rules
```golang
rules, err := iptables.NewIPTables().
	Table(iptables.TableTypeFilter).
	Chain(iptables.ChainTypeINPUT).
	MatchSource(false, "192.168.1.100").
	TargetAccept().
	FindRules()
```
#### Delete all rules from all tables
```golang
iptables.NewIPTables().Flush()
```
#### Allow a maximum of 10 connections per minute to enter port 80
```golang
iptables.NewIPTables().
	Table(iptables.TableTypeFilter).
	Chain(iptables.ChainTypeINPUT).
	MatchProtocol(false, network.ProtocolTCP).
	MatchTCP(iptables.WithMatchTCPDstPort(false, 80)).
	MatchLimit(iptables.WithMatchLimit(xtables.Rate{10, xtables.Minute})).
	TargetAccept().
	Append()
```
#### Mirror traffic to the gateway
```golang
iptables.NewIPTables().
	Table(iptables.TableTypeMangle).
	Chain(iptables.ChainTypePREROUTING).
	MatchProtocol(false, network.ProtocolTCP).
	MatchTCP(iptables.WithMatchTCPDstPort(false, 2432)).
	TargetTEE(net.ParseIP("192.168.1.1")).
	Insert()
```
#### Deny access from a specific MAC address.

This example uses ebtables. Please note that this rule applies to the ```linux-bridge```, so make sure that the network interface is being hosted by the bridge.

```golang
ebtables.NewEBTables().
	Table(ebtables.TableTypeFilter).
	Chain(ebtables.ChainTypeINPUT).
	MatchSource(false, "00:11:22:33:44:55").
	TargetDrop().
	Append()
```
### Real-world scenario
#### Anti DDOS attack
```golang
custom := "SYN_FLOOD"
ipt := iptables.NewIPTables().Table(iptables.TableTypeFilter)
ipt.NewChain(custom)
ipt.Chain(iptables.ChainTypeINPUT).
	MatchProtocol(false, network.ProtocolTCP).
	MatchTCP(iptables.WithMatchTCPSYN(false)).
	TargetJumpChain(custom).
	Append()

userDefined := iptables.ChainTypeUserDefined
userDefined.SetName(custom)
rate := xtables.Rate{1, xtables.Second}
ipt.Chain(userDefined).
	MatchLimit(
		iptables.WithMatchLimit(rate),
		iptables.WithMatchLimitBurst(3)).
	TargetReturn().
	Append()
ipt.Chain(userDefined).
	TargetDrop().
	Append()
```
#### Disable PING
```golang
iptables.NewIPTables().
	Table(iptables.TableTypeFilter).
	Chain(iptables.ChainTypeINPUT).
	MatchProtocol(false, network.ProtocolICMP).
	MatchICMP(false, network.ICMPType(network.EchoRequest)).
	TargetDrop().
	Append()
```
#### Traffic outbound only except ssh port
```golang
ipt := iptables.NewIPTables().Table(iptables.TableTypeFilter)
ipt.Chain(iptables.ChainTypeINPUT).
	MatchInInterface(false, "lo").
	TargetAccept().
	Append()
ipt.Chain(iptables.ChainTypeINPUT).
	MatchState(iptables.ESTABLISHED | iptables.RELATED).
	TargetAccept().
	Append()
ipt.Chain(iptables.ChainTypeINPUT).
	MatchProtocol(false, network.ProtocolTCP).
	MatchTCP(iptables.WithMatchTCPDstPort(false, 22)).
	TargetAccept().
	Append()
ipt.Chain(iptables.ChainTypeINPUT).Policy(iptables.TargetTypeDrop)
ipt.Chain(iptables.ChainTypeFORWARD).Policy(iptables.TargetTypeDrop)
ipt.Chain(iptables.ChainTypeOUTPUT).Policy(iptables.TargetTypeAccept)
```
## Note

### Compatibility
Starting from Linux kernel version 4.18, nftables became part of the kernel and gradually replaced iptables. Therefore, distributions using Linux 4.18 and higher versions typically use nftables instead of iptables. Since nftables is not fully compatible with iptables, if you still want to continue using go-xtables, it is best to switch to iptables to continue using it when using these distributions.

The following distributions need to pay attention to compatibility:

* Debian 10(Buster) and higher versions
* Ubuntu 18.04(Bionic Beaver) and higher versions.
* Centos 8 and higher versions.
* Fedora 18 and higher versions.
* OpenSUSE Leap 15.2 and higher versions.
* Arch Linux

## Contributing
If you find any bug, please submit the issue, and we will respond in a short time.
 
If you want to contribute new features or help solve project problems, please feel free to submit a PR:
 
 * Maintain consistent code style
 * Submit one feature at a time
 * Include unit tests with the code you submit

## License

© Austin Zhai, 2022-2025

Released under the [Apache License 2.0](https://github.com/singchia/go-xtables/blob/main/LICENSE)
