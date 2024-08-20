<p align=center>
<img src="./docs/go-xtables.png" width="35%" height="35%">
</p>

<div align="center">

[![Go Reference](https://pkg.go.dev/badge/badge/github.com/singchia/go-xtables.svg)](https://pkg.go.dev/badge/github.com/singchia/go-xtables)
[![Go](https://github.com/singchia/go-xtables/actions/workflows/go.yml/badge.svg)](https://github.com/singchia/go-xtables/actions/workflows/go.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/singchia/go-xtables)](https://goreportcard.com/report/github.com/singchia/go-xtables)
![Platform](https://img.shields.io/badge/platform-linux-brightgreen.svg)

[English](./README.md) | 简体中文

</div>

## 简介

### 设计

![](docs/design-v2.png)
### 说明
Netfilter允许数据包在多个表和链进行过滤、转换和修改，其内核态通过提供setsockopt和getsockopt的多个socket option给上层以增删改查的能力，但这些socket option因为没有标准定义并不直接开放给开发者，对于c/c++开发者来说，可以考虑```libiptc ```来与netfilter交互，不过据netfilter官方描述，libiptc从不（NEVER）意味着对公众开放。因此对于go开发者来说，使用系统调用封装socket或使用cgo封装libiptc都不是更好的选择，按照netfilter的说明，更建议开发者使用iptables, ebtables和arptables工具来操作数据包。

Go-xtables就是对iptables, ebtables和arptables工具进行了封装，相比较其他库，额外提供ebtables和arptables的能力，全特性支持（对所有在man手册提及的扩展能力进行了封装），对外提供了链式调用和option模式，完整继承了几个tables里对用户的抽象，非常方便。

查看 [iptables godoc](https://pkg.go.dev/github.com/singchia/go-xtables/iptables) 和 [ebtables godoc](https://pkg.go.dev/github.com/singchia/go-xtables/ebtables) 来了解70+ ```match```能力，50+ ```target```能力以10+ ```option```能力。

**Matches:**

- :white_check_mark: MatchTypeAddrType
- :white_check_mark: MatchTypeAH
- :white_check_mark: MatchTypeBPF
- :white_check_mark: MatchTypeCGroup
- :white_check_mark: MatchTypeCluster
- :white_check_mark: MatchTypeComment
- :white_check_mark: MatchTypeConnBytes
- :white_check_mark: MatchTypeConnLabel
- :white_check_mark: MatchTypeConnLimit
- :white_check_mark: MatchTypeConnMark
- :white_check_mark: MatchTypeConnTrack
- :white_check_mark: MatchTypeCPU
- :white_check_mark: MatchTypeDCCP
- :white_check_mark: MatchTypeDestination
- :white_check_mark: MatchTypeDevGroup
- :white_check_mark: MatchTypeDSCP
- :white_check_mark: MatchTypeDst
- :white_check_mark: MatchTypeECN
- :white_check_mark: MatchTypeESP
- :white_check_mark: MatchTypeEUI64
- :white_check_mark: MatchTypeFrag
- :white_check_mark: MatchTypeHashLimit
- :white_check_mark: MatchTypeHBH
- :white_check_mark: MatchTypeHelper
- :white_check_mark: MatchTypeHL
- :white_check_mark: MatchTypeICMP
- :white_check_mark: MatchTypeInInterface
- :white_check_mark: MatchTypeIPRange
- :white_check_mark: MatchTypeIPv4
- :white_check_mark: MatchTypeIPv6
- :white_check_mark: MatchTypeIPv6Header
- :white_check_mark: MatchTypeIPVS
- :white_check_mark: MatchTypeLength
- :white_check_mark: MatchTypeLimit
- :white_check_mark: MatchTypeMAC
- :white_check_mark: MatchTypeMark
- :white_check_mark: MatchTypeMH
- :white_check_mark: MatchTypeMultiPort
- :white_check_mark: MatchTypeNFAcct
- :white_check_mark: MatchTypeOSF
- :white_check_mark: MatchTypeOutInterface
- :white_check_mark: MatchTypeOwner
- :white_check_mark: MatchTypePhysDev
- :white_check_mark: MatchTypePktType
- :white_check_mark: MatchTypePolicy
- :white_check_mark: MatchTypeProtocol
- :white_check_mark: MatchTypeQuota
- :white_check_mark: MatchTypeRateEst
- :white_check_mark: MatchTypeRealm
- :white_check_mark: MatchTypeRecent
- :white_check_mark: MatchTypeRPFilter
- :white_check_mark: MatchTypeRT
- :white_check_mark: MatchTypeSCTP
- :white_check_mark: MatchTypeSet
- :white_check_mark: MatchTypeSocket
- :white_check_mark: MatchTypeSource
- :white_check_mark: MatchTypeSRH
- :white_check_mark: MatchTypeState
- :white_check_mark: MatchTypeStatistic
- :white_check_mark: MatchTypeString
- :white_check_mark: MatchTypeTCP
- :white_check_mark: MatchTypeTCPMSS
- :white_check_mark: MatchTypeTime
- :white_check_mark: MatchTypeTOS
- :white_check_mark: MatchTypeTTL
- :white_check_mark: MatchTypeU32
- :white_check_mark: MatchTypeUDP

**Targets:**

- :white_check_mark: TargetTypeAccept
- :white_check_mark: TargetTypeDrop
- :white_check_mark: TargetTypeReturn
- :white_check_mark: TargetTypeJumpChain
- :white_check_mark: TargetTypeGotoChain
- :white_check_mark: TargetTypeAudit
- :white_check_mark: TargetTypeCheckSum
- :white_check_mark: TargetTypeClassify
- :white_check_mark: TargetTypeClusterIP
- :white_check_mark: TargetTypeConnMark
- :white_check_mark: TargetTypeConnSecMark
- :white_check_mark: TargetTypeCT
- :white_check_mark: TargetTypeDNAT
- :white_check_mark: TargetTypeDNPT
- :white_check_mark: TargetTypeDSCP
- :white_check_mark: TargetTypeECN
- :white_check_mark: TargetTypeHL
- :white_check_mark: TargetTypeHMark
- :white_check_mark: TargetTypeIdleTimer
- :white_check_mark: TargetTypeLED
- :white_check_mark: TargetTypeLog
- :white_check_mark: TargetTypeMark
- :white_check_mark: TargetTypeMasquerade
- :white_check_mark: TargetTypeMirror
- :white_check_mark: TargetTypeNetmap
- :white_check_mark: TargetTypeNFLog
- :white_check_mark: TargetTypeNFQueue
- :white_check_mark: TargetTypeNoTrack
- :white_check_mark: TargetTypeRateEst
- :white_check_mark: TargetTypeRedirect
- :white_check_mark: TargetTypeReject
- :white_check_mark: TargetTypeSame
- :white_check_mark: TargetTypeSecMark
- :white_check_mark: TargetTypeSet
- :white_check_mark: TargetTypeSNAT
- :white_check_mark: TargetTypeSNPT
- :white_check_mark: TargetTypeSYNProxy
- :white_check_mark: TargetTypeTCPMSS
- :white_check_mark: TargetTypeTCPOptStrip
- :white_check_mark: TargetTypeTEE
- :white_check_mark: TargetTypeTOS
- :white_check_mark: TargetTypeTProxy
- :white_check_mark: TargetTypeTrace
- :white_check_mark: TargetTypeTTL
- :white_check_mark: TargetTypeULog


### 特性

* 简单易用
* 多tables支持（iptables, ebtables, arptables）
* 全特性支持（全量matches, options, watchers和其他extensions）
* 链式调用（任意排序，可复用对象）
* Dryrun
* 可控日志（默认日志或logrus等）

## 使用
### 上手一试
#### 仅允许ssh, http和https端口流量
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

### 简单使用
#### 拒绝特定端口的所有进入流量
```golang 
iptables.NewIPTables().
	Table(iptables.TableTypeFilter).
	Chain(iptables.ChainTypeINPUT).
	MatchProtocol(false, network.ProtocolTCP).
	MatchTCP(iptables.WithMatchTCPDstPort(false, 2432)).
	TargetDrop().
	Append()
```
#### 允许特定源IP地址的所有进入流量
```golang
iptables.NewIPTables().
	Table(iptables.TableTypeFilter).
	Chain(iptables.ChainTypeINPUT).
	MatchSource(false, "192.168.1.100").
	TargetAccept().
	Append()
```
#### 查找相关的规则
```golang
rules, err := iptables.NewIPTables().
	Table(iptables.TableTypeFilter).
	Chain(iptables.ChainTypeINPUT).
	MatchSource(false, "192.168.1.100").
	TargetAccept().
	FindRules()
```
#### 删除所有表的所有规则
```golang
iptables.NewIPTables().Flush()
```
#### 允许每分钟10个连接进入80端口
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
#### 流量镜像到网关
```golang
iptables.NewIPTables().
	Table(iptables.TableTypeMangle).
	Chain(iptables.ChainTypePREROUTING).
	MatchProtocol(false, network.ProtocolTCP).
	MatchTCP(iptables.WithMatchTCPDstPort(false, 2432)).
	TargetTEE(net.ParseIP("192.168.1.1")).
	Insert()
```
#### 拒绝特定MAC地址的访问

该示例使用ebtables，请注意该规则作用在```linux-bridge```上，请先确保网卡被bridge接管。

```golang
ebtables.NewEBTables().
	Table(ebtables.TableTypeFilter).
	Chain(ebtables.ChainTypeINPUT).
	MatchSource(false, "00:11:22:33:44:55").
	TargetDrop().
	Append()
```
### 现实场景
#### 防止DDos攻击
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
#### 禁PING
```golang
iptables.NewIPTables().
	Table(iptables.TableTypeFilter).
	Chain(iptables.ChainTypeINPUT).
	MatchProtocol(false, network.ProtocolICMP).
	MatchICMP(false, network.ICMPType(network.EchoRequest)).
	TargetDrop().
	Append()
```
#### 流量只出不进
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
## 注意

### 兼容性
从Linux内核版本4.18开始，nftables成为内核的一部分，并逐步替代iptables。因此，使用linux 4.18以及更高版本的发行版通常会使用nftables而不是iptables。由于nftables并不完全兼容iptables，如果还想要继续使用go-xtables，在使用这些发行版时最好能够切换到iptables以继续使用。

以下发行版需要注意兼容性：

* Debian 10(Buster) 及更高版本
* Ubuntu 18.04(Bionic Beaver) 及更高版本
* Centos 8 及更高版本
* Fedora 18 及更高版本
* OpenSUSE Leap 15.2 及更高版本
* Arch Linux

## 参与开发
 当前go-xtables处于生产就绪阶段，如果你发现任何Bug，请随意提出Issue，项目Maintainers会及时响应相关问题。
 
 如果你希望能够提交Feature，更快速解决项目问题，满足以下简单条件下欢迎提交PR：
 
 * 代码风格保持一致
 * 每次提交一个Feature
 * 提交的代码都携带单元测试
 * 通过CI构建

经过Code review没问题，就会合入代码。

## 谁在使用

<img src="docs/users/Moresec-LOGO.png" width="100">


## 许可证


Released under the [Apache License 2.0](https://github.com/singchia/go-xtables/blob/main/LICENSE)