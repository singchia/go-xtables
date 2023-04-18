GO-XTABLES

* go doc
* go reference
* go passing
* linux
* license

---

## 目录

[TOC]

## 简介

### 说明

Netfilter允许数据包在多个表和链进行过滤、转换和修改，其内核态通过提供setsockopt和getsockopt的多个socket option给上层以增删改查的能力，但这些socket option因为没有标准定义并不直接开放给开发者，对于c/c++开发者来说，可以考虑```libiptc ```来与netfilter交互，不过据netfilter官方描述，libiptc从不（NEVER）意味着对公众开放。因此对于go开发者来说，使用系统调用封装socket或使用cgo封装libiptc都不是更好的选择，按照netfilter的说明，更建议开发者使用iptables, ebtables和arptables工具来操作数据包。

Go-xtables就是对iptables, ebtables和arptables工具进行了封装，相比较其他库，额外提供ebtables和arptables的能力，全特性支持（对所有在man手册提及的扩展能力进行了封装），对外提供了链式调用和option模式，完整继承了几个tables里对用户的抽象，非常可口。

### 设计

![](/Users/zhaizenghui/Documents/默安/go-xtables/未命名.jpg)

### 特性

* 简单易用
* 多tables支持（iptables, ebtables, arptables）
* 全特性支持（全量matches, options, watchers和其他extensions）
* 链式调用（任意排序，可复用对象）
* Dryrun
* 可控日志（默认日志或logrus等）

## 使用

### 简单使用

#### 拒绝特定端口的所有进入流量

``` 
iptables.NewIPTables().
	Table(iptables.TableTypeFilter).
	Chain(iptables.ChainTypeINPUT).
	MatchProtocol(false, network.ProtocolTCP).
	MatchTCP(iptables.WithMatchTCPDstPort(false, 2432)).
	TargetDrop().
	Append()
```

#### 允许特定源IP地址的所有进入流量

```
iptables.NewIPTables().
	Table(iptables.TableTypeFilter).
	Chain(iptables.ChainTypeINPUT).
	MatchSource(false, "192.168.1.100").
	TargetAccept().
	Append()

```

#### 查找相关的规则

```
rules, err := iptables.NewIPTables().
	Table(iptables.TableTypeFilter).
	Chain(iptables.ChainTypeINPUT).
	MatchSource(false, "192.168.1.100").
	TargetAccept().
	FindRules()
```

#### 删除所有表的所有规则

```
iptables.NewIPTables().Flush()

```

#### 允许每分钟10个连接进入80端口

```
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

```
iptables.NewIPTables().
	Table(iptables.TableTypeMangle).
	Chain(iptables.ChainTypePREROUTING).
	MatchProtocol(false, network.ProtocolTCP).
	MatchTCP(iptables.WithMatchTCPDstPort(false, 2432)).
	TargetTEE(net.ParseIP("192.168.1.1")).
	Insert()

```

### 场景示例

## 注意

### 兼容性

## 参与开发

## 贡献