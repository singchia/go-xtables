GO-XTABLES

* go doc
* go reference
* go passing
* other badger
* linux
* license

---

## 目录

[TOC]

## 简介

### 说明

Netfilter允许数据包在多个表和链进行过滤、转换和修改，其内核态通过提供setsockopt和getsockopt的多个socket option给上层以增删改查的能力，但这些socket option因为没有标准定义并不直接开放给开发者，对于c/c++开发者来说，可以考虑```libiptc ```来与netfilter交互，不过据netfilter官方描述，libiptc从不（NEVER）意味着对公众开放。因此对于go开发者来说，使用系统调用封装socket或使用cgo封装libiptc都不是更好的选择，按照netfilter的说明，更建议开发者使用iptables, ebtables和arptables工具来操作数据包。

Go-xtables就是对iptables, ebtables和arptables工具进行了封装，相比较其他库，额外提供ebtables和arptables的能力，全特性支持（对所有在man手册提及的扩展能力进行了封装），对外提供了链式调用和option模式，完整继承了几个tables里对用户的抽象，非常可口。

### 架构

![](/Users/zhaizenghui/Documents/默安/go-xtables/未命名.jpg)

### 特性

* 多tables支持（iptables, ebtables, arptables）
* 全量matches, options, watchers和其他extensions特性
* 链式调用（任意排序）
* Dryrun
* 可控日志
* 文件锁，避免多应用干扰

## 使用

### 简单使用

#### 删除所有表数据

```golang



golang```

### 案例