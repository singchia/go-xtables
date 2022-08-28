package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"text/template"
	"time"
)

const protocolHeaderFmt = `//
// Apache License 2.0
//
// Copyright (c) 2022, Austin Zhai
// All rights reserved.
//

package netdb

import "strconv"

// Created by gen.go, don't edit manually
// Generated at %s

func GetProtocolByName(name string) Protocol {
	protocol, ok := ProtocolUpperNameType[name]
	if !ok {
		return ProtocolUnknown
	}
	return protocol
}

type Protocol int

var (
	ProtocolUnknown Protocol = -1
)

func (proto Protocol) Type() string {
	return "Protocol"
}

func (proto Protocol) Value() string {
	return strconv.Itoa(int(proto))
}
`

var protocolTypeTpl = template.Must(template.New("protocolTypeTpl").
	Parse(`{{"\t"}}Protocol{{.ProtocolName}}{{"\t"}}{{"\t"}}Protocol = {{.ProtocolID}} // {{.ProtocolComment}}
`))

var protocolUpperTypeMapTpl = template.Must(template.New("protocolUpperTypeMapTpl").
	Parse(`"{{.ProtocolUpperName}}":{{"\t"}}Protocol{{.ProtocolName}},
`))

var protocolLowerTypeMapTpl = template.Must(template.New("protocolLowerTypeMapTpl").
	Parse(`"{{.ProtocolLowerName}}":{{"\t"}}Protocol{{.ProtocolName}},
`))

func genProtocols(arrays [][]string, writer io.Writer) {
	buf := new(bytes.Buffer)
	header := fmt.Sprintf(protocolHeaderFmt, time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintln(buf, header)

	fmt.Fprintln(buf, "const (")
	for _, array := range arrays {
		if len(array) == 0 {
			continue
		}
		tmp := struct {
			ProtocolName    string
			ProtocolID      string
			ProtocolComment string
		}{}
		if len(array) < 4 {
			tmp.ProtocolComment = ""
		} else {
			tmp.ProtocolComment = strings.Join(array[4:], " ")
		}
		name := array[2]
		name = strings.ReplaceAll(name, "-", "_")
		name = strings.ReplaceAll(name, ".", "Dot")
		name = strings.ReplaceAll(name, "/", "_")
		name = strings.ReplaceAll(name, "+", "Plus")
		tmp.ProtocolName = name
		tmp.ProtocolID = array[1]
		if err := protocolTypeTpl.Execute(buf, tmp); err != nil {
			fmt.Printf("tpl execute err: %s\n", err)
			continue
		}
	}
	fmt.Fprintln(buf, ")")

	// variables
	fmt.Fprintln(buf, "var (")
	fmt.Fprintln(buf, "ProtocolUpperNameType = map[string]Protocol{")
	for _, array := range arrays {
		if len(array) == 0 {
			continue
		}
		tmp := struct {
			ProtocolUpperName string
			ProtocolName      string
		}{}
		tmp.ProtocolUpperName = array[2]
		name := array[2]
		name = strings.ReplaceAll(name, "-", "_")
		name = strings.ReplaceAll(name, ".", "Dot")
		name = strings.ReplaceAll(name, "/", "_")
		name = strings.ReplaceAll(name, "+", "Plus")
		tmp.ProtocolName = name
		if err := protocolUpperTypeMapTpl.Execute(buf, tmp); err != nil {
			fmt.Printf("tpl execute err: %s\n", err)
			continue
		}
	}
	fmt.Fprintln(buf, "}")

	if *protocolLowerMaps {
		fmt.Fprintln(buf, "ProtocolLowerNameType = map[string]Protocol{")
		for _, array := range arrays {
			if len(array) == 0 {
				continue
			}
			tmp := struct {
				ProtocolLowerName string
				ProtocolName      string
			}{}
			tmp.ProtocolLowerName = array[0]
			name := array[2]
			name = strings.ReplaceAll(name, "-", "_")
			name = strings.ReplaceAll(name, ".", "Dot")
			name = strings.ReplaceAll(name, "/", "_")
			name = strings.ReplaceAll(name, "*", "_")
			name = strings.ReplaceAll(name, "+", "Plus")
			tmp.ProtocolName = name
			if err := protocolLowerTypeMapTpl.Execute(buf, tmp); err != nil {
				fmt.Printf("tpl execute err: %s\n", err)
				continue
			}
		}
		fmt.Fprintln(buf, "}")
	}
	fmt.Fprintln(buf, ")")
	buf.WriteTo(writer)
}
