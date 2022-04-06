package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"

	"github.com/singchia/go-xtables/pkg/cmd"
)

const headerFmt = `/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */

package iptables

import "strconv"

// Created by gen.go, don't edit manually
// Generated at %s

type Protocol int

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
	header := fmt.Sprintf(headerFmt, time.Now().Format("2006-01-02 15:04:05"))
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
		name = strings.ReplaceAll(name, "+", "Plus")
		tmp.ProtocolName = name
		if err := protocolLowerTypeMapTpl.Execute(buf, tmp); err != nil {
			fmt.Printf("tpl execute err: %s\n", err)
			continue
		}
	}
	fmt.Fprintln(buf, "}")
	fmt.Fprintln(buf, ")")

	gofmt, err := exec.LookPath("gofmt")
	if err == nil {
		fd, err := os.OpenFile("tmp", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
		if err != nil {
			fmt.Printf("open tmp err: %s\n", err)
			return
		}
		defer fd.Close()
		defer os.Remove("tmp")

		buf.WriteTo(fd)
		stdout, stderr, err := cmd.Cmd(gofmt, "tmp")
		if err != nil {
			fmt.Printf("go fmt err: %s\n", string(stderr))
			return
		}
		buf = bytes.NewBuffer(stdout)
	}
	buf.WriteTo(writer)
}
