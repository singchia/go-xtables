package main

import (
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"
)

const headerFmt = `/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */

package iptables

// Created by gen.go, don't edit manually
// Generated at %s
`

var protocolTpl = template.Must(template.New("protocolTpl").
	Parse(`{{"\t"}}Protocol{{.ProtocolName}}{{"\t"}}{{"\t"}}Protocol = {{.ProtocolID}} // {{.ProtocolComment}}
`))

func genProtocols(arrays [][]string, writer io.Writer) {
	header := fmt.Sprintf(headerFmt, time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintln(writer, header)

	fmt.Fprintln(writer, "const (")
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
		//tmp.ProtocolName = array[2]
		name := array[2]
		name = strings.ReplaceAll(name, "-", "_")
		name = strings.ReplaceAll(name, ".", "Dot")
		name = strings.ReplaceAll(name, "/", "_")
		name = strings.ReplaceAll(name, "+", "Plus")
		tmp.ProtocolName = name
		tmp.ProtocolID = array[1]
		if err := protocolTpl.Execute(writer, tmp); err != nil {
			fmt.Printf("tpl execute err: %s\n", err)
			continue
		}
	}
	fmt.Fprintln(writer, ")")
}
