package main

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"
)

const serviceHeaderFmt = `//
// Apache License 2.0
//
// Copyright (c) 2022, Austin Zhai
// All rights reserved.
//

package network

// Created by gen.go, don't edit manually
// Generated at %s

func GetPortByServiceAndProtocol(service Service, proto Protocol) int {
	pps, ok := ServicePortProtoMaps[service]
	if !ok {
		return -1
	}
	for _, pp:= range pps {
		if proto == pp.Proto {
			return pp.Port
		}
	}
	return -1
}

type Service string

var (
	ServiceUnknown Service = "unknown"
)

func (service Service) Type() string {
	return "Service"
}

func (service Service) Value() string {
	return string(service)
}

type PortProto struct {
    Port int
	Proto Protocol
}
`

var serviceTypeTpl = template.Must(template.New("serviceTypeTpl").
	Parse(`{{"\t"}}Service{{.ServiceName}}{{"\t"}}{{"\t"}}Service = "{{.ServiceID}}" // {{.ServiceComment}}
`))

var serviceTypeMapTpl = template.Must(template.New("serviceTypeMapTpl").
	Parse(`PortProto{ {{.Port}}, {{.Protocol}} }:{{"\t"}}Service{{.ServiceName}},
`))

var servicePortProtoKeyTpl = template.Must(template.New("servicePortProtoKeyTpl").
	Parse(`Service{{.ServiceName}}: `))

var servicePortProtoValueTpl = template.Must(template.New("servicePortProtoValueTpl").
	Parse(`[]PortProto{ {{range $index, $pp := . }} PortProto{ {{ $pp.Port }}, {{ $pp.Protocol }}, }, {{end}}},
`))

func genServices(arrays [][]string, writer io.Writer) {
	buf := new(bytes.Buffer)
	header := fmt.Sprintf(serviceHeaderFmt, time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintln(buf, header)

	if *serviceDefine {
		fmt.Fprintln(buf, "const (")
		names := map[string]bool{}
		for _, array := range arrays {
			if len(array) == 0 {
				continue
			}
			tmp := struct {
				ServiceName    string
				ServiceID      string
				ServiceComment string
			}{}
			name := array[0]
			{
				index := strings.IndexAny(name, "-/*")
				for index != -1 {
					if name[index+1] <= 'z' && name[index+1] >= 'a' {
						name = name[0:index] + string(name[index+1]-32) + name[index+2:]
					} else {
						name = name[0:index] + name[index+1:]
					}
					index = strings.IndexAny(name, "-/*")
				}
				name = strings.ReplaceAll(name, ".", "Dot")
				name = strings.ReplaceAll(name, "+", "Plus")
				name = strings.Title(name)
				_, ok := names[name]
				if !ok {
					names[name] = true
				} else {
					continue
				}
			}

			id := array[0]
			comment := ""

			index := 0
			for i, elem := range array {
				if elem == "#" {
					index = i
					break
				}
			}
			if index+1 < len(array) {
				comment = strings.Join(array[index+1:], " ")
			}
			tmp.ServiceName = name
			tmp.ServiceID = id
			tmp.ServiceComment = comment
			if err := serviceTypeTpl.Execute(buf, tmp); err != nil {
				fmt.Printf("tpl execute err: %s\n", err)
				continue
			}
		}
		fmt.Fprintln(buf, ")")
	}

	// variables
	fmt.Fprintln(buf, "var (")
	fmt.Fprintln(buf, "ServicePortProtoMaps = map[Service][]PortProto{")

	type PortProto struct {
		Port     int
		Protocol int
	}
	maps := map[string][]PortProto{}
	for _, array := range arrays {
		if len(array) == 0 {
			continue
		}
		name := array[0]
		{
			index := strings.IndexAny(name, "-/*")
			for index != -1 {
				if name[index+1] <= 'z' && name[index+1] >= 'a' {
					name = name[0:index] + string(name[index+1]-32) + name[index+2:]
				} else {
					name = name[0:index] + name[index+1:]
				}
				index = strings.IndexAny(name, "-/*")
			}
			name = strings.ReplaceAll(name, ".", "Dot")
			name = strings.ReplaceAll(name, "+", "Plus")
			name = strings.Title(name)
		}
		portproto := strings.Split(array[1], "/")
		port, err := strconv.Atoi(portproto[0])
		if err != nil {
			fmt.Printf("conv port err: %s\n", err)
			continue
		}
		proto := 6
		switch portproto[1] {
		case "udp":
			proto = 17
		case "sctp":
			proto = 132
		case "dccp":
			proto = 33
		}

		pps, ok := maps[name]
		if !ok {
			maps[name] = []PortProto{PortProto{port, proto}}
		} else {
			pps = append(pps, PortProto{port, proto})
			maps[name] = pps
		}
	}
	keys := make([]string, len(maps))
	cursor := 0
	for name, _ := range maps {
		keys[cursor] = name
		cursor++
	}
	sort.Strings(keys)

	for _, name := range keys {
		tmp := struct {
			ServiceName string
		}{name}
		err := servicePortProtoKeyTpl.Execute(buf, tmp)
		if err != nil {
			fmt.Println("execute key err:", err)
			continue
		}
		pps, _ := maps[name]
		err = servicePortProtoValueTpl.Execute(buf, pps)
		if err != nil {
			fmt.Println("execute value err:", err)
			continue
		}
	}

	fmt.Fprintln(buf, "}")
	fmt.Fprintln(buf, ")")

	if *serviceTypeMaps {
		fmt.Fprintln(buf, "var (")
		fmt.Fprintln(buf, "ServiceType = map[PortProto]Service{")
		for _, array := range arrays {
			if len(array) == 0 {
				continue
			}
			name := array[0]
			{
				index := strings.IndexAny(name, "-/*")
				for index != -1 {
					if name[index+1] <= 'z' && name[index+1] >= 'a' {
						name = name[0:index] + string(name[index+1]-32) + name[index+2:]
					} else {
						name = name[0:index] + name[index+1:]
					}
					index = strings.IndexAny(name, "-/*")
				}
				name = strings.ReplaceAll(name, ".", "Dot")
				name = strings.ReplaceAll(name, "+", "Plus")
				name = strings.Title(name)
			}
			portproto := strings.Split(array[1], "/")
			port, err := strconv.Atoi(portproto[0])
			if err != nil {
				fmt.Printf("conv port err: %s\n", err)
				continue
			}
			proto := 6
			switch portproto[1] {
			case "udp":
				proto = 17
			case "sctp":
				proto = 132
			case "dccp":
				proto = 33
			}

			tmp := struct {
				ServiceName string
				Port        int
				Protocol    int
			}{}

			tmp.ServiceName = name
			tmp.Port = port
			tmp.Protocol = proto
			if err := serviceTypeMapTpl.Execute(buf, tmp); err != nil {
				fmt.Printf("tpl execute err: %s\n", err)
				continue
			}
		}
		fmt.Fprintln(buf, "}")
		fmt.Fprintln(buf, ")")
	}

	// end
	buf.WriteTo(writer)
}
