/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/singchia/go-xtables/pkg/cmd"
)

var (
	protocolLowerMaps = flag.Bool("proto_lower_maps", false, "gen protocol lower maps")
	serviceDefine     = flag.Bool("service_define", true, "whether service define")
	serviceTypeMaps   = flag.Bool("service_maps", false, "gen service maps")
)

const (
	linuxProtocolFile = "protocols"
	linuxServiceFile  = "services"
)

func iterate(file string, cb func(row []string) error) ([][]string, error) {
	fs, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fs.Close()

	rowses := [][]string{}

	reader := bufio.NewReader(fs)
	for {
		row, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if len(row) < 1 || row[0] == '#' || row[0] == ' ' {
			continue
		}
		rows := strings.Fields(row)
		if cb != nil {
			err = cb(rows)
			if err != nil {
				return nil, err
			}
		}
		rowses = append(rowses, rows)
	}
	return rowses, nil
}

const (
	outProtocol = "../pkg/network/protocol.go"
	outService  = "../pkg/network/service.go"
)

func main() {
	flag.Parse()
	// protocols
	arrays, err := iterate(linuxProtocolFile, nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	fdProtocol, err := os.OpenFile(outProtocol, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer fdProtocol.Close()

	genProtocols(arrays, fdProtocol)

	// services
	arrays, err = iterate(linuxServiceFile, nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	fdService, err := os.OpenFile(outService, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer fdService.Close()

	genServices(arrays, fdService)

	// format
	gofmt, err := exec.LookPath("gofmt")
	if err == nil {
		cmd.Cmd(gofmt, "-s", "-w", outProtocol)
		cmd.Cmd(gofmt, "-s", "-w", outService)
	}
}
