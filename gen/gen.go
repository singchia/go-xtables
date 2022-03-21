/*
 * Apache License 2.0
 *
 * Copyright (c) 2022, Austin Zhai
 * All rights reserved.
 */
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	linuxProtocolFile = "protocols"
)

func iterate(cb func(row []string) error) ([][]string, error) {
	fs, err := os.Open(linuxProtocolFile)
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
	outProtocol = "./protocol.go"
)

func main() {
	arrays, err := iterate(nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	fd, err := os.OpenFile(outProtocol, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer fd.Close()

	genProtocols(arrays, fd)
}
