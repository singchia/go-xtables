package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
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

	rows := [][]string{}

	cr := csv.NewReader(fs)
	for {
		row, err := cr.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if cb != nil {
			err = cb(row)
			if err != nil {
				return nil, err
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func main() {
	fmt.Println("vim-go")
}
