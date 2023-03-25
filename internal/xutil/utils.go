package xutil

import (
	"errors"
	"strconv"
)

var asciiSpace = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}

func ErrAndStdErr(err error, stderr []byte) error {
	return errors.New(err.Error() + ";" + string(stderr))
}

func NFields(s []byte, n int) ([][]byte, int) {
	a := make([][]byte, n)
	na := 0
	fieldStart := 0
	i := 0
	// Skip spaces in the front of the input.
	for i < len(s) && asciiSpace[s[i]] != 0 {
		i++
	}
	fieldStart = i
	for i < len(s) {
		if asciiSpace[s[i]] == 0 {
			i++
			continue
		}
		a[na] = s[fieldStart:i:i]
		na++
		i++
		// Skip spaces in between fields.
		for i < len(s) && asciiSpace[s[i]] != 0 {
			i++
		}
		fieldStart = i
		if na == n {
			break
		}
	}
	return a, i
}

func UnfoldDecimal(decimal string) (int64, error) {
	lastPart := decimal[len(decimal)-1]
	numPart := decimal[0 : len(decimal)-1]
	switch lastPart {
	case 'k', 'K':
		num, err := strconv.ParseInt(numPart, 10, 64)
		if err != nil {
			return num, err
		}
		return num * 1024, nil
	case 'm', 'M':
		num, err := strconv.ParseInt(numPart, 10, 64)
		if err != nil {
			return num, err
		}
		return num * 1024 * 1024, nil
	case 'g', 'G':
		num, err := strconv.ParseInt(numPart, 10, 64)
		if err != nil {
			return num, err
		}
		return num * 1024 * 1024 * 1024, nil
	case 't', 'T':
		num, err := strconv.ParseInt(numPart, 10, 64)
		if err != nil {
			return num, err
		}
		return num * 1024 * 1024 * 1024 * 1024, nil
	case 'p', 'P':
		num, err := strconv.ParseInt(numPart, 10, 64)
		if err != nil {
			return num, err
		}
		return num * 1024 * 1024 * 1024 * 1024 * 1024, nil
	case 'z', 'Z':
		num, err := strconv.ParseInt(numPart, 10, 64)
		if err != nil {
			return num, err
		}
		return num * 1024 * 1024 * 1024 * 1024 * 1024 * 1024, nil
	}
	return strconv.ParseInt(decimal, 10, 64)
}
