package xutil

var asciiSpace = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}

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
