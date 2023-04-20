package network

import "testing"

func TestServiceName(t *testing.T) {
	for key := range ServicePortProtoMaps {
		name := key.Value()
		for _, char := range name {
			if (char < '0' || char > 'z') &&
				char != '+' && char != '-' &&
				char != '*' && char != '.' &&
				char != '_' && char != '/' {
				t.Error("illegal char", char, 'A', '9')
			}
		}
	}
}
