package network

// see https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/in[6].h
type IPv6Option struct {
	Type   int
	Length int
}

// IP headers
type IPv6HeaderType uint8

func (ipHeaderType IPv6HeaderType) String() string {
	switch ipHeaderType {
	case IPv6HeaderTypeHOPOPTS:
		return "hop"
	case IPv6HeaderTypeDSTOPTS:
		return "dst"
	case IPv6HeaderTypeROUTING:
		return "route"
	case IPv6HeaderTypeFRAGMENT:
		return "frag"
	case IPv6HeaderTypeAH:
		return "auth"
	case IPv6HeaderTypeESP:
		return "esp"
	case IPv6HeaderTypeNONE:
		return "none"
	case IPv6HeaderTypeRAW:
		return "proto"
	default:
		return ""
	}
}

const (
	IPv6HeaderTypeESP IPv6HeaderType = 50
	IPv6HeaderTypeAH  IPv6HeaderType = 51
	IPv6HeaderTypeRAW IPv6HeaderType = 255
	// IPv6 extension headers
	IPv6HeaderTypeHOPOPTS  IPv6HeaderType = 0
	IPv6HeaderTypeROUTING  IPv6HeaderType = 43
	IPv6HeaderTypeFRAGMENT IPv6HeaderType = 44
	IPv6HeaderTypeICMPV6   IPv6HeaderType = 58
	IPv6HeaderTypeNONE     IPv6HeaderType = 59
	IPv6HeaderTypeDSTOPTS  IPv6HeaderType = 60
	IPv6HeaderTypeMH       IPv6HeaderType = 135

	// mask
	MaskHOPOPTS  IPv6HeaderType = 128
	MaskDSTOPTS  IPv6HeaderType = 64
	MaskROUTING  IPv6HeaderType = 32
	MaskFRAGMENT IPv6HeaderType = 16
	MaskAH       IPv6HeaderType = 8
	MaskESP      IPv6HeaderType = 4
	MaskNONE     IPv6HeaderType = 2
	MaskPROTO    IPv6HeaderType = 1
)

var (
	IPv6HeaderTypeMasks = [...]IPv6HeaderType{
		MaskHOPOPTS, MaskDSTOPTS, MaskROUTING, MaskFRAGMENT,
		MaskAH, MaskESP, MaskNONE, MaskPROTO}

	IPv6HeaderTypeMaskMap = map[IPv6HeaderType]IPv6HeaderType{
		MaskHOPOPTS:  IPv6HeaderTypeHOPOPTS,
		MaskDSTOPTS:  IPv6HeaderTypeDSTOPTS,
		MaskROUTING:  IPv6HeaderTypeROUTING,
		MaskFRAGMENT: IPv6HeaderTypeFRAGMENT,
		MaskAH:       IPv6HeaderTypeAH,
		MaskESP:      IPv6HeaderTypeESP,
		MaskNONE:     IPv6HeaderTypeNONE,
		MaskPROTO:    IPv6HeaderTypeRAW,
	}
)

var (
	IPv6HeaderTypes = map[string]IPv6HeaderType{
		"hop":        IPv6HeaderTypeHOPOPTS,
		"hop-by-hop": IPv6HeaderTypeHOPOPTS,
		"dst":        IPv6HeaderTypeDSTOPTS,
		"ipv6-opts":  IPv6HeaderTypeDSTOPTS,
		"route":      IPv6HeaderTypeROUTING,
		"ipv6-route": IPv6HeaderTypeROUTING,
		"frag":       IPv6HeaderTypeFRAGMENT,
		"ipv6-frag":  IPv6HeaderTypeFRAGMENT,
		"auth":       IPv6HeaderTypeAH,
		"ah":         IPv6HeaderTypeAH,
		"esp":        IPv6HeaderTypeESP,
		"none":       IPv6HeaderTypeNONE,
		"ipv6-nonxt": IPv6HeaderTypeNONE,
		"prot":       IPv6HeaderTypeRAW,
		"protocol":   IPv6HeaderTypeRAW,
	}
)
