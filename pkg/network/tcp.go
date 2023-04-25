package network

type TCPFlag int

func (tcpFlag TCPFlag) String() string {
	flag := ""
	sep := ""
	if tcpFlag&TCPFlagFIN != 0 {
		flag += sep + "FIN"
		sep = ","
	}
	if tcpFlag&TCPFlagSYN != 0 {
		flag += sep + "SYN"
		sep = ","
	}
	if tcpFlag&TCPFlagRST != 0 {
		flag += sep + "RST"
		sep = ","
	}
	if tcpFlag&TCPFlagPSH != 0 {
		flag += sep + "PSH"
		sep = ","
	}
	if tcpFlag&TCPFlagACK != 0 {
		flag += sep + "ACK"
		sep = ","
	}
	if tcpFlag&TCPFlagURG != 0 {
		flag += sep + "URG"
		sep = ","
	}
	return flag
}

const (
	TCPFlagFIN TCPFlag = 1 << iota
	TCPFlagSYN
	TCPFlagRST
	TCPFlagPSH
	TCPFlagACK
	TCPFlagURG
	TCPFlagALL  TCPFlag = TCPFlagFIN | TCPFlagSYN | TCPFlagRST | TCPFlagPSH | TCPFlagACK | TCPFlagURG
	TCPFlagNONE TCPFlag = 0
)

var (
	TCPFlags = map[string]TCPFlag{
		"NONE": TCPFlagNONE,
		"FIN":  TCPFlagFIN,
		"SYN":  TCPFlagSYN,
		"RST":  TCPFlagRST,
		"PSH":  TCPFlagPSH,
		"ACK":  TCPFlagACK,
		"URG":  TCPFlagURG,
		"ALL":  TCPFlagALL,
	}
)

type TCPOpt uint8

func (tcpOpt TCPOpt) String() string {
	switch tcpOpt {
	case TCPOptMD5:
		return "md5"
	case TCPOptMSS:
		return "mss"
	case TCPOptWindowScale:
		return "wscale"
	case TCPOptSACKPermitted:
		return "sack-permitted"
	case TCPOptSACK:
		return "sack"
	case TCPOptTimestamp:
		return "timestamp"
	default:
		return ""
	}
}

const (
	TCPOptMD5           TCPOpt = 19
	TCPOptMSS           TCPOpt = 2
	TCPOptWindowScale   TCPOpt = 3
	TCPOptSACKPermitted TCPOpt = 4
	TCPOptSACK          TCPOpt = 5
	TCPOptTimestamp     TCPOpt = 8
)

var (
	TCPOpts = map[string]TCPOpt{
		"wscale":         TCPOptWindowScale,
		"mss":            TCPOptMSS,
		"sack-permitted": TCPOptSACKPermitted,
		"sack":           TCPOptSACK,
		"timestamp":      TCPOptTimestamp,
		"md5":            TCPOptMD5,
	}
)
