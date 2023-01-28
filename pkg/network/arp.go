package network

import (
	"strconv"
)

// refer to https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
type ARPOpCode uint16

func (opCode ARPOpCode) String() string {
	return strconv.Itoa(int(opCode))
}

func (opCode ARPOpCode) Hex() [2]byte {
	buf := [2]byte{}
	// little endian
	buf[0] = byte(opCode)
	buf[1] = byte(opCode >> 8)
	return buf
}

const (
	ARPOpCodeReserved              ARPOpCode = 0
	ARPOpCodeRequest               ARPOpCode = 1
	ARPOpCodeReply                 ARPOpCode = 2
	ARPOpCodeRequestReverse        ARPOpCode = 3
	ARPOpCodeReplyReverse          ARPOpCode = 4
	ARPOpCodeDRARPRequest          ARPOpCode = 5
	ARPOpCodeDRARPReply            ARPOpCode = 6
	ARPOpCodeDRARPError            ARPOpCode = 7
	ARPOpCodeInARPRequest          ARPOpCode = 8
	ARPOpCodeInARPReply            ARPOpCode = 9
	ARPOpCodeInARPNAK              ARPOpCode = 10
	ARPOpCodeMARSRequest           ARPOpCode = 11
	ARPOpCodeMARSMulti             ARPOpCode = 12
	ARPOpCodeMARSJoin              ARPOpCode = 14
	ARPOpCodeMARSLeave             ARPOpCode = 15
	ARPOpCodeMARSNAK               ARPOpCode = 16
	ARPOpCodeMARSUnserv            ARPOpCode = 17
	ARPOpCodeMARSSJoin             ARPOpCode = 18
	ARPOpCodeMARSSLeave            ARPOpCode = 19
	ARPOpCodeMARSSGrouplistRequest ARPOpCode = 20
	ARPOpCodeMARSSGrouplistReply   ARPOpCode = 21
	ARPOpCodeMARSSGrouplistMap     ARPOpCode = 22
	ARPOpCodeMAPOSUNARP            ARPOpCode = 23
	ARPOpCodeOPEXP1                ARPOpCode = 24
	ARPOpCodeOPEXP2                ARPOpCode = 25
)
