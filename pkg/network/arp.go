package network

import (
	"strconv"
	"strings"
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

func ParseARPOpCode(code string) (ARPOpCode, error) {
	cd, err := strconv.ParseUint(code, 10, 16)
	if err == nil {
		return ARPOpCode(cd), nil
	}
	switch strings.ToUpper(code) {
	case "REQUEST":
		return ARPOpCodeRequest, nil
	case "REPLY":
		return ARPOpCodeReply, nil
	case "REQUEST_REVERSE":
		return ARPOpCodeRequestReverse, nil
	case "REPLY_REVERSE":
		return ARPOpCodeReplyReverse, nil
	case "DRARP_REQUEST":
		return ARPOpCodeDRARPRequest, nil
	case "DRARP_REPLY":
		return ARPOpCodeDRARPReply, nil
	case "DRARP_ERROR":
		return ARPOpCodeDRARPError, nil
	case "INARP_REQUEST":
		return ARPOpCodeInARPRequest, nil
	case "ARP_NAK":
		// ebtables bug, the decimal should be 9.
		return ARPOpCodeInARPNAK, nil
	}
	return 0, err
}
