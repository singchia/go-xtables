package iptables

import (
	"testing"
)

func TestTargetAudit(t *testing.T) {
	mains := [][]byte{
		[]byte("AUDIT accept"),
	}
	for _, main := range mains {
		tAudit := &TargetAudit{}
		index, ok := tAudit.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tAudit)
	}
}

func TestTargetChecksum(t *testing.T) {
	mains := [][]byte{
		[]byte("CHECKSUM fill"),
	}
	for _, main := range mains {
		tCS := &TargetChecksum{}
		index, ok := tCS.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tCS)
	}
}

func TestTargetClassify(t *testing.T) {
	mains := [][]byte{
		[]byte("CLASSIFY set 0:ffff"),
	}
	for _, main := range mains {
		tClassify := &TargetClassify{}
		index, ok := tClassify.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tClassify)
	}
}

func TestTargetClusterIP(t *testing.T) {
	mains := [][]byte{
		[]byte("CLUSTERIP hashmode=sourceip clustermac=01:AA:7B:47:F7:D7 total_nodes=2 local_node=1 hash_init=1"),
	}
	for _, main := range mains {
		tClusterIP := &TargetClusterIP{}
		index, ok := tClusterIP.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tClusterIP)
	}
}

func TestTargetConnMark(t *testing.T) {
	mains := [][]byte{
		[]byte("CONNMARK save nfmask 0x1 ctmask ~0x2"),
	}
	for _, main := range mains {
		tConnMark := &TargetConnMark{}
		index, ok := tConnMark.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tConnMark)
	}
}

func TestTargetConnSecMark(t *testing.T) {
	mains := [][]byte{
		[]byte("CONNSECMARK restore"),
	}
	for _, main := range mains {
		tConnSecMark := &TargetConnSecMark{}
		index, ok := tConnSecMark.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tConnSecMark)
	}
}

func TestTargetCT(t *testing.T) {
	mains := [][]byte{
		[]byte("CT ctevents new,related,destroy,reply,assured,protoinfo,helper,mark zone-orig mark"),
	}
	for _, main := range mains {
		tCT := &TargetCT{}
		index, ok := tCT.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tCT)
	}
}

func TestTargetDNAT(t *testing.T) {
	mains := [][]byte{
		[]byte("to:1.1.1.1-1.1.1.10:1025-65535"),
		[]byte("to:[dead::beef-dead::fee7]:1025-65535 random"),
	}
	for _, main := range mains {
		tDNAT := &TargetDNAT{}
		index, ok := tDNAT.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tDNAT)
	}
}

func TestTargetDNPT(t *testing.T) {
	mains := [][]byte{
		[]byte("DNPT src-pfx dead::/64 dst-pfx 1c3::/64"),
	}
	for _, main := range mains {
		tDNPT := &TargetDNPT{}
		index, ok := tDNPT.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tDNPT)
	}
}

func TestTargetECN(t *testing.T) {
	mains := [][]byte{
		[]byte("ECN TCP remove"),
	}
	for _, main := range mains {
		tECN := &TargetECN{}
		index, ok := tECN.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tECN)
	}
}

func TestTargetHL(t *testing.T) {
	mains := [][]byte{
		[]byte("HL set to 4"),
	}
	for _, main := range mains {
		tHL := &TargetHL{}
		index, ok := tHL.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tHL)
	}
}

func TestTargetHMark(t *testing.T) {
	mains := [][]byte{
		[]byte("HMARK mod 42 + 0x1 ct, src-prefix 32 dst-prefix 32 sport-mask 0xffff dport-mask 0xffff proto-mask 0xffff rnd 0x4 "),
	}
	for _, main := range mains {
		tHMark := &TargetHMark{}
		index, ok := tHMark.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tHMark)
	}
}

func TestTargetIdleTimer(t *testing.T) {
	mains := [][]byte{
		[]byte("timeout:42 label:foo"),
	}
	for _, main := range mains {
		tIdleTimer := &TargetIdleTimer{}
		index, ok := tIdleTimer.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tIdleTimer)
	}
}

func TestTargetLED(t *testing.T) {
	mains := [][]byte{
		[]byte(`led-trigger-id:"s\"sh2" led-delay:1ms`),
	}
	for _, main := range mains {
		tLED := &TargetLED{}
		index, ok := tLED.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tLED)
	}
}

func TestTargetLOG(t *testing.T) {
	mains := [][]byte{
		[]byte(`LOG flags 0 level 1 prefix "test: "`),
		[]byte(`LOG flags 1 level 1 prefix "test: "`),
		[]byte(`LOG level debug prefix "test: "`),
	}
	for _, main := range mains {
		tLOG := &TargetLog{}
		index, ok := tLOG.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tLOG)
	}
}

func TestTargetMark(t *testing.T) {
	mains := [][]byte{
		[]byte(`MARK xset 0x1/0x3`),
	}
	for _, main := range mains {
		tMark := &TargetMark{}
		index, ok := tMark.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tMark)
	}
}

func TestTargetMasquerade(t *testing.T) {
	mains := [][]byte{
		[]byte(`random-fully`),
		[]byte(`random`),
		[]byte(`masq ports: 50000-50100 random`),
	}
	for _, main := range mains {
		tMasquerade := &TargetMasquerade{}
		index, ok := tMasquerade.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, len(main), *tMasquerade)
	}
}

func TestTargetNetmap(t *testing.T) {
	mains := [][]byte{
		[]byte(`to:192.168.199.0/24`),
		[]byte(`to:dead::/64`),
	}
	for _, main := range mains {
		tNetmap := &TargetNetmap{}
		index, ok := tNetmap.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, len(main), *tNetmap)
	}
}

func TestTargetNFLog(t *testing.T) {
	mains := [][]byte{
		[]byte(`nflog-prefix  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx nflog-group 40`),
	}
	for _, main := range mains {
		tNFLog := &TargetNFLog{}
		index, ok := tNFLog.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, len(main), *tNFLog)
	}
}

func TestTargetNFQueue(t *testing.T) {
	mains := [][]byte{
		[]byte(`NFQUEUE balance 0:6 bypass cpu-fanout`),
	}
	for _, main := range mains {
		tNFQueue := &TargetNFQueue{}
		index, ok := tNFQueue.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, len(main), *tNFQueue)
	}
}

func TestTargetRateEst(t *testing.T) {
	mains := [][]byte{
		[]byte(`name RE2 interval 250.0ms ewmalog 500.0us`),
	}
	for _, main := range mains {
		tRateEst := &TargetRateEst{}
		index, ok := tRateEst.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, len(main), *tRateEst)
	}
}

func TestTargetRedirect(t *testing.T) {
	mains := [][]byte{
		[]byte(`redir ports 42-1234 random`),
		[]byte(``),
	}
	for _, main := range mains {
		tRedirect := &TargetRedirect{}
		index, ok := tRedirect.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, len(main), *tRedirect)
	}
}

func TestTargetReject(t *testing.T) {
	mains := [][]byte{
		[]byte(`reject-with icmp-proto-unreachable`),
	}
	for _, main := range mains {
		tReject := &TargetReject{}
		index, ok := tReject.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, len(main), *tReject)
	}
}

func TestTargetSame(t *testing.T) {
	mains := [][]byte{
		[]byte(`same: 192.168.1.0-192.168.1.260 nodst random `),
	}
	for _, main := range mains {
		tSame := &TargetSame{}
		index, ok := tSame.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, len(main), *tSame)
	}
}

func TestTargetSecMark(t *testing.T) {
	mains := [][]byte{
		[]byte(`SECMARK selctx httpcontext`),
	}
	for _, main := range mains {
		tSecMark := &TargetSecMark{}
		index, ok := tSecMark.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, len(main), *tSecMark)
	}
}

func TestTargetSet(t *testing.T) {
	mains := [][]byte{
		[]byte(`del-set knock2 src`),
		[]byte(`add-set knock2 src timeout 4`),
		[]byte(`add-set knock2 src timeout 4`),
		[]byte(`add-set knock2 src exist timeout 4`),
		[]byte(`map-set knock2 src,src map-mark map-prio`),
	}
	for _, main := range mains {
		tSet := &TargetSet{}
		index, ok := tSet.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, len(main), *tSet)
	}
}

func TestTargetSNAT(t *testing.T) {
	mains := [][]byte{
		[]byte("to:[dead::beef-dead::fee7]:1025-65535"),
		[]byte("to:[dead::beef-dead::fee7]:1025-65535 random"),
	}
	for _, main := range mains {
		tSNAT := &TargetSNAT{}
		index, ok := tSNAT.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tSNAT)
	}
}

func TestTargetSNPT(t *testing.T) {
	mains := [][]byte{
		[]byte("SNPT src-pfx dead::/64 dst-pfx 1c3::/64"),
	}
	for _, main := range mains {
		tSNPT := &TargetSNPT{}
		index, ok := tSNPT.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tSNPT)
	}
}

func TestTargetSYNProxy(t *testing.T) {
	mains := [][]byte{
		[]byte("SYNPROXY sack-perm timestamp wscale 9 mss 1460 "),
	}
	for _, main := range mains {
		tSYNProxy := &TargetSYNProxy{}
		index, ok := tSYNProxy.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tSYNProxy)
	}
}

func TestTargetTCPMSS(t *testing.T) {
	mains := [][]byte{
		[]byte("TCPMSS set 42"),
		[]byte("TCPMSS clamp to PMTU"),
	}
	for _, main := range mains {
		tTCPMSS := &TargetTCPMSS{}
		index, ok := tTCPMSS.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tTCPMSS)
	}
}

func TestTargetTCPOptStrip(t *testing.T) {
	mains := [][]byte{
		[]byte("TCPOPTSTRIP options mss,wscale,sack-permitted,sack,6,7"),
		[]byte("TCPOPTSTRIP options 2,3,4,5,6,7"),
	}
	for _, main := range mains {
		tTCPOptStrip := &TargetTCPOptStrip{}
		index, ok := tTCPOptStrip.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tTCPOptStrip)
	}
}

func TestTargetTEE(t *testing.T) {
	mains := [][]byte{
		[]byte("TEE gw:192.168.3.100"),
		[]byte("TEE gw:2001:db8::1"),
	}
	for _, main := range mains {
		tTEE := &TargetTEE{}
		index, ok := tTEE.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tTEE)
	}
}

func TestTargetTOS(t *testing.T) {
	mains := [][]byte{
		[]byte("TOS set 0x10/0x3f"),
	}
	for _, main := range mains {
		tTOS := &TargetTOS{}
		index, ok := tTOS.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tTOS)
	}
}

func TestTargetTProxy(t *testing.T) {
	mains := [][]byte{
		[]byte("TPROXY redirect 10.0.0.1:12345 mark 0x23/0xff"),
	}
	for _, main := range mains {
		tTProxy := &TargetTProxy{}
		index, ok := tTProxy.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tTProxy)
	}
}

func TestTargetTTL(t *testing.T) {
	mains := [][]byte{
		[]byte("TTL set to 42"),
	}
	for _, main := range mains {
		tTTL := &TargetTTL{}
		index, ok := tTTL.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tTTL)
	}
}

func TestTargetULOG(t *testing.T) {
	mains := [][]byte{
		[]byte(`ULOG copy_range 1 nlgroup 2 prefix "foo" queue_threshold 10`),
		[]byte(`ULOG copy_range 1 nlgroup 2 prefix "f\\oo" queue_threshold 10`),
		[]byte(`ULOG copy_range 1 nlgroup 2 queue_threshold 11`),
	}
	for _, main := range mains {
		tULOG := &TargetULog{}
		index, ok := tULOG.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *tULOG)
	}
}
