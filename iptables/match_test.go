package iptables

import "testing"

func TestMatchAddrType(t *testing.T) {
	mains := [][]byte{
		[]byte("ADDRTYPE match src-type !UNSPEC"),
		[]byte("ADDRTYPE match dst-typeUNSPEC"),
		[]byte("ADDRTYPE match dst-type UNSPEC limit-in"),
	}
	for _, main := range mains {
		mAddrType := &MatchAddrType{}
		index, ok := mAddrType.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index)
	}
}

func TestMatchAddrTypeShort(t *testing.T) {
	mAddrType, err := NewMatchAddrType(
		WithMatchAddrTypeSrcType(true, BLACKHOLE),
		WithMatchAddrTypeDstType(false, LOCAL),
		WithMatchAddrLimitIfaceIn(),
		WithMatchAddrLimitIfaceOut(),
	)
	if err != nil {
		t.Error(err)
	}
	t.Log(mAddrType.Short())
}

func TestMatchAH(t *testing.T) {
	mains := [][]byte{
		[]byte("ah spi:50"),
		[]byte("ah spi:!50"),
		[]byte("ah spis:50:60"),
		[]byte("ah spis:!50:60"),
		[]byte("ah spis:!50:60 Unknown invflags: 0xHex"),
		[]byte("ah spis:!50:60length:!1800 reserved"),
	}
	for _, main := range mains {
		mAH := &MatchAH{}
		index, ok := mAH.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mAH)
	}
}

func TestMatchBPF(t *testing.T) {
	mains := [][]byte{
		[]byte("match bpf 48 0 0 9,21 0 1 6,6 0 0 1,6 0 0 0\000"),
		[]byte("match bpf pinned /sys/fs/bpf/iptbpf"),
	}
	for _, main := range mains {
		mBPF := &MatchBPF{}
		index, ok := mBPF.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mBPF)
	}
}

func TestMatchCGroup(t *testing.T) {
	mains := [][]byte{
		[]byte("cgroup ! net_cls/mytask"),
		[]byte("cgroup net_cls/mytask"),
		[]byte("cgroup ! 10054"),
		[]byte("cgroup 1234"),
	}
	for _, main := range mains {
		mCG := &MatchCGroup{}
		index, ok := mCG.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mCG)
	}
}

func TestMatchCluster(t *testing.T) {
	mains := [][]byte{
		[]byte("cluster node_mask=0x00000001 total_nodes=2 hash_seed=0xdeadbeef"),
	}
	for _, main := range mains {
		mCluster := &MatchCluster{}
		index, ok := mCluster.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mCluster)
	}
}

func TestMatchComment(t *testing.T) {
	mains := [][]byte{
		[]byte("/* Austin added */"),
	}
	for _, main := range mains {
		mComment := &MatchComment{}
		index, ok := mComment.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mComment)
	}
}

func TestMatchConnBytes(t *testing.T) {
	mains := [][]byte{
		[]byte("! connbytes 10000:100000 connbytes mode bytes connbytes direction both"),
	}
	for _, main := range mains {
		mConnBytes := &MatchConnBytes{}
		index, ok := mConnBytes.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mConnBytes)
	}
}

func TestMatchConnLabel(t *testing.T) {
	mains := [][]byte{
		[]byte("connlabel ! 0"),
		[]byte("connlabel 'ftp'"),
		[]byte("connlabel 'ftp' set"),
	}
	for _, main := range mains {
		mConnLabel := &MatchConnLabel{}
		index, ok := mConnLabel.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mConnLabel)
	}
}

func TestMatchConnLimit(t *testing.T) {
	mains := [][]byte{
		[]byte("#conn src/24 > 16"),
	}
	for _, main := range mains {
		mConnLimit := &MatchConnLimit{}
		index, ok := mConnLimit.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mConnLimit)
	}
}

func TestMatchConnMark(t *testing.T) {
	mains := [][]byte{
		[]byte("connmark match  0x14/0x2"),
		[]byte("connmark match ! 0x14"),
	}
	for _, main := range mains {
		mConnMark := &MatchConnMark{}
		index, ok := mConnMark.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mConnMark)
	}
}

func TestMatchConnTrack(t *testing.T) {
	mains := [][]byte{
		[]byte("ctstate RELATED,ESTABLISHED"),
		[]byte("! ctproto 6"),
		[]byte("ctstate NEW ctproto 6 ctorigsrc 192.168.0.0/24 ctorigdstport 80:65535"),
	}
	for _, main := range mains {
		mConnTrack := &MatchConnTrack{}
		index, ok := mConnTrack.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mConnTrack)
	}
}

func TestMatchCPU(t *testing.T) {
	mains := [][]byte{
		[]byte("cpu 1"),
	}
	for _, main := range mains {
		mCPU := &MatchCPU{}
		index, ok := mCPU.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mCPU)
	}
}

func TestMatchDCCP(t *testing.T) {
	mains := [][]byte{
		[]byte("dccp spt:80 0,1,2,3,4 option=!1"),
	}
	for _, main := range mains {
		mDCCP := &MatchDCCP{}
		index, ok := mDCCP.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mDCCP)
	}
}

func TestMatchDevGroup(t *testing.T) {
	mains := [][]byte{
		[]byte("src-group 0x1"),
		[]byte("! dst-group 0x1"),
	}
	for _, main := range mains {
		mDevGroup := &MatchDevGroup{}
		index, ok := mDevGroup.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mDevGroup)
	}
}

func TestMatchDSCP(t *testing.T) {
	mains := [][]byte{
		[]byte("DSCP match 0x00"),
		[]byte("DSCP match !0x00"),
	}
	for _, main := range mains {
		mDSCP := &MatchDSCP{}
		index, ok := mDSCP.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mDSCP)
	}
}

func TestMatchDst(t *testing.T) {
	mains := [][]byte{
		[]byte("dst length:42 opts 149:92,12:12,123:12 "),
		[]byte("dst length:42 opts 150,12:12,123:12 "),
	}
	for _, main := range mains {
		mDst := &MatchDst{}
		index, ok := mDst.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mDst)
	}
}

func TestMatchECN(t *testing.T) {
	mains := [][]byte{
		[]byte("ECN match ECE !ECT=3"),
	}
	for _, main := range mains {
		mECN := &MatchECN{}
		index, ok := mECN.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mECN)
	}
}

func TestMatchESP(t *testing.T) {
	mains := [][]byte{
		[]byte("esp spi:50"),
		[]byte("esp spi:!50"),
		[]byte("esp spis:50:60"),
		[]byte("esp spis:!50:60"),
		[]byte("esp spis:!50:60 Unknown invflags: 0xHex"),
	}
	for _, main := range mains {
		mESP := &MatchESP{}
		index, ok := mESP.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index)
	}
}

func TestMatchEUI64(t *testing.T) {
	mains := [][]byte{
		[]byte("eui64"),
	}
	for _, main := range mains {
		mEUI64 := &MatchEUI64{}
		index, ok := mEUI64.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mEUI64)
	}
}

func TestMatchFrag(t *testing.T) {
	mains := [][]byte{
		[]byte("frag ids:1:42 last"),
	}
	for _, main := range mains {
		mFrag := &MatchFrag{}
		index, ok := mFrag.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mFrag)
	}
}

func TestMatchHashLimit(t *testing.T) {
	mains := [][]byte{
		[]byte("limit: up to 1000/sec burst 5 mode srcip"),
		[]byte("limit: above 512kb/s mode srcip-srcport-dstip-dstport"),
	}
	for _, main := range mains {
		mHashLimit := &MatchHashLimit{}
		index, ok := mHashLimit.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mHashLimit)
	}
}

func TestMatchHBH(t *testing.T) {
	mains := [][]byte{
		[]byte("hbh length:!42 opts 1:2,23:42,4:6,8:10,42,23,4:5"),
	}
	for _, main := range mains {
		mHBH := &MatchHBH{}
		index, ok := mHBH.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mHBH)
	}
}

func TestMatchHelper(t *testing.T) {
	mains := [][]byte{
		[]byte("helper match \"ftp-2121\""),
	}
	for _, main := range mains {
		mHelper := &MatchHelper{}
		index, ok := mHelper.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mHelper)
	}
}

func TestMatchHL(t *testing.T) {
	mains := [][]byte{
		[]byte("HL match HL > 42"),
	}
	for _, main := range mains {
		mHL := &MatchHL{}
		index, ok := mHL.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mHL)
	}
}

func TestMatchICMP(t *testing.T) {
	mains := [][]byte{
		[]byte("ipv6-icmptype 2 code 8"),
		[]byte("ipv6-icmp !type 2 codes 8-10"),
		[]byte("ipv6-icmp no-route"),
		[]byte("ipv6-icmp packet-too-big"),
		[]byte("icmp any"),
	}
	for _, main := range mains {
		mICMP := &MatchICMP{}
		index, ok := mICMP.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mICMP)
	}
}

func TestMatchIPRange(t *testing.T) {
	mains := [][]byte{
		[]byte("source IP range 192.168.0.1-192.168.0.255"),
	}
	for _, main := range mains {
		mIPRange := &MatchIPRange{}
		index, ok := mIPRange.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mIPRange)
	}
}

func TestMatchIPv6Header(t *testing.T) {
	mains := [][]byte{
		[]byte("ipv6header flags:0x41"),
		[]byte("ipv6header flags:ipv6-opts"),
		[]byte("ipv6header flags:!ipv6-opts"),
		[]byte("ipv6header flags:ipv6-opts,esp"),
	}
	for _, main := range mains {
		mIPv6Header := &MatchIPv6Header{}
		index, ok := mIPv6Header.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mIPv6Header)
	}
}

func TestMatchIPVS(t *testing.T) {
	mains := [][]byte{
		[]byte("! vproto 6 vaddr 192.168.0.0/24"),
		[]byte("! ipvs"),
	}
	for _, main := range mains {
		mIPVS := &MatchIPVS{}
		index, ok := mIPVS.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mIPVS)
	}
}

func TestMatchLength(t *testing.T) {
	mains := [][]byte{
		[]byte("length 0:60"),
	}
	for _, main := range mains {
		mLength := &MatchLength{}
		index, ok := mLength.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mLength)
	}
}

func TestMatchLimit(t *testing.T) {
	mains := [][]byte{
		[]byte("limit: avg 3/hour burst 5"),
	}
	for _, main := range mains {
		mLimit := &MatchLimit{}
		index, ok := mLimit.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mLimit)
	}
}

func TestMatchMAC(t *testing.T) {
	mains := [][]byte{
		[]byte("MACaa:bb:cc:dd:ee:ff"),
		[]byte("MAC !aa:bb:cc:dd:ee:ff"),
	}
	for _, main := range mains {
		mMAC := &MatchMAC{}
		index, ok := mMAC.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mMAC)
	}
}

func TestMatchMark(t *testing.T) {
	mains := [][]byte{
		[]byte("mark match 0x1/0x3"),
	}
	for _, main := range mains {
		mMark := &MatchMark{}
		index, ok := mMark.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mMark)
	}
}

func TestMatchMH(t *testing.T) {
	mains := [][]byte{
		[]byte("mh 4:123"),
		[]byte("mh careof-test:123"),
		[]byte("mh !4"),
		[]byte("mh !careof-test"),
		[]byte("mh !careof-test:binding-error"),
	}
	for _, main := range mains {
		mMH := &MatchMH{}
		index, ok := mMH.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mMH)
	}
}

func TestMatchMultiPort(t *testing.T) {
	mains := [][]byte{
		[]byte("multiport sports 50:51"),
	}
	for _, main := range mains {
		mMultiPort := &MatchMultiPort{}
		index, ok := mMultiPort.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mMultiPort)
	}
}

func TestMatchNFAcct(t *testing.T) {
	mains := [][]byte{
		[]byte("nfacct-name  http-traffic"),
	}
	for _, main := range mains {
		mNFAcct := &MatchNFAcct{}
		index, ok := mNFAcct.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mNFAcct)
	}
}

func TestMatchOSF(t *testing.T) {
	mains := [][]byte{
		[]byte("OS fingerprint match Linux"),
	}
	for _, main := range mains {
		mOSF := &MatchOSF{}
		index, ok := mOSF.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mOSF)
	}
}

func TestMatchOwner(t *testing.T) {
	mains := [][]byte{
		[]byte("owner socket exists owner UID match 0 owner GID match 0 incl. suppl. groups"),
		[]byte("owner socket exists owner UID match root owner GID match root incl. suppl. groups"),
		[]byte("owner UID match 0"),
		[]byte("owner UID match 1-999"),
	}
	for _, main := range mains {
		mOwner := &MatchOwner{}
		index, ok := mOwner.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mOwner)
	}
}

func TestMatchPhysDev(t *testing.T) {
	mains := [][]byte{
		[]byte("PHYSDEV match ! --physdev-in enp0s3 --physdev-out docker0 ! --physdev-is-bridged"),
	}
	for _, main := range mains {
		mPhysDev := &MatchPhysDev{}
		index, ok := mPhysDev.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mPhysDev)
	}
}

func TestMatchPktType(t *testing.T) {
	mains := [][]byte{
		[]byte("PKTTYPE = unicast"),
	}
	for _, main := range mains {
		mPktType := &MatchPktType{}
		index, ok := mPktType.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mPktType)
	}
}

func TestMatchPolicy(t *testing.T) {
	mains := [][]byte{
		[]byte("policy match dir in pol ipsec strict [0] reqid 1 spi 0x1 proto ipcomp mode tunnel tunnel-dst 10.0.0.0/8 tunnel-src 10.0.0.0/8 [1] reqid 2"),
		[]byte("policy match dir in pol ipsec strict [0] reqid 1 spi 0x1 proto ipcomp mode tunnel tunnel-dst 10.0.0.0/8 tunnel-src 10.0.0.0/8 [1] reqid 2 foo"),
	}
	for _, main := range mains {
		mPolicy := &MatchPolicy{}
		index, ok := mPolicy.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, len(main), *mPolicy)
		for i, elem := range mPolicy.Elements {
			t.Log(i, elem)
		}
	}
}

func TestMatchQuota(t *testing.T) {
	mains := [][]byte{
		[]byte("quota: 50 bytes"),
	}
	for _, main := range mains {
		mQuota := &MatchQuota{}
		index, ok := mQuota.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mQuota)
	}
}

func TestMatchRateEst(t *testing.T) {
	mains := [][]byte{
		[]byte("rateest match RE1 delta pps 0 lt RE2 pps 42"),
		[]byte("rateest match RE1 delta bps 16bit 0bit gt"),
	}
	for _, main := range mains {
		mRateEst := &MatchRateEst{}
		index, ok := mRateEst.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mRateEst)
	}
}

func TestMatchRealm(t *testing.T) {
	mains := [][]byte{
		[]byte("realm 0x1/0x2a"),
		[]byte("realm cosmos"),
	}
	for _, main := range mains {
		mRealm := &MatchRealm{}
		index, ok := mRealm.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mRealm)
	}
}

func TestMatchRecent(t *testing.T) {
	mains := [][]byte{
		[]byte("recent: UPDATE seconds: 300 hit_count: 3 name: SSH side: source mask: 255.255.255.255"),
	}
	for _, main := range mains {
		mRecent := &MatchRecent{}
		index, ok := mRecent.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mRecent, len(mRecent.Mask))
	}

}

func TestMatchRPFilter(t *testing.T) {
	mains := [][]byte{
		[]byte("rpfilter loose validmark accept-local invert"),
	}
	for _, main := range mains {
		mRPFilter := &MatchRPFilter{}
		index, ok := mRPFilter.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mRPFilter)
	}
}

func TestMatchRT(t *testing.T) {
	mains := [][]byte{
		[]byte("rt type:0 segslefts:!1:23 length:!42 reserved 0-addrs 2001:db8:85a3::8a2e:370:7334"),
		[]byte("rt type:0 segslefts:!1:23 length:!42 reserved 0-addrs 2001:db8:85a3::8a2e:370:7334,2001:db8:85a3::8a2e:370:7339"),
	}
	for _, main := range mains {
		mRT := &MatchRT{}
		index, ok := mRT.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mRT)
	}
}

func TestMatchSCTP(t *testing.T) {
	mains := [][]byte{
		[]byte("sctp any DATA:Be,INIT"),
		[]byte("sctp any 0x0000:Be,0x0001"),
		[]byte("sctp spts:2603:2610 any 0x0000:Be,0x0001"),
	}
	for _, main := range mains {
		mSCTP := &MatchSCTP{}
		index, ok := mSCTP.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mSCTP)
	}
}

func TestMatchSet(t *testing.T) {
	mains := [][]byte{
		[]byte("match-set foo src,src"),
		[]byte("match-set foo src,src return-nomatch bytes-lt 1000"),
	}
	for _, main := range mains {
		mSet := &MatchSet{}
		index, ok := mSet.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mSet)
	}
}

func TestMatchSocket(t *testing.T) {
	mains := [][]byte{
		[]byte("socket --transparent --restore-skmark"),
	}
	for _, main := range mains {
		mSocket := &MatchSocket{}
		index, ok := mSocket.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mSocket)
	}
}

func TestMatchState(t *testing.T) {
	mains := [][]byte{
		[]byte("! state INVALID,NEW"),
	}
	for _, main := range mains {
		mState := &MatchState{}
		index, ok := mState.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mState)
	}
}

func TestMatchStatis(t *testing.T) {
	mains := [][]byte{
		[]byte("statistic mode random probability 0.00000018021"),
		[]byte("statistic mode nth every 2 packet 1"),
	}
	for _, main := range mains {
		mStatis := &MatchStatistic{}
		index, ok := mStatis.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mStatis)
	}
}

func TestMatchString(t *testing.T) {
	mains := [][]byte{
		[]byte(`STRING match  "|03777777096e657466696c746572036f7267005c3122|" ALGO name bm FROM 40 TO 57`),
		[]byte(`STRING match  "|03|www|09|netfilter|03|org|00|\\1\"" ALGO name bm FROM 40 TO 57`),
	}
	for _, main := range mains {
		mString := &MatchString{}
		index, ok := mString.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mString)
	}
}

func TestMatchTCP(t *testing.T) {
	mains := [][]byte{
		[]byte(`tcp flags:FIN,SYN,RST,ACK/SYN`),
		[]byte(`tcp flags:0x17/0x02`),
		[]byte(`tcp spt:1234 dpt:!80 option=8 flags:!FIN,SYN,RST,ACK,URG/SYN,URG`),
	}
	for _, main := range mains {
		mTCP := &MatchTCP{}
		index, ok := mTCP.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mTCP)
	}
}

func TestMatchTCPMSS(t *testing.T) {
	mains := [][]byte{
		[]byte(`tcpmss match 64:1200`),
		[]byte(`tcpmss match !64:1200`),
	}
	for _, main := range mains {
		mTCPMSS := &MatchTCPMSS{}
		index, ok := mTCPMSS.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mTCPMSS)
	}
}

func TestMatchTime(t *testing.T) {
	mains := [][]byte{
		[]byte(`TIME on Mon,Sun on 1st,3rd,5th starting from 2007-01-01 00:00:00 until date 2009-01-01 00:00:00`),
	}
	for _, main := range mains {
		mTime := &MatchTime{}
		index, ok := mTime.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mTime)
	}
}

func TestMatchTOS(t *testing.T) {
	mains := [][]byte{
		[]byte(`tos match Minimize-Delay`),
		[]byte(`tos match0x18/0x3f`),
	}
	for _, main := range mains {
		mTOS := &MatchTOS{}
		index, ok := mTOS.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mTOS)
	}
}

func TestMatchTTL(t *testing.T) {
	mains := [][]byte{
		[]byte("TTL match TTL == 255"),
	}
	for _, main := range mains {
		mTTL := &MatchTTL{}
		index, ok := mTTL.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mTTL)
	}
}

func TestMatchU32(t *testing.T) {
	mains := [][]byte{
		[]byte(`u32 "0x6&0xff=0x11&&0x4&0x1fff=0x0&&0x0>>0x16&0x3c@0x0&0xffff=0x35&&0x0>>0x16&0x3c@0x8>>0xf&0x1=0x1"`),
		[]byte(`u32 ! "0x0=0x0&&0x0=0x1"`),
	}
	for _, main := range mains {
		mU32 := &MatchU32{}
		index, ok := mU32.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mU32)
	}
}

func TestMatchUDP(t *testing.T) {
	mains := [][]byte{
		[]byte(`udp spts:50:8000`),
	}
	for _, main := range mains {
		mUDP := &MatchUDP{}
		index, ok := mUDP.Parse(main)
		if !ok {
			t.Errorf("not found")
			return
		}
		t.Log(index, *mUDP)
	}
}
