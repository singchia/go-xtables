package iptables

import (
	"net"
	"testing"

	"github.com/singchia/go-xtables"
	"github.com/singchia/go-xtables/pkg/network"
)

func Test_baseMatch_Parse(t *testing.T) {
	type fields struct {
		matchType MatchType
		invert    bool
		addrType  network.AddressType
		child     Match
	}
	type args struct {
		params []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bm := &baseMatch{
				matchType: tt.fields.matchType,
				invert:    tt.fields.invert,
				addrType:  tt.fields.addrType,
				child:     tt.fields.child,
			}
			got, got1 := bm.Parse(tt.args.params)
			if got != tt.want {
				t.Errorf("baseMatch.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("baseMatch.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchAddrType_Parse(t *testing.T) {
	type fields struct {
		baseMatch     *baseMatch
		SrcTypeInvert bool
		SrcType       AddrType
		HasSrcType    bool
		DstTypeInvert bool
		DstType       AddrType
		HasDstType    bool
		LimitIfaceIn  bool
		LimitIfaceOut bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mAddrType := &MatchAddrType{
				baseMatch:     tt.fields.baseMatch,
				SrcTypeInvert: tt.fields.SrcTypeInvert,
				SrcType:       tt.fields.SrcType,
				HasSrcType:    tt.fields.HasSrcType,
				DstTypeInvert: tt.fields.DstTypeInvert,
				DstType:       tt.fields.DstType,
				HasDstType:    tt.fields.HasDstType,
				LimitIfaceIn:  tt.fields.LimitIfaceIn,
				LimitIfaceOut: tt.fields.LimitIfaceOut,
			}
			got, got1 := mAddrType.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchAddrType.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchAddrType.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchAH_Parse(t *testing.T) {
	type fields struct {
		baseMatch    *baseMatch
		SPIMin       int
		SPIMax       int
		Length       int
		Reserved     bool
		SPIInvert    bool
		LengthInvert bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mAH := &MatchAH{
				baseMatch:    tt.fields.baseMatch,
				SPIMin:       tt.fields.SPIMin,
				SPIMax:       tt.fields.SPIMax,
				Length:       tt.fields.Length,
				Reserved:     tt.fields.Reserved,
				SPIInvert:    tt.fields.SPIInvert,
				LengthInvert: tt.fields.LengthInvert,
			}
			got, got1 := mAH.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchAH.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchAH.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchBPF_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		BPF       []BPFSockFilter
		BPFRaw    string
		Path      string
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mBPF := &MatchBPF{
				baseMatch: tt.fields.baseMatch,
				BPF:       tt.fields.BPF,
				BPFRaw:    tt.fields.BPFRaw,
				Path:      tt.fields.Path,
			}
			got, got1 := mBPF.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchBPF.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchBPF.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchCGroup_Parse(t *testing.T) {
	type fields struct {
		baseMatch     *baseMatch
		Path          string
		ClassID       int
		PathInvert    bool
		ClassIDInvert bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mCG := &MatchCGroup{
				baseMatch:     tt.fields.baseMatch,
				Path:          tt.fields.Path,
				ClassID:       tt.fields.ClassID,
				PathInvert:    tt.fields.PathInvert,
				ClassIDInvert: tt.fields.ClassIDInvert,
			}
			got, got1 := mCG.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchCGroup.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchCGroup.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchCluster_Parse(t *testing.T) {
	type fields struct {
		baseMatch     *baseMatch
		TotalNodes    int
		LocalNodeMask int64
		HashSeed      int64
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mCluster := &MatchCluster{
				baseMatch:     tt.fields.baseMatch,
				TotalNodes:    tt.fields.TotalNodes,
				LocalNodeMask: tt.fields.LocalNodeMask,
				HashSeed:      tt.fields.HashSeed,
			}
			got, got1 := mCluster.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchCluster.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchCluster.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchComment_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Comment   string
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mComment := &MatchComment{
				baseMatch: tt.fields.baseMatch,
				Comment:   tt.fields.Comment,
			}
			got, got1 := mComment.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchComment.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchComment.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchConnBytes_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		From      int64
		To        int64
		Mode      ConnBytesMode
		Direction ConnTrackDir
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mConnBytes := &MatchConnBytes{
				baseMatch: tt.fields.baseMatch,
				From:      tt.fields.From,
				To:        tt.fields.To,
				Mode:      tt.fields.Mode,
				Direction: tt.fields.Direction,
			}
			got, got1 := mConnBytes.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchConnBytes.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchConnBytes.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchConnLabel_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Label     int
		LabelName string
		Set       bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mConnLabel := &MatchConnLabel{
				baseMatch: tt.fields.baseMatch,
				Label:     tt.fields.Label,
				LabelName: tt.fields.LabelName,
				Set:       tt.fields.Set,
			}
			got, got1 := mConnLabel.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchConnLabel.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchConnLabel.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchConnLimit_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Upto      int
		Above     int
		Mask      int
		Src       bool
		Dst       bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mConnLimit := &MatchConnLimit{
				baseMatch: tt.fields.baseMatch,
				Upto:      tt.fields.Upto,
				Above:     tt.fields.Above,
				Mask:      tt.fields.Mask,
				Src:       tt.fields.Src,
				Dst:       tt.fields.Dst,
			}
			got, got1 := mConnLimit.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchConnLimit.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchConnLimit.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchConnMark_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Value     int
		Mask      int
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mConnMark := &MatchConnMark{
				baseMatch: tt.fields.baseMatch,
				Value:     tt.fields.Value,
				Mask:      tt.fields.Mask,
			}
			got, got1 := mConnMark.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchConnMark.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchConnMark.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchConnTrack_Parse(t *testing.T) {
	type fields struct {
		baseMatch         *baseMatch
		State             ConnTrackState
		Status            ConnTrackStatus
		Direction         ConnTrackDir
		Proto             network.Protocol
		OrigSrc           network.Address
		OrigDst           network.Address
		ReplSrc           network.Address
		ReplDst           network.Address
		OrigSrcPortMin    int
		OrigSrcPortMax    int
		OrigDstPortMin    int
		OrigDstPortMax    int
		ReplSrcPortMin    int
		ReplSrcPortMax    int
		ReplDstPortMin    int
		ReplDstPortMax    int
		ExpireMin         int
		ExpireMax         int
		StateInvert       bool
		StatusInvert      bool
		ProtoInvert       bool
		OrigSrcInvert     bool
		OrigDstInvert     bool
		ReplSrcInvert     bool
		ReplDstInvert     bool
		OrigSrcPortInvert bool
		OrigDstPortInvert bool
		ReplSrcPortInvert bool
		ReplDstPortInvert bool
		ExpireInvert      bool
		DirectionInvert   bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mConnTrack := &MatchConnTrack{
				baseMatch:         tt.fields.baseMatch,
				State:             tt.fields.State,
				Status:            tt.fields.Status,
				Direction:         tt.fields.Direction,
				Proto:             tt.fields.Proto,
				OrigSrc:           tt.fields.OrigSrc,
				OrigDst:           tt.fields.OrigDst,
				ReplSrc:           tt.fields.ReplSrc,
				ReplDst:           tt.fields.ReplDst,
				OrigSrcPortMin:    tt.fields.OrigSrcPortMin,
				OrigSrcPortMax:    tt.fields.OrigSrcPortMax,
				OrigDstPortMin:    tt.fields.OrigDstPortMin,
				OrigDstPortMax:    tt.fields.OrigDstPortMax,
				ReplSrcPortMin:    tt.fields.ReplSrcPortMin,
				ReplSrcPortMax:    tt.fields.ReplSrcPortMax,
				ReplDstPortMin:    tt.fields.ReplDstPortMin,
				ReplDstPortMax:    tt.fields.ReplDstPortMax,
				ExpireMin:         tt.fields.ExpireMin,
				ExpireMax:         tt.fields.ExpireMax,
				StateInvert:       tt.fields.StateInvert,
				StatusInvert:      tt.fields.StatusInvert,
				ProtoInvert:       tt.fields.ProtoInvert,
				OrigSrcInvert:     tt.fields.OrigSrcInvert,
				OrigDstInvert:     tt.fields.OrigDstInvert,
				ReplSrcInvert:     tt.fields.ReplSrcInvert,
				ReplDstInvert:     tt.fields.ReplDstInvert,
				OrigSrcPortInvert: tt.fields.OrigSrcPortInvert,
				OrigDstPortInvert: tt.fields.OrigDstPortInvert,
				ReplSrcPortInvert: tt.fields.ReplSrcPortInvert,
				ReplDstPortInvert: tt.fields.ReplDstPortInvert,
				ExpireInvert:      tt.fields.ExpireInvert,
				DirectionInvert:   tt.fields.DirectionInvert,
			}
			got, got1 := mConnTrack.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchConnTrack.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchConnTrack.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchCPU_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		CPU       int
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mCPU := &MatchCPU{
				baseMatch: tt.fields.baseMatch,
				CPU:       tt.fields.CPU,
			}
			got, got1 := mCPU.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchCPU.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchCPU.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchDCCP_Parse(t *testing.T) {
	type fields struct {
		baseMatch     *baseMatch
		SrcPortMin    int
		SrcPortMax    int
		DstPortMin    int
		DstPortMax    int
		DCCPType      DCCPType
		Option        int
		SrcPortInvert bool
		DstPortInvert bool
		TypeInvert    bool
		OptionInvert  bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mDCCP := &MatchDCCP{
				baseMatch:     tt.fields.baseMatch,
				SrcPortMin:    tt.fields.SrcPortMin,
				SrcPortMax:    tt.fields.SrcPortMax,
				DstPortMin:    tt.fields.DstPortMin,
				DstPortMax:    tt.fields.DstPortMax,
				DCCPType:      tt.fields.DCCPType,
				Option:        tt.fields.Option,
				SrcPortInvert: tt.fields.SrcPortInvert,
				DstPortInvert: tt.fields.DstPortInvert,
				TypeInvert:    tt.fields.TypeInvert,
				OptionInvert:  tt.fields.OptionInvert,
			}
			got, got1 := mDCCP.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchDCCP.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchDCCP.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchDevGroup_Parse(t *testing.T) {
	type fields struct {
		baseMatch      *baseMatch
		SrcGroup       int64
		DstGroup       int64
		SrcGroupInvert bool
		DstGroupInvert bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mDevGroup := &MatchDevGroup{
				baseMatch:      tt.fields.baseMatch,
				SrcGroup:       tt.fields.SrcGroup,
				DstGroup:       tt.fields.DstGroup,
				SrcGroupInvert: tt.fields.SrcGroupInvert,
				DstGroupInvert: tt.fields.DstGroupInvert,
			}
			got, got1 := mDevGroup.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchDevGroup.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchDevGroup.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchDSCP_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Value     int
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mDSCP := &MatchDSCP{
				baseMatch: tt.fields.baseMatch,
				Value:     tt.fields.Value,
			}
			got, got1 := mDSCP.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchDSCP.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchDSCP.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchDst_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Length    int
		Options   []network.IPv6Option
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mDst := &MatchDst{
				baseMatch: tt.fields.baseMatch,
				Length:    tt.fields.Length,
				Options:   tt.fields.Options,
			}
			got, got1 := mDst.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchDst.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchDst.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchECN_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		ECE       bool
		CWR       bool
		ECT       int
		ECEInvert bool
		CWRInvert bool
		ECTInvert bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mECN := &MatchECN{
				baseMatch: tt.fields.baseMatch,
				ECE:       tt.fields.ECE,
				CWR:       tt.fields.CWR,
				ECT:       tt.fields.ECT,
				ECEInvert: tt.fields.ECEInvert,
				CWRInvert: tt.fields.CWRInvert,
				ECTInvert: tt.fields.ECTInvert,
			}
			got, got1 := mECN.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchECN.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchECN.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchESP_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		SPIMin    int
		SPIMax    int
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mESP := &MatchESP{
				baseMatch: tt.fields.baseMatch,
				SPIMin:    tt.fields.SPIMin,
				SPIMax:    tt.fields.SPIMax,
			}
			got, got1 := mESP.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchESP.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchESP.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchEUI64_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mEUI64 := &MatchEUI64{
				baseMatch: tt.fields.baseMatch,
			}
			got, got1 := mEUI64.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchEUI64.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchEUI64.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchFrag_Parse(t *testing.T) {
	type fields struct {
		baseMatch    *baseMatch
		IDMin        int
		IDMax        int
		Length       int
		Reserved     bool
		First        bool
		Last         bool
		More         bool
		IDInvert     bool
		LengthInvert bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mFrag := &MatchFrag{
				baseMatch:    tt.fields.baseMatch,
				IDMin:        tt.fields.IDMin,
				IDMax:        tt.fields.IDMax,
				Length:       tt.fields.Length,
				Reserved:     tt.fields.Reserved,
				First:        tt.fields.First,
				Last:         tt.fields.Last,
				More:         tt.fields.More,
				IDInvert:     tt.fields.IDInvert,
				LengthInvert: tt.fields.LengthInvert,
			}
			got, got1 := mFrag.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchFrag.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchFrag.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchHashLimit_Parse(t *testing.T) {
	type fields struct {
		baseMatch           *baseMatch
		Avg                 xtables.Rate
		Burst               int
		Mode                HashLimitMode
		SrcMask             int
		DstMask             int
		Name                string
		HashtableSize       int
		HashtableMax        int
		HashtableGCInterval int
		HashtableExpire     int
		RateMatch           bool
		RateInterval        int
		AvgInvert           bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mHashLimit := &MatchHashLimit{
				baseMatch:           tt.fields.baseMatch,
				Avg:                 tt.fields.Avg,
				Burst:               tt.fields.Burst,
				Mode:                tt.fields.Mode,
				SrcMask:             tt.fields.SrcMask,
				DstMask:             tt.fields.DstMask,
				Name:                tt.fields.Name,
				HashtableSize:       tt.fields.HashtableSize,
				HashtableMax:        tt.fields.HashtableMax,
				HashtableGCInterval: tt.fields.HashtableGCInterval,
				HashtableExpire:     tt.fields.HashtableExpire,
				RateMatch:           tt.fields.RateMatch,
				RateInterval:        tt.fields.RateInterval,
				AvgInvert:           tt.fields.AvgInvert,
			}
			got, got1 := mHashLimit.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchHashLimit.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchHashLimit.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchHBH_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Length    int
		Options   []network.IPv6Option
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mHBH := &MatchHBH{
				baseMatch: tt.fields.baseMatch,
				Length:    tt.fields.Length,
				Options:   tt.fields.Options,
			}
			got, got1 := mHBH.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchHBH.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchHBH.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchHelper_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Name      string
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mHelper := &MatchHelper{
				baseMatch: tt.fields.baseMatch,
				Name:      tt.fields.Name,
			}
			got, got1 := mHelper.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchHelper.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchHelper.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchHL_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Operator  xtables.Operator
		Value     int
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mHL := &MatchHL{
				baseMatch: tt.fields.baseMatch,
				Operator:  tt.fields.Operator,
				Value:     tt.fields.Value,
			}
			got, got1 := mHL.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchHL.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchHL.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchICMP_Parse(t *testing.T) {
	type fields struct {
		baseMatch  *baseMatch
		ICMPType   network.ICMPType
		CodeMin    network.ICMPCode
		CodeMax    network.ICMPCode
		typeString string
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mICMP := &MatchICMP{
				baseMatch:  tt.fields.baseMatch,
				ICMPType:   tt.fields.ICMPType,
				CodeMin:    tt.fields.CodeMin,
				CodeMax:    tt.fields.CodeMax,
				typeString: tt.fields.typeString,
			}
			got, got1 := mICMP.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchICMP.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchICMP.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchIPRange_Parse(t *testing.T) {
	type fields struct {
		baseMatch   *baseMatch
		SrcIPMin    net.IP
		SrcIPMax    net.IP
		DstIPMin    net.IP
		DstIPMax    net.IP
		SrcIPInvert bool
		DstIPInvert bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mIPRange := &MatchIPRange{
				baseMatch:   tt.fields.baseMatch,
				SrcIPMin:    tt.fields.SrcIPMin,
				SrcIPMax:    tt.fields.SrcIPMax,
				DstIPMin:    tt.fields.DstIPMin,
				DstIPMax:    tt.fields.DstIPMax,
				SrcIPInvert: tt.fields.SrcIPInvert,
				DstIPInvert: tt.fields.DstIPInvert,
			}
			got, got1 := mIPRange.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchIPRange.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchIPRange.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchIPv6Header_Parse(t *testing.T) {
	type fields struct {
		baseMatch     *baseMatch
		Soft          bool
		IPHeaderTypes []network.IPv6HeaderType
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mIPv6 := &MatchIPv6Header{
				baseMatch:     tt.fields.baseMatch,
				Soft:          tt.fields.Soft,
				IPHeaderTypes: tt.fields.IPHeaderTypes,
			}
			got, got1 := mIPv6.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchIPv6Header.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchIPv6Header.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchIPVS_Parse(t *testing.T) {
	type fields struct {
		baseMatch      *baseMatch
		IPVS           bool
		VProto         network.Protocol
		VAddr          network.Address
		VPort          int
		VDir           ConnTrackDir
		VMethod        IPVSMethod
		VPortCtl       int
		IPVSInvert     bool
		VProtoInvert   bool
		VAddrInvert    bool
		VPortInvert    bool
		VMethodInvert  bool
		VPortCtlInvert bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mIPVS := &MatchIPVS{
				baseMatch:      tt.fields.baseMatch,
				IPVS:           tt.fields.IPVS,
				VProto:         tt.fields.VProto,
				VAddr:          tt.fields.VAddr,
				VPort:          tt.fields.VPort,
				VDir:           tt.fields.VDir,
				VMethod:        tt.fields.VMethod,
				VPortCtl:       tt.fields.VPortCtl,
				IPVSInvert:     tt.fields.IPVSInvert,
				VProtoInvert:   tt.fields.VProtoInvert,
				VAddrInvert:    tt.fields.VAddrInvert,
				VPortInvert:    tt.fields.VPortInvert,
				VMethodInvert:  tt.fields.VMethodInvert,
				VPortCtlInvert: tt.fields.VPortCtlInvert,
			}
			got, got1 := mIPVS.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchIPVS.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchIPVS.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchLength_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		LengthMin int
		LengthMax int
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mLength := &MatchLength{
				baseMatch: tt.fields.baseMatch,
				LengthMin: tt.fields.LengthMin,
				LengthMax: tt.fields.LengthMax,
			}
			got, got1 := mLength.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchLength.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchLength.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchLimit_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Avg       xtables.Rate
		Burst     int
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mLimit := &MatchLimit{
				baseMatch: tt.fields.baseMatch,
				Avg:       tt.fields.Avg,
				Burst:     tt.fields.Burst,
			}
			got, got1 := mLimit.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchLimit.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchLimit.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchMAC_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		SrcMac    net.HardwareAddr
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mMAC := &MatchMAC{
				baseMatch: tt.fields.baseMatch,
				SrcMac:    tt.fields.SrcMac,
			}
			got, got1 := mMAC.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchMAC.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchMAC.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchMark_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Value     int
		Mask      int
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mMark := &MatchMark{
				baseMatch: tt.fields.baseMatch,
				Value:     tt.fields.Value,
				Mask:      tt.fields.Mask,
			}
			got, got1 := mMark.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchMark.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchMark.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchMH_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		TypeMin   MHType
		TypeMax   MHType
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mMH := &MatchMH{
				baseMatch: tt.fields.baseMatch,
				TypeMin:   tt.fields.TypeMin,
				TypeMax:   tt.fields.TypeMax,
			}
			got, got1 := mMH.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchMH.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchMH.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchMultiPort_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		SrcPorts  []PortRange
		DstPorts  []PortRange
		Ports     []PortRange
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mMultiPort := &MatchMultiPort{
				baseMatch: tt.fields.baseMatch,
				SrcPorts:  tt.fields.SrcPorts,
				DstPorts:  tt.fields.DstPorts,
				Ports:     tt.fields.Ports,
			}
			got, got1 := mMultiPort.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchMultiPort.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchMultiPort.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchNFAcct_Parse(t *testing.T) {
	type fields struct {
		baseMatch      *baseMatch
		AccountingName string
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mNFAcct := &MatchNFAcct{
				baseMatch:      tt.fields.baseMatch,
				AccountingName: tt.fields.AccountingName,
			}
			got, got1 := mNFAcct.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchNFAcct.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchNFAcct.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchOSF_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Genre     string
		TTLLevel  int
		LogLevel  int
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mOSF := &MatchOSF{
				baseMatch: tt.fields.baseMatch,
				Genre:     tt.fields.Genre,
				TTLLevel:  tt.fields.TTLLevel,
				LogLevel:  tt.fields.LogLevel,
			}
			got, got1 := mOSF.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchOSF.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchOSF.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchOwner_Parse(t *testing.T) {
	type fields struct {
		baseMatch          *baseMatch
		UidOwnerMin        int
		UidOwnerMax        int
		User               string
		GidOwnerMin        int
		GidOwnerMax        int
		Group              string
		SupplGroups        bool
		HasSocketExists    bool
		UidOwnerInvert     bool
		GidOwnerInvert     bool
		SocketExistsInvert bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mOwner := &MatchOwner{
				baseMatch:          tt.fields.baseMatch,
				UidOwnerMin:        tt.fields.UidOwnerMin,
				UidOwnerMax:        tt.fields.UidOwnerMax,
				User:               tt.fields.User,
				GidOwnerMin:        tt.fields.GidOwnerMin,
				GidOwnerMax:        tt.fields.GidOwnerMax,
				Group:              tt.fields.Group,
				SupplGroups:        tt.fields.SupplGroups,
				HasSocketExists:    tt.fields.HasSocketExists,
				UidOwnerInvert:     tt.fields.UidOwnerInvert,
				GidOwnerInvert:     tt.fields.GidOwnerInvert,
				SocketExistsInvert: tt.fields.SocketExistsInvert,
			}
			got, got1 := mOwner.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchOwner.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchOwner.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchPhysDev_Parse(t *testing.T) {
	type fields struct {
		baseMatch              *baseMatch
		PhysDevIn              string
		PhysDevOut             string
		PhysDevIsIn            bool
		PhysDevIsOut           bool
		PhysDevIsBridged       bool
		PhysDevInInvert        bool
		PhysDevOutInvert       bool
		PhysDevIsInInvert      bool
		PhysDevIsOutInvert     bool
		PhysDevIsBridgedInvert bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mPhysDev := &MatchPhysDev{
				baseMatch:              tt.fields.baseMatch,
				PhysDevIn:              tt.fields.PhysDevIn,
				PhysDevOut:             tt.fields.PhysDevOut,
				PhysDevIsIn:            tt.fields.PhysDevIsIn,
				PhysDevIsOut:           tt.fields.PhysDevIsOut,
				PhysDevIsBridged:       tt.fields.PhysDevIsBridged,
				PhysDevInInvert:        tt.fields.PhysDevInInvert,
				PhysDevOutInvert:       tt.fields.PhysDevOutInvert,
				PhysDevIsInInvert:      tt.fields.PhysDevIsInInvert,
				PhysDevIsOutInvert:     tt.fields.PhysDevIsOutInvert,
				PhysDevIsBridgedInvert: tt.fields.PhysDevIsBridgedInvert,
			}
			got, got1 := mPhysDev.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchPhysDev.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchPhysDev.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchPktType_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		PktType   PktType
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mPktType := &MatchPktType{
				baseMatch: tt.fields.baseMatch,
				PktType:   tt.fields.PktType,
			}
			got, got1 := mPktType.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchPktType.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchPktType.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchPolicy_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Dir       xtables.Direction
		Pol       PolicyPol
		Strict    bool
		Elements  []*MatchPolicyElement
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mPolicy := &MatchPolicy{
				baseMatch: tt.fields.baseMatch,
				Dir:       tt.fields.Dir,
				Pol:       tt.fields.Pol,
				Strict:    tt.fields.Strict,
				Elements:  tt.fields.Elements,
			}
			got, got1 := mPolicy.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchPolicy.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchPolicy.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchQuota_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Quota     int64
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mQuota := &MatchQuota{
				baseMatch: tt.fields.baseMatch,
				Quota:     tt.fields.Quota,
			}
			got, got1 := mQuota.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchQuota.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchQuota.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchRateEst_Parse(t *testing.T) {
	type fields struct {
		baseMatch    *baseMatch
		RateestDelta bool
		Operator     xtables.Operator
		Name         string
		Rateest1     string
		Rateest2     string
		Relative     bool
		RateestBPS   int
		RateestPPS   int
		RateestBPS1  int
		RateestPPS1  int
		RateestBPS2  int
		RateestPPS2  int
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mRateEst := &MatchRateEst{
				baseMatch:    tt.fields.baseMatch,
				RateestDelta: tt.fields.RateestDelta,
				Operator:     tt.fields.Operator,
				Name:         tt.fields.Name,
				Rateest1:     tt.fields.Rateest1,
				Rateest2:     tt.fields.Rateest2,
				Relative:     tt.fields.Relative,
				RateestBPS:   tt.fields.RateestBPS,
				RateestPPS:   tt.fields.RateestPPS,
				RateestBPS1:  tt.fields.RateestBPS1,
				RateestPPS1:  tt.fields.RateestPPS1,
				RateestBPS2:  tt.fields.RateestBPS2,
				RateestPPS2:  tt.fields.RateestPPS2,
			}
			got, got1 := mRateEst.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchRateEst.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchRateEst.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchRealm_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Value     int
		Mask      int
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mRealm := &MatchRealm{
				baseMatch: tt.fields.baseMatch,
				Value:     tt.fields.Value,
				Mask:      tt.fields.Mask,
			}
			got, got1 := mRealm.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchRealm.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchRealm.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchRecent_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Name      string
		Set       bool
		RCheck    bool
		Update    bool
		Remove    bool
		RSource   bool
		RDest     bool
		Seconds   int
		Reap      bool
		HitCount  int
		RTTL      bool
		Mask      net.IPMask
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mRecent := &MatchRecent{
				baseMatch: tt.fields.baseMatch,
				Name:      tt.fields.Name,
				Set:       tt.fields.Set,
				RCheck:    tt.fields.RCheck,
				Update:    tt.fields.Update,
				Remove:    tt.fields.Remove,
				RSource:   tt.fields.RSource,
				RDest:     tt.fields.RDest,
				Seconds:   tt.fields.Seconds,
				Reap:      tt.fields.Reap,
				HitCount:  tt.fields.HitCount,
				RTTL:      tt.fields.RTTL,
				Mask:      tt.fields.Mask,
			}
			got, got1 := mRecent.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchRecent.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchRecent.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchRPFilter_Parse(t *testing.T) {
	type fields struct {
		baseMatch   *baseMatch
		Loose       bool
		ValidMark   bool
		AcceptLocal bool
		Invert      bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mRPFilter := &MatchRPFilter{
				baseMatch:   tt.fields.baseMatch,
				Loose:       tt.fields.Loose,
				ValidMark:   tt.fields.ValidMark,
				AcceptLocal: tt.fields.AcceptLocal,
				Invert:      tt.fields.Invert,
			}
			got, got1 := mRPFilter.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchRPFilter.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchRPFilter.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchRT_Parse(t *testing.T) {
	type fields struct {
		baseMatch      *baseMatch
		RTType         int
		SegsLeftMin    int
		SegsLeftMax    int
		Length         int
		Reserved       bool
		Addrs          []network.Address
		NotStrict      bool
		TypeInvert     bool
		SegsLeftInvert bool
		LengthInvert   bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mRT := &MatchRT{
				baseMatch:      tt.fields.baseMatch,
				RTType:         tt.fields.RTType,
				SegsLeftMin:    tt.fields.SegsLeftMin,
				SegsLeftMax:    tt.fields.SegsLeftMax,
				Length:         tt.fields.Length,
				Reserved:       tt.fields.Reserved,
				Addrs:          tt.fields.Addrs,
				NotStrict:      tt.fields.NotStrict,
				TypeInvert:     tt.fields.TypeInvert,
				SegsLeftInvert: tt.fields.SegsLeftInvert,
				LengthInvert:   tt.fields.LengthInvert,
			}
			got, got1 := mRT.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchRT.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchRT.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchSCTP_Parse(t *testing.T) {
	type fields struct {
		baseMatch     *baseMatch
		SrcPortMin    int
		SrcPortMax    int
		DstPortMin    int
		DstPortMax    int
		Chunks        []Chunk
		Range         MatchRange
		SrcPortInvert bool
		DstPortInvert bool
		ChunksInvert  bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mSCTP := &MatchSCTP{
				baseMatch:     tt.fields.baseMatch,
				SrcPortMin:    tt.fields.SrcPortMin,
				SrcPortMax:    tt.fields.SrcPortMax,
				DstPortMin:    tt.fields.DstPortMin,
				DstPortMax:    tt.fields.DstPortMax,
				Chunks:        tt.fields.Chunks,
				Range:         tt.fields.Range,
				SrcPortInvert: tt.fields.SrcPortInvert,
				DstPortInvert: tt.fields.DstPortInvert,
				ChunksInvert:  tt.fields.ChunksInvert,
			}
			got, got1 := mSCTP.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchSCTP.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchSCTP.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchSet_Parse(t *testing.T) {
	type fields struct {
		baseMatch            *baseMatch
		SetName              string
		Flags                []Flag
		ReturnNoMatch        bool
		SkipCounterUpdate    bool
		SkipSubCounterUpdate bool
		PacketsEQ            int
		PacketsLT            int
		PacketsGT            int
		BytesEQ              int
		BytesLT              int
		BytesGT              int
		SetNameInvert        bool
		PacketsEQInvert      bool
		BytesEQInvert        bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mSet := &MatchSet{
				baseMatch:            tt.fields.baseMatch,
				SetName:              tt.fields.SetName,
				Flags:                tt.fields.Flags,
				ReturnNoMatch:        tt.fields.ReturnNoMatch,
				SkipCounterUpdate:    tt.fields.SkipCounterUpdate,
				SkipSubCounterUpdate: tt.fields.SkipSubCounterUpdate,
				PacketsEQ:            tt.fields.PacketsEQ,
				PacketsLT:            tt.fields.PacketsLT,
				PacketsGT:            tt.fields.PacketsGT,
				BytesEQ:              tt.fields.BytesEQ,
				BytesLT:              tt.fields.BytesLT,
				BytesGT:              tt.fields.BytesGT,
				SetNameInvert:        tt.fields.SetNameInvert,
				PacketsEQInvert:      tt.fields.PacketsEQInvert,
				BytesEQInvert:        tt.fields.BytesEQInvert,
			}
			got, got1 := mSet.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchSet.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchSet.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchSocket_Parse(t *testing.T) {
	type fields struct {
		baseMatch     *baseMatch
		Transparent   bool
		NoWildcard    bool
		RestoreSKMark bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mSocket := &MatchSocket{
				baseMatch:     tt.fields.baseMatch,
				Transparent:   tt.fields.Transparent,
				NoWildcard:    tt.fields.NoWildcard,
				RestoreSKMark: tt.fields.RestoreSKMark,
			}
			got, got1 := mSocket.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchSocket.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchSocket.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchState_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		State     ConnTrackState
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mState := &MatchState{
				baseMatch: tt.fields.baseMatch,
				State:     tt.fields.State,
			}
			got, got1 := mState.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchState.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchState.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchStatistic_Parse(t *testing.T) {
	type fields struct {
		baseMatch         *baseMatch
		Mode              StatisticMode
		Probability       float64
		Every             int
		Packet            int
		ProbabilityInvert bool
		EveryInvert       bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mStatis := &MatchStatistic{
				baseMatch:         tt.fields.baseMatch,
				Mode:              tt.fields.Mode,
				Probability:       tt.fields.Probability,
				Every:             tt.fields.Every,
				Packet:            tt.fields.Packet,
				ProbabilityInvert: tt.fields.ProbabilityInvert,
				EveryInvert:       tt.fields.EveryInvert,
			}
			got, got1 := mStatis.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchStatistic.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchStatistic.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchString_Parse(t *testing.T) {
	type fields struct {
		baseMatch        *baseMatch
		Algo             StringAlgo
		From             int
		To               int
		Pattern          string
		HexPattern       []byte
		IgnoreCase       bool
		PatternInvert    bool
		HexPatternInvert bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mString := &MatchString{
				baseMatch:        tt.fields.baseMatch,
				Algo:             tt.fields.Algo,
				From:             tt.fields.From,
				To:               tt.fields.To,
				Pattern:          tt.fields.Pattern,
				HexPattern:       tt.fields.HexPattern,
				IgnoreCase:       tt.fields.IgnoreCase,
				PatternInvert:    tt.fields.PatternInvert,
				HexPatternInvert: tt.fields.HexPatternInvert,
			}
			got, got1 := mString.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchString.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchString.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchTCP_Parse(t *testing.T) {
	type fields struct {
		baseMatch     *baseMatch
		SrcPortMin    int
		SrcPortMax    int
		DstPortMin    int
		DstPortMax    int
		FlagsMask     network.TCPFlag
		FlagsSet      network.TCPFlag
		Option        int
		SrcPortInvert bool
		DstPortInvert bool
		FlagsInvert   bool
		OptionInvert  bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mTCP := &MatchTCP{
				baseMatch:     tt.fields.baseMatch,
				SrcPortMin:    tt.fields.SrcPortMin,
				SrcPortMax:    tt.fields.SrcPortMax,
				DstPortMin:    tt.fields.DstPortMin,
				DstPortMax:    tt.fields.DstPortMax,
				FlagsMask:     tt.fields.FlagsMask,
				FlagsSet:      tt.fields.FlagsSet,
				Option:        tt.fields.Option,
				SrcPortInvert: tt.fields.SrcPortInvert,
				DstPortInvert: tt.fields.DstPortInvert,
				FlagsInvert:   tt.fields.FlagsInvert,
				OptionInvert:  tt.fields.OptionInvert,
			}
			got, got1 := mTCP.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchTCP.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchTCP.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchTCPMSS_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		MSSMin    int
		MSSMax    int
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mTCPMSS := &MatchTCPMSS{
				baseMatch: tt.fields.baseMatch,
				MSSMin:    tt.fields.MSSMin,
				MSSMax:    tt.fields.MSSMax,
			}
			got, got1 := mTCPMSS.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchTCPMSS.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchTCPMSS.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchTime_Parse(t *testing.T) {
	type fields struct {
		baseMatch    *baseMatch
		DaytimeStart *xtables.Daytime
		DaytimeStop  *xtables.Daytime
		DateStart    *xtables.Date
		DateStop     *xtables.Date
		Weekdays     xtables.Weekday
		Monthdays    xtables.Monthday
		KernelTZ     bool
		Contiguous   bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mTime := &MatchTime{
				baseMatch:    tt.fields.baseMatch,
				DaytimeStart: tt.fields.DaytimeStart,
				DaytimeStop:  tt.fields.DaytimeStop,
				DateStart:    tt.fields.DateStart,
				DateStop:     tt.fields.DateStop,
				Weekdays:     tt.fields.Weekdays,
				Monthdays:    tt.fields.Monthdays,
				KernelTZ:     tt.fields.KernelTZ,
				Contiguous:   tt.fields.Contiguous,
			}
			got, got1 := mTime.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchTime.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchTime.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchTOS_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Value     network.TOS
		Mask      network.TOS
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mTOS := &MatchTOS{
				baseMatch: tt.fields.baseMatch,
				Value:     tt.fields.Value,
				Mask:      tt.fields.Mask,
			}
			got, got1 := mTOS.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchTOS.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchTOS.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchTTL_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Operator  xtables.Operator
		Value     int
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mTTL := &MatchTTL{
				baseMatch: tt.fields.baseMatch,
				Operator:  tt.fields.Operator,
				Value:     tt.fields.Value,
			}
			got, got1 := mTTL.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchTTL.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchTTL.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchU32_Parse(t *testing.T) {
	type fields struct {
		baseMatch *baseMatch
		Tests     string
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mU32 := &MatchU32{
				baseMatch: tt.fields.baseMatch,
				Tests:     tt.fields.Tests,
			}
			got, got1 := mU32.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchU32.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchU32.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestMatchUDP_Parse(t *testing.T) {
	type fields struct {
		baseMatch     *baseMatch
		SrcPortMin    int
		SrcPortMax    int
		DstPortMin    int
		DstPortMax    int
		SrcPortInvert bool
		DstPortInvert bool
	}
	type args struct {
		main []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		want1  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mUDP := &MatchUDP{
				baseMatch:     tt.fields.baseMatch,
				SrcPortMin:    tt.fields.SrcPortMin,
				SrcPortMax:    tt.fields.SrcPortMax,
				DstPortMin:    tt.fields.DstPortMin,
				DstPortMax:    tt.fields.DstPortMax,
				SrcPortInvert: tt.fields.SrcPortInvert,
				DstPortInvert: tt.fields.DstPortInvert,
			}
			got, got1 := mUDP.Parse(tt.args.main)
			if got != tt.want {
				t.Errorf("MatchUDP.Parse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("MatchUDP.Parse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
