package direction

type Direction int

func (dir Direction) String() string {
	switch dir {
	case In:
		return "in"
	case Out:
		return "out"
	default:
		return ""
	}
}

const (
	In Direction = 1 << iota
	Out
)
