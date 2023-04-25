package iproute2

const (
	group = "/etc/iproute2/group"
)

type Group struct {
	names map[int]string
}
