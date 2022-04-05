package iptables

type operator int

func (operator operator) String() string {
	switch operator {
	case Must:
		return "Must"
	case Mustnot:
		return "Mustnot"
	}
	return ""
}

const (
	_ operator = iota
	Must
	Mustnot
)

type constraints struct {
	constraints map[string]*constraint
}

func newConstraints() *constraints {
	return &constraints{
		constraints: make(map[string]*constraint),
	}
}

func (constraints *constraints) add(operator operator,
	firstType, first, secondType string, seconds ...string) {
	key := operator.String() + firstType + first + secondType
	value, ok := constraints.constraints[key]
	if !ok {
		constraints.constraints[key] = &constraint{
			operator:   operator,
			firstType:  firstType,
			first:      first,
			secondType: secondType,
			seconds:    seconds,
		}
	} else {
		exist := false
		for _, second := range seconds {
			for _, elem := range value.seconds {
				if second == elem {
					exist = true
					break
				}
			}
			if exist {
				break
			}
		}
		if !exist {
			value.seconds = append(value.seconds, seconds...)
		}
	}
}

func (constraints *constraints) conflict(firstType, first, secondType, second string) bool {
	// must
	key := Must.String() + firstType + first + secondType
	value, ok := constraints.constraints[key]
	if ok {
		found := false
		for _, elem := range value.seconds {
			if second == elem {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}

	// mustnot
	key = Mustnot.String() + firstType + first + secondType
	value, ok = constraints.constraints[key]
	if ok {
		for _, elem := range value.seconds {
			if second == elem {
				return true
			}
		}
	}
	return false
}

type constraint struct {
	operator   operator
	firstType  string
	first      string
	secondType string
	seconds    []string
}
