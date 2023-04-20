package xtables

import "strconv"

// time related
type Unit int

const (
	_ Unit = iota
	Microsecond
	Millisecond
	Second
	Minute
	Hour
	Day
	BPS  // bytes per second
	KBPS // kilo bytes per second
	MBPS // million bytes per second
)

type Rate struct {
	Rate int
	Unit Unit
}

func (rate Rate) String() string {
	unit := "second"
	switch rate.Unit {
	case Minute:
		unit = "minute"
	case Hour:
		unit = "hour"
	case Day:
		unit = "day"
	}
	return strconv.Itoa(rate.Rate) + "/" + unit
}

type RateFloat struct {
	Rate float64
	Unit Unit
}

func (rateFloat RateFloat) Sting() string {
	unit := "second"
	switch rateFloat.Unit {
	case Microsecond:
		unit = "us"
	case Millisecond:
		unit = "ms"
	case Second:
		unit = "s"
	}
	return strconv.FormatFloat(rateFloat.Rate, 'f', 2, 64) + unit
}
