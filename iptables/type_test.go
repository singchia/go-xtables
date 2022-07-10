package iptables

import "testing"

func TestDaytime(t *testing.T) {
	dt := &Daytime{
		Hour:   -1,
		Minute: -1,
		Second: -1,
	}
	t.Log(dt.String())
	dt = &Daytime{
		Hour:   23,
		Minute: -1,
		Second: -1,
	}
	t.Log(dt.String())
	dt = &Daytime{
		Hour:   23,
		Minute: 59,
		Second: 59}
	t.Log(dt.String())
}

func TestYeartime(t *testing.T) {
	yt := &Yeartime{
		Year:  -1,
		Month: -1,
		Day:   -1,
	}
	t.Log(yt.String())
	yt = &Yeartime{
		Year:  2022,
		Month: -1,
		Day:   -1,
	}
	t.Log(yt.String())
	yt = &Yeartime{
		Year:  2022,
		Month: 12,
		Day:   31,
	}
	t.Log(yt.String())
}

func TestDate(t *testing.T) {
	date := &Date{}
	date.Yeartime = &Yeartime{
		Year:  2022,
		Month: 12,
		Day:   31}
	date.Daytime = &Daytime{
		Hour:   23,
		Minute: 59,
		Second: 59}
	t.Log(date.String())
}

func TestWeekday(t *testing.T) {
	weekday := Weekday(Monday | Tuesday | Wednesday)
	t.Log(weekday.String())
}

func TestMonthday(t *testing.T) {
	weekday := Monthday(1<<(1-1) | 1<<(31-1))
	t.Log(weekday.String())
}
