package xtables

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Daytime struct {
	Hour   int8
	Minute int8
	Second int8
	sets   int
}

func (dt *Daytime) String() string {
	daytime := ""
	sep := ""
	if dt.Hour >= 0 && dt.Hour <= 23 {
		daytime += sep + fmt.Sprintf("%2d", dt.Hour)
		sep = ":"
		dt.sets += 1
	}
	if dt.Minute >= 0 && dt.Minute <= 59 {
		daytime += sep + fmt.Sprintf("%2d", dt.Minute)
		sep = ":"
		dt.sets += 1
	}
	if dt.Second >= 0 && dt.Second <= 59 {
		daytime += sep + fmt.Sprintf("%2d", dt.Second)
		sep = ":"
		dt.sets += 1
	}
	return daytime
}

func ParseDaytime(daytime string) (*Daytime, error) {
	dt := &Daytime{-1, -1, -1, 0}
	err := error(nil)
	parts := strings.Split(daytime, ":")
	if len(parts) != 3 {
		err = errors.New("wrong elems")
		return dt, err
	}
	for index, part := range parts {
		switch index {
		case 0:
			hour, err := strconv.ParseInt(part, 10, 8)
			if err != nil {
				return dt, err
			}
			dt.Hour = int8(hour)
		case 1:
			minute, err := strconv.ParseInt(part, 10, 8)
			if err != nil {
				return dt, err
			}
			dt.Minute = int8(minute)
		case 2:
			second, err := strconv.ParseInt(part, 10, 8)
			if err != nil {
				return dt, err
			}
			dt.Second = int8(second)
		}
	}
	return dt, nil
}

type Yeartime struct {
	Year  int16
	Month int8
	Day   int8
	sets  int
}

func (yt *Yeartime) String() string {
	yeartime := ""
	sep := ""
	if yt.Year > -1 {
		yeartime += sep + fmt.Sprintf("%4d", yt.Year)
		sep = ":"
		yt.sets += 1
	}
	if yt.Month >= 1 && yt.Month <= 12 {
		yeartime += sep + fmt.Sprintf("%2d", yt.Month)
		sep = ":"
		yt.sets += 1
	}
	if yt.Day >= 1 && yt.Day <= 31 {
		yeartime += sep + fmt.Sprintf("%2d", yt.Day)
		sep = ":"
		yt.sets += 1
	}
	return yeartime
}

func ParseYeartime(yeartime string) (*Yeartime, error) {
	yt := &Yeartime{-1, -1, -1, 0}
	err := error(nil)
	parts := strings.Split(yeartime, "-")
	if len(parts) != 3 {
		err = errors.New("wrong elems")
		return yt, err
	}
	for index, part := range parts {
		switch index {
		case 0:
			year, err := strconv.ParseInt(part, 10, 16)
			if err != nil {
				return yt, err
			}
			yt.Year = int16(year)
		case 1:
			month, err := strconv.ParseInt(part, 10, 8)
			if err != nil {
				return yt, err
			}
			yt.Month = int8(month)
		case 2:
			day, err := strconv.ParseInt(part, 10, 8)
			if err != nil {
				return yt, err
			}
			yt.Day = int8(day)
		}
	}
	return yt, nil
}

type Date struct {
	*Yeartime
	*Daytime
}

func (date *Date) String() string {
	yeartime := date.Yeartime.String()
	daytime := date.Daytime.String()
	if date.Yeartime.sets == 3 && date.Daytime.sets == 3 {
		return yeartime + "T" + daytime
	}
	return yeartime
}

func ParseDate(date string) (*Date, error) {
	de := &Date{}
	err := error(nil)
	if len(date) != 19 {
		err = errors.New("wrong len")
		return de, err
	}
	yeartime := date[:10]
	daytime := date[11:]
	yt, err := ParseYeartime(yeartime)
	if err != nil {
		return de, err
	}
	dt, err := ParseDaytime(daytime)
	if err != nil {
		return de, err
	}
	de.Yeartime = yt
	de.Daytime = dt
	return de, nil
}

type Weekday int8

func (weekday Weekday) String() string {
	weekdays := ""
	sep := ""
	for i := 0; i <= 6; i++ {
		if weekday&(1<<i) != 0 {
			weekdays += sep + strconv.Itoa(i+1)
			sep = ","
		}
	}
	return weekdays
}

const (
	Monday Weekday = 1 << iota
	Tuesday
	Wednesday
	Thursday
	Friday
	Saturday
	Sunday
)

var (
	Weekdays = map[string]Weekday{
		"Mon": Monday,
		"Tue": Tuesday,
		"Wed": Wednesday,
		"Thu": Thursday,
		"Fri": Friday,
		"Sat": Saturday,
		"Sun": Sunday,
	}
)

type Monthday int32

func (monthday Monthday) String() string {
	monthdays := ""
	sep := ""
	for i := 0; i <= 30; i++ {
		if monthday&(1<<i) != 0 {
			monthdays += sep + strconv.Itoa(i+1)
			sep = ","
		}
	}
	return monthdays
}
