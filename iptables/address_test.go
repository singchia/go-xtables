package iptables

import "testing"

func TestParseAddress(t *testing.T) {
	ads, err := ParseAddress("google.com")
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(ads.String(), "\n")

	ads, err = ParseAddress("goo-gle.com")
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(ads.String(), "\n")

	ads, err = ParseAddress("google")
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(ads.String(), "\n")

	ads, err = ParseAddress("192.168.0.2")
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(ads.String(), "\n")

	ads, err = ParseAddress("192.168.0.0/16")
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(ads.String(), "\n")

	ads, err = ParseAddress(".google.com")
	if err == nil {
		t.Error("parse missed")
		return
	}
	t.Log(err, "\n")

	ads, err = ParseAddress("-google.com")
	if err == nil {
		t.Error("parse missed")
		return
	}
	t.Log(err, "\n")

	ads, err = ParseAddress("google-.com")
	if err == nil {
		t.Error("parse missed")
		return
	}
	t.Log(err, "\n")

	ads, err = ParseAddress("-.google.com")
	if err == nil {
		t.Error("parse missed")
		return
	}
	t.Log(err, "\n")
}
