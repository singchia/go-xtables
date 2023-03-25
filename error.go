package xtables

import "errors"

var (
	ErrUnsupportedAddress       = errors.New("unsupported address")
	ErrIllegalAddress           = errors.New("illegal address")
	ErrChainRequired            = errors.New("chain required")
	ErrCommandRequired          = errors.New("command required")
	ErrRulenumMustNot0          = errors.New("rulenum mustn't be 0")
	ErrChainLineTooShort        = errors.New("chain line too short")
	ErrChainAttrsNotRecognized  = errors.New("chain attrs not recognized")
	ErrArgs                     = errors.New("wrong args")
	ErrTargetNotFound           = errors.New("target not found")
	ErrMatchParams              = errors.New("illegal match params")
	ErrWatcherParams            = errors.New("illegal watcher params")
	ErrTargetParams             = errors.New("illegal target params")
	ErrAtLeastOneOptionRequired = errors.New("at least one option required")
	ErrTargetParseFailed        = errors.New("target parse failed")
	ErrIllegalTargetType        = errors.New("illegal target type")
	ErrArgsWithoutMAC           = errors.New("args without mac address")
)
