package xtables

import (
	"errors"
	"strings"
)

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

type CommandError struct {
	Err     error
	Message string
}

func (ce *CommandError) Error() string {
	return ce.Error() + ";" + ce.Message
}

func (ce *CommandError) IsRuleNotExistError() bool {
	return strings.Contains(ce.Message, "rule does not exist") ||
		strings.Contains(ce.Message, "does a matching rule exist in that chain?")
}

func ErrAndStdErr(err error, stderr []byte) error {
	ce := &CommandError{
		Err:     err,
		Message: string(stderr),
	}
	return ce
}
