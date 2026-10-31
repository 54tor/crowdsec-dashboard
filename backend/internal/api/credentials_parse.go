package api

import (
	"errors"
	"regexp"
)

var errUnparseableCredentials = errors.New("unparseable cscli credentials output")

var (
	bouncerKeyLinePattern  = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z0-9+/=_-]{16,})[ \t]*\r?$`)
	machinePasswordPattern = regexp.MustCompile(`(?m)^[ \t]*password:[ \t]*["']?([^\s"']+)["']?[ \t]*\r?$`)
)

func parseBouncerKey(output []byte) (string, error) {
	match := bouncerKeyLinePattern.FindSubmatch(output)
	if match == nil {
		return "", errUnparseableCredentials
	}
	return string(match[1]), nil
}

func parseMachinePassword(output []byte) (string, error) {
	match := machinePasswordPattern.FindSubmatch(output)
	if match == nil {
		return "", errUnparseableCredentials
	}
	return string(match[1]), nil
}
