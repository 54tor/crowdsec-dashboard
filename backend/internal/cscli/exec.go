package cscli

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrUnknownCommand = errors.New("unknown cscli command")
	ErrCscliFailed    = errors.New("cscli command failed")
)

type Runner interface {
	Run(ctx context.Context, argv []string) (stdout []byte, err error)
}

func Execute(ctx context.Context, runner Runner, name string, fields map[string]string) ([]byte, error) {
	command, found := Lookup(name)
	if !found {
		return nil, fmt.Errorf("%w: %q", ErrUnknownCommand, name)
	}
	argv, err := command.Build(fields)
	if err != nil {
		return nil, err
	}
	return runner.Run(ctx, argv)
}
