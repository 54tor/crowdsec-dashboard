package cscli

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrUnknownCommand = errors.New("unknown cscli command")
	ErrCscliFailed    = errors.New("cscli command failed")
	ErrTimeout        = errors.New("cscli command timed out")
)

type Runner interface {
	Run(ctx context.Context, argv []string) (stdout []byte, err error)
}

func execute(ctx context.Context, runner Runner, name string, fields map[string]string) ([]byte, error) {
	command, found := Lookup(name)
	if !found {
		return nil, fmt.Errorf("%w: %q", ErrUnknownCommand, name)
	}
	argv, err := command.Build(fields)
	if err != nil {
		return nil, err
	}
	commandContext, cancel := context.WithTimeout(ctx, command.Timeout)
	defer cancel()
	output, runError := runner.Run(commandContext, argv)
	if runError != nil && errors.Is(runError, context.DeadlineExceeded) && ctx.Err() == nil {
		return nil, ErrTimeout
	}
	return output, runError
}
