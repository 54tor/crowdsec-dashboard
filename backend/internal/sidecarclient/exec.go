package sidecarclient

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
)

const remoteTimeoutMargin = 10 * time.Second

func (client *Client) Execute(ctx context.Context, name string, fields map[string]string) ([]byte, error) {
	command, found := cscli.Lookup(name)
	if !found {
		return nil, fmt.Errorf("%w: %q", cscli.ErrUnknownCommand, name)
	}
	if _, buildError := command.Build(fields); buildError != nil {
		return nil, buildError
	}
	body, encodeError := json.Marshal(sidecarapi.ExecRequest{Command: command.Name, Fields: fields})
	if encodeError != nil {
		return nil, fmt.Errorf("%w: encode request", ErrUnavailable)
	}
	execContext, cancel := context.WithTimeout(ctx, command.Timeout+remoteTimeoutMargin)
	defer cancel()
	var execResponse sidecarapi.ExecResponse
	if exchangeError := client.exchange(execContext, sidecarapi.PathExec, body, &execResponse); exchangeError != nil {
		return nil, exchangeError
	}
	return checkedOutput(execResponse.Output)
}

func checkedOutput(output []byte) ([]byte, error) {
	if output == nil {
		return nil, ErrInvalidResponse
	}
	if len(output) > sidecarapi.MaxExecOutputBytes {
		return nil, cscli.ErrOutputTooLarge
	}
	return output, nil
}
