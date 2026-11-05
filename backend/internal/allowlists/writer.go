package allowlists

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/netparse"
)

type cscliWriter struct {
	executor cscli.Executor
}

func NewCscliWriter(executor cscli.Executor) Writer {
	return &cscliWriter{executor: executor}
}

func (writer *cscliWriter) Create(ctx context.Context, allowlistName, description string) error {
	return writer.execute(ctx, "allowlists_create", map[string]string{"name": allowlistName, "description": description})
}

func (writer *cscliWriter) Delete(ctx context.Context, allowlistName string) error {
	return writer.execute(ctx, "allowlists_delete", map[string]string{"name": allowlistName})
}

func (writer *cscliWriter) Add(ctx context.Context, allowlistName string, value netip.Prefix, expiration, description string) error {
	fields := map[string]string{"name": allowlistName, "value": netparse.CanonicalAllowlistValue(value)}
	if expiration != "" {
		fields["expiration"] = expiration
	}
	if description != "" {
		fields["comment"] = description
	}
	return writer.execute(ctx, "allowlists_add", fields)
}

func (writer *cscliWriter) Remove(ctx context.Context, allowlistName string, value netip.Prefix) error {
	return writer.execute(ctx, "allowlists_remove", map[string]string{"name": allowlistName, "value": netparse.CanonicalAllowlistValue(value)})
}

func (writer *cscliWriter) execute(ctx context.Context, commandName string, fields map[string]string) error {
	_, executeError := writer.executor.Execute(ctx, commandName, fields)
	return classifyCscliError(executeError)
}

func classifyCscliError(executeError error) error {
	switch {
	case executeError == nil:
		return nil
	case errors.Is(executeError, cscli.ErrInvalidField):
		return fmt.Errorf("%w: %w", ErrInvalid, executeError)
	case errors.Is(executeError, cscli.ErrTimeout):
		return fmt.Errorf("%w: %w", ErrWriteFailed, cscli.ErrTimeout)
	default:
		return fmt.Errorf("%w: %w", ErrWriteFailed, cscli.ErrCscliFailed)
	}
}

type localOnlyWriters struct {
	local Writer
}

func LocalOnlyWriters(local Writer) WriterSource {
	return localOnlyWriters{local: local}
}

func (source localOnlyWriters) Writer(engine engines.Engine) (Writer, bool) {
	if !engine.IsLocal {
		return nil, false
	}
	return source.local, true
}
