package bundle

import (
	"context"
	"errors"

	"crowdsec-dashboard/internal/confwrite"
)

var ErrUnredactedUnavailable = errors.New("bundle: unredacted configuration unavailable")

type ConfigReader interface {
	List(ctx context.Context) ([]string, error)
	Read(ctx context.Context, name string) ([]byte, error)
	ReadUnredacted(ctx context.Context, name string) ([]byte, error)
	FlushMaxItems(ctx context.Context) (int, bool)
}

type CurrentFile struct {
	Exists          bool
	Oversized       bool
	Digest          string
	RedactedContent []byte
}

type AcquisitionWriter interface {
	State(ctx context.Context) (writable bool, recoveryPending bool, err error)
	ReadCurrent(ctx context.Context, name string) (CurrentFile, error)
	Apply(ctx context.Context, changes []confwrite.FileChange) (confwrite.Result, error)
}
