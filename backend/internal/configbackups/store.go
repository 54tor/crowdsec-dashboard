package configbackups

import (
	"bytes"
	"context"
	"errors"
	"time"
)

const (
	RetainedBackupCount = 10
	MaximumContentBytes = 262144
)

var (
	ErrNotFound        = errors.New("config backup not found")
	ErrContentTooLarge = errors.New("config backup content too large")
	ErrContentInvalid  = errors.New("config backup content contains a NUL byte")
)

func validateContent(content []byte) error {
	if len(content) > MaximumContentBytes {
		return ErrContentTooLarge
	}
	if bytes.IndexByte(content, 0) >= 0 {
		return ErrContentInvalid
	}
	return nil
}

type Backup struct {
	ID          int64
	EngineName  string
	FileName    string
	Content     []byte
	CreatedAt   time.Time
	AccountName string
	Digest      string
}

type Store interface {
	Add(ctx context.Context, backup Backup) error
	List(ctx context.Context, engineName, fileName string) ([]Backup, error)
	Get(ctx context.Context, id int64) (Backup, error)
}
