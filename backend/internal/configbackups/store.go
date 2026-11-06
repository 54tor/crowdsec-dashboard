package configbackups

import (
	"context"
	"errors"
	"time"
)

const (
	RetainedBackupCount = 10
	MaximumContentBytes = 262144
)

var ErrNotFound = errors.New("config backup not found")

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
