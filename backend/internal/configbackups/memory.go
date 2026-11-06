package configbackups

import (
	"context"
	"sync"
	"time"
)

type memoryStore struct {
	lock       sync.Mutex
	backups    []Backup
	lastBackup int64
}

func NewMemoryStore() Store {
	return &memoryStore{}
}

func (store *memoryStore) Add(_ context.Context, backup Backup) error {
	if contentError := validateContent(backup.Content); contentError != nil {
		return contentError
	}
	store.lock.Lock()
	defer store.lock.Unlock()

	store.lastBackup++
	backup.ID = store.lastBackup
	backup.CreatedAt = time.Now().UTC()
	backup.Content = append([]byte(nil), backup.Content...)
	store.backups = append(store.backups, backup)

	store.dropBackupsBeyondRetention(backup.EngineName, backup.FileName)
	return nil
}

func (store *memoryStore) dropBackupsBeyondRetention(engineName, fileName string) {
	remainingForFile := RetainedBackupCount
	keptBackups := make([]Backup, len(store.backups))
	keptCount := len(store.backups)
	for backupIndex := len(store.backups) - 1; backupIndex >= 0; backupIndex-- {
		backup := store.backups[backupIndex]
		if backup.EngineName == engineName && backup.FileName == fileName {
			if remainingForFile == 0 {
				continue
			}
			remainingForFile--
		}
		keptCount--
		keptBackups[keptCount] = backup
	}
	store.backups = keptBackups[keptCount:]
}

func (store *memoryStore) List(_ context.Context, engineName, fileName string) ([]Backup, error) {
	store.lock.Lock()
	defer store.lock.Unlock()

	listedBackups := []Backup{}
	for backupIndex := len(store.backups) - 1; backupIndex >= 0; backupIndex-- {
		backup := store.backups[backupIndex]
		if backup.EngineName == engineName && backup.FileName == fileName {
			listedBackups = append(listedBackups, backup)
		}
	}
	return listedBackups, nil
}

func (store *memoryStore) Get(_ context.Context, id int64) (Backup, error) {
	store.lock.Lock()
	defer store.lock.Unlock()

	for _, backup := range store.backups {
		if backup.ID == id {
			return backup, nil
		}
	}
	return Backup{}, ErrNotFound
}
