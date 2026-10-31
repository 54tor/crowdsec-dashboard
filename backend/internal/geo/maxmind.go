package geo

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang/v2"
)

const statInterval = time.Minute

type loadedDatabase struct {
	reader   *geoip2.Reader
	fileInfo os.FileInfo
}

type MaxMindFile struct {
	databasePath   string
	now            func() time.Time
	current        atomic.Pointer[loadedDatabase]
	lastCheckNanos atomic.Int64
	reloadMutex    sync.Mutex
}

func NewMaxMindFile(databasePath string, now func() time.Time) *MaxMindFile {
	maxMindFile := &MaxMindFile{databasePath: databasePath, now: now}
	maxMindFile.reloadIfChanged()
	return maxMindFile
}

func (maxMindFile *MaxMindFile) CountryCode(_ context.Context, address netip.Addr) (string, error) {
	maxMindFile.reloadIfDue()
	database := maxMindFile.current.Load()
	if database == nil {
		return "", ErrGeolocationUnavailable
	}
	record, lookupError := database.reader.Country(address.Unmap())
	if lookupError != nil {
		return "", fmt.Errorf("geo: lookup: %w", lookupError)
	}
	if !record.HasData() || record.Country.ISOCode == "" {
		return "", ErrCountryUnknown
	}
	return record.Country.ISOCode, nil
}

func (maxMindFile *MaxMindFile) Available() bool {
	return maxMindFile.current.Load() != nil
}

func (maxMindFile *MaxMindFile) DatabaseAge() (time.Duration, bool) {
	database := maxMindFile.current.Load()
	if database == nil {
		return 0, false
	}
	return maxMindFile.now().Sub(database.fileInfo.ModTime()), true
}

func (maxMindFile *MaxMindFile) reloadIfDue() {
	lastCheck := time.Unix(0, maxMindFile.lastCheckNanos.Load())
	if maxMindFile.now().Sub(lastCheck) < statInterval {
		return
	}
	maxMindFile.reloadIfChanged()
}

func (maxMindFile *MaxMindFile) reloadIfChanged() {
	if !maxMindFile.reloadMutex.TryLock() {
		return
	}
	defer maxMindFile.reloadMutex.Unlock()
	maxMindFile.lastCheckNanos.Store(maxMindFile.now().UnixNano())

	fileInfo, statError := os.Stat(maxMindFile.databasePath)
	if statError != nil {
		return
	}
	if !maxMindFile.hasChanged(fileInfo) {
		return
	}
	reader, loadError := openReader(maxMindFile.databasePath)
	if loadError != nil {
		log.Printf("geo: keeping previous database, cannot load %s: %v", maxMindFile.databasePath, loadError)
		return
	}
	maxMindFile.current.Store(&loadedDatabase{reader: reader, fileInfo: fileInfo})
}

func (maxMindFile *MaxMindFile) hasChanged(fileInfo os.FileInfo) bool {
	database := maxMindFile.current.Load()
	if database == nil {
		return true
	}
	previous := database.fileInfo
	return previous.Size() != fileInfo.Size() ||
		!previous.ModTime().Equal(fileInfo.ModTime()) ||
		!os.SameFile(previous, fileInfo)
}

func openReader(databasePath string) (*geoip2.Reader, error) {
	content, readError := os.ReadFile(databasePath)
	if readError != nil {
		return nil, readError
	}
	return geoip2.OpenBytes(content)
}
