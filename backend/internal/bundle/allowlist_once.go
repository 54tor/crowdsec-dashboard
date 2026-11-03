package bundle

import (
	"context"

	"crowdsec-dashboard/internal/lapi"
)

type onceAllowlistReader struct {
	reader    AllowlistReader
	isRead    bool
	read      lapi.AllowlistRead
	readError error
}

func readAllowlistsOnce(reader AllowlistReader) AllowlistReader {
	if reader == nil {
		return nil
	}
	return &onceAllowlistReader{reader: reader}
}

func (cached *onceAllowlistReader) ListAllowlists(ctx context.Context) (lapi.AllowlistRead, error) {
	if !cached.isRead {
		cached.read, cached.readError = cached.reader.ListAllowlists(ctx)
		cached.isRead = true
	}
	return cached.read, cached.readError
}
