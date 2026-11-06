package api

import (
	"context"

	"crowdsec-dashboard/internal/logtail"
	"crowdsec-dashboard/internal/sidecarapi"
	"crowdsec-dashboard/internal/sidecarclient"
)

type LogSources interface {
	List(ctx context.Context) (logtail.Listing, error)
	Read(ctx context.Context, sourceID string, lineCount int) (logtail.Lines, error)
}

type readerLogSources struct{ reader logtail.Reader }

func (sources readerLogSources) List(context.Context) (logtail.Listing, error) {
	return sources.reader.List()
}

func (sources readerLogSources) Read(_ context.Context, sourceID string, lineCount int) (logtail.Lines, error) {
	return sources.reader.Read(sourceID, lineCount)
}

type sidecarLogSources struct{ client *sidecarclient.Client }

func (sources sidecarLogSources) List(ctx context.Context) (logtail.Listing, error) {
	response, listError := sources.client.ListLogSources(ctx)
	if listError != nil {
		return logtail.Listing{}, listError
	}
	return listingOf(response), nil
}

func (sources sidecarLogSources) Read(ctx context.Context, sourceID string, lineCount int) (logtail.Lines, error) {
	response, readError := sources.client.ReadLogSource(ctx, sourceID, lineCount)
	if readError != nil {
		return logtail.Lines{}, readError
	}
	return logtail.Lines{Lines: response.Lines, FileSize: response.FileSize, Truncated: response.Truncated}, nil
}

func listingOf(response sidecarapi.LogSourcesResponse) logtail.Listing {
	listing := logtail.Listing{Truncated: response.Truncated}
	for _, sourceCourante := range response.Sources {
		listing.Sources = append(listing.Sources, logtail.Source{ID: sourceCourante.ID, Label: sourceCourante.Label})
	}
	for _, unreadableCourant := range response.Unreadable {
		listing.Unreadable = append(listing.Unreadable, logtail.UnreadableSource{Kind: unreadableCourant.Kind, Detail: unreadableCourant.Detail})
	}
	return listing
}
