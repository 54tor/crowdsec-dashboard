package sidecarclient

import (
	"regexp"

	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/sidecarapi"
)

var keyedDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type AcquisitionFile struct {
	Exists          bool
	Oversized       bool
	Digest          string
	RedactedContent []byte
}

func acquisitionFileOf(fileResponse sidecarapi.AcquisitionFileResponse) (AcquisitionFile, error) {
	if !isConsistentAcquisitionFile(fileResponse) {
		return AcquisitionFile{}, ErrInvalidResponse
	}
	return AcquisitionFile{
		Exists:          fileResponse.Exists,
		Oversized:       fileResponse.Oversized,
		Digest:          fileResponse.Digest,
		RedactedContent: fileResponse.Content,
	}, nil
}

func isConsistentAcquisitionFile(fileResponse sidecarapi.AcquisitionFileResponse) bool {
	hasReadableContent := fileResponse.Exists && !fileResponse.Oversized
	if !hasReadableContent {
		isKnownState := fileResponse.Exists || !fileResponse.Oversized
		return isKnownState && fileResponse.Content == nil && fileResponse.Digest == ""
	}
	isContentWithinCap := fileResponse.Content != nil && len(fileResponse.Content) <= confwrite.MaxFileBytes
	return isContentWithinCap && keyedDigestPattern.MatchString(fileResponse.Digest)
}
