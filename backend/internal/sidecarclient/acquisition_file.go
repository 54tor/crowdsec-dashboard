package sidecarclient

import (
	"regexp"

	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/sidecarapi"
)

var rawHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type AcquisitionFile struct {
	Exists          bool
	Oversized       bool
	SHA256          string
	RedactedContent []byte
}

func acquisitionFileOf(fileResponse sidecarapi.AcquisitionFileResponse) (AcquisitionFile, error) {
	if !isConsistentAcquisitionFile(fileResponse) {
		return AcquisitionFile{}, ErrInvalidResponse
	}
	return AcquisitionFile{
		Exists:          fileResponse.Exists,
		Oversized:       fileResponse.Oversized,
		SHA256:          fileResponse.SHA256,
		RedactedContent: fileResponse.Content,
	}, nil
}

func isConsistentAcquisitionFile(fileResponse sidecarapi.AcquisitionFileResponse) bool {
	hasReadableContent := fileResponse.Exists && !fileResponse.Oversized
	if !hasReadableContent {
		isKnownState := fileResponse.Exists || !fileResponse.Oversized
		return isKnownState && fileResponse.Content == nil && fileResponse.SHA256 == ""
	}
	isContentWithinCap := fileResponse.Content != nil && len(fileResponse.Content) <= confwrite.MaxFileBytes
	return isContentWithinCap && rawHashPattern.MatchString(fileResponse.SHA256)
}
