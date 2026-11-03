package archive

import (
	"strings"

	"crowdsec-dashboard/internal/lapi"
)

const (
	SourceKindLog    = "log"
	SourceKindAppSec = "appsec"
)

const (
	appSecServiceName   = "appsec"
	appSecLogTypePrefix = "appsec-"
)

func SourceKind(alert lapi.Alert) string {
	for _, receivedEvent := range alert.Events {
		if isAppSecEvent(receivedEvent.Meta) {
			return SourceKindAppSec
		}
	}
	return SourceKindLog
}

func IsSourceKind(candidate string) bool {
	return candidate == SourceKindLog || candidate == SourceKindAppSec
}

func isAppSecEvent(metaEntries []lapi.MetaEntry) bool {
	hasMatchedZones := false
	hasTargetFQDN := false
	for _, metaEntry := range metaEntries {
		switch metaEntry.Key {
		case "service":
			if metaEntry.Value == appSecServiceName {
				return true
			}
		case "log_type":
			if strings.HasPrefix(metaEntry.Value, appSecLogTypePrefix) {
				return true
			}
		case "matched_zones":
			hasMatchedZones = true
		case "target_fqdn":
			hasTargetFQDN = true
		}
	}
	return hasMatchedZones && hasTargetFQDN
}
