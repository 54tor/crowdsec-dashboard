package allowguard

import "time"

func EntryExpiration(rawExpiration string) (time.Time, bool) {
	if rawExpiration == "" {
		return time.Time{}, false
	}
	expiresAt, parseError := time.Parse(time.RFC3339Nano, rawExpiration)
	if parseError != nil || expiresAt.Year() <= 1 {
		return time.Time{}, false
	}
	return expiresAt, true
}

func entryIsActive(rawExpiration string, now time.Time) bool {
	expiresAt, hasExpiration := EntryExpiration(rawExpiration)
	return !hasExpiration || !expiresAt.Before(now)
}
