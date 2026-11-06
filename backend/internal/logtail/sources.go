package logtail

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
)

const (
	MaxSources         = 200
	sourceIDByteLength = 16
)

var (
	ErrLogsDisabled       = errors.New("logtail: no allowed log root configured")
	ErrAcquisitionInvalid = errors.New("logtail: acquisition configuration is invalid")
)

type Source struct {
	ID       string
	Root     string
	Relative string
	Label    string
}

type UnreadableSource struct {
	Kind   string
	Detail string
}

type Listing struct {
	Sources    []Source
	Unreadable []UnreadableSource
	Truncated  bool
}

func ListSources(confDir string, allowedRoots []string) (Listing, error) {
	resolvedRoots := resolveRoots(allowedRoots)
	if len(resolvedRoots) == 0 {
		return Listing{}, ErrLogsDisabled
	}
	declarations, declarationError := readDeclarations(confDir)
	if declarationError != nil {
		return Listing{}, declarationError
	}
	listing := Listing{Unreadable: unreadableKindsOf(declarations)}
	listing.Sources, listing.Truncated = collectSources(declarations, resolvedRoots)
	return listing, nil
}

func unreadableKindsOf(declarations []declaration) []UnreadableSource {
	kinds := make([]string, 0)
	for _, declarationCourante := range declarations {
		isFile := declarationCourante.sourceKind == fileSourceKind
		if !isFile && !slices.Contains(kinds, declarationCourante.sourceKind) {
			kinds = append(kinds, declarationCourante.sourceKind)
		}
	}
	slices.Sort(kinds)
	unreadable := make([]UnreadableSource, 0, len(kinds))
	for _, kindCourant := range kinds {
		unreadable = append(unreadable, UnreadableSource{Kind: kindCourant})
	}
	return unreadable
}

func sourceIDOf(resolvedPath string) string {
	digest := sha256.Sum256([]byte(resolvedPath))
	return hex.EncodeToString(digest[:sourceIDByteLength])
}
