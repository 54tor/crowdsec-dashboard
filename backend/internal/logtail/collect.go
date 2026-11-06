package logtail

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func resolveRoots(allowedRoots []string) []string {
	resolved := make([]string, 0, len(allowedRoots))
	for _, rootCourante := range allowedRoots {
		if !filepath.IsAbs(rootCourante) {
			continue
		}
		resolvedRoot, resolveError := filepath.EvalSymlinks(rootCourante)
		if resolveError == nil {
			resolved = append(resolved, resolvedRoot)
		}
	}
	return resolved
}

func isUnderRoots(resolvedPath string, resolvedRoots []string) bool {
	return slices.ContainsFunc(resolvedRoots, func(rootCourante string) bool {
		relative, relativeError := filepath.Rel(rootCourante, resolvedPath)
		return relativeError == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
	})
}

func collectSources(declarations []declaration, resolvedRoots []string) ([]Source, bool) {
	seenPaths := map[string]bool{}
	sources := []Source{}
	for _, declarationCourante := range declarations {
		if declarationCourante.sourceKind != fileSourceKind {
			continue
		}
		for _, patternCourant := range declarationCourante.patterns {
			matches, _ := filepath.Glob(patternCourant)
			for _, matchCourant := range matches {
				source, isReadable := sourceOf(matchCourant, resolvedRoots)
				if !isReadable || seenPaths[source.Path] {
					continue
				}
				if len(sources) == MaxSources {
					return sortedSources(sources), true
				}
				seenPaths[source.Path] = true
				sources = append(sources, source)
			}
		}
	}
	return sortedSources(sources), false
}

func sourceOf(matchedPath string, resolvedRoots []string) (Source, bool) {
	resolvedPath, resolveError := filepath.EvalSymlinks(matchedPath)
	if resolveError != nil || !isUnderRoots(resolvedPath, resolvedRoots) {
		return Source{}, false
	}
	fileInfo, statError := os.Stat(resolvedPath)
	if statError != nil || !fileInfo.Mode().IsRegular() {
		return Source{}, false
	}
	return Source{ID: sourceIDOf(resolvedPath), Path: resolvedPath, Label: matchedPath}, true
}

func sortedSources(sources []Source) []Source {
	slices.SortFunc(sources, func(left Source, right Source) int {
		return strings.Compare(left.Label, right.Label)
	})
	return sources
}
