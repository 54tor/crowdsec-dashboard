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

func containingRoot(resolvedPath string, resolvedRoots []string) (root string, relative string, found bool) {
	for _, rootCourante := range resolvedRoots {
		relativePath, relativeError := filepath.Rel(rootCourante, resolvedPath)
		isInside := relativeError == nil && relativePath != "." && relativePath != ".." && !strings.HasPrefix(relativePath, ".."+string(filepath.Separator))
		if isInside {
			return rootCourante, relativePath, true
		}
	}
	return "", "", false
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
				if !isReadable || seenPaths[source.Root+"/"+source.Relative] {
					continue
				}
				if len(sources) == MaxSources {
					return sortedSources(sources), true
				}
				seenPaths[source.Root+"/"+source.Relative] = true
				sources = append(sources, source)
			}
		}
	}
	return sortedSources(sources), false
}

func sourceOf(matchedPath string, resolvedRoots []string) (Source, bool) {
	resolvedPath, resolveError := filepath.EvalSymlinks(matchedPath)
	if resolveError != nil {
		return Source{}, false
	}
	root, relative, isInside := containingRoot(resolvedPath, resolvedRoots)
	if !isInside {
		return Source{}, false
	}
	fileInfo, statError := os.Stat(resolvedPath)
	if statError != nil || !fileInfo.Mode().IsRegular() {
		return Source{}, false
	}
	return Source{ID: sourceIDOf(resolvedPath), Root: root, Relative: relative, Label: matchedPath}, true
}

func sortedSources(sources []Source) []Source {
	slices.SortFunc(sources, func(left Source, right Source) int {
		return strings.Compare(left.Label, right.Label)
	})
	return sources
}
