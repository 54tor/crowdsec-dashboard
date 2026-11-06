package logtail

import (
	"fmt"
	"path/filepath"
	"strings"
)

func ParseAllowedRoots(variableName string, rawValue string) ([]string, error) {
	if strings.TrimSpace(rawValue) == "" {
		return nil, nil
	}
	roots := []string{}
	for _, rawRoot := range strings.Split(rawValue, ":") {
		if !filepath.IsAbs(rawRoot) {
			return nil, fmt.Errorf("%s: %q must be an absolute path", variableName, rawRoot)
		}
		roots = append(roots, filepath.Clean(rawRoot))
	}
	return roots, nil
}
