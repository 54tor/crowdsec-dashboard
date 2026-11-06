package confwrite

import (
	"crowdsec-dashboard/internal/confread"
)

func ReadCurrentTree(rootDir, name string) (Current, error) {
	if !confread.IsAllowedName(name) {
		return Current{}, ErrInvalidName
	}
	root, openError := openImportRoot(rootDir)
	if openError != nil {
		return Current{}, openError
	}
	defer root.Close()
	return readCurrent(root, name)
}
