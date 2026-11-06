package confwrite

import (
	"errors"
	"io/fs"
	"path"
	"slices"

	"crowdsec-dashboard/internal/confread"
)

const (
	readOnlyConfigName   = "config.yaml"
	acquisitionDirectory = "acquis.d"
)

var (
	ErrReadOnlyFile  = errors.New("confwrite: read-only file")
	ErrProtectedFile = errors.New("confwrite: protected file cannot be deleted")
	ErrParentMissing = errors.New("confwrite: parent directory missing")
)

var protectedFromDeletion = []string{readOnlyConfigName, "acquis.yaml", "profiles.yaml"}

func ValidateEditableName(name string) error {
	if name == readOnlyConfigName {
		return ErrReadOnlyFile
	}
	if !confread.IsAllowedName(name) {
		return ErrInvalidName
	}
	return nil
}

func requireParentDirectory(root rootInspector, name string) error {
	parentInfo, lstatError := root.Lstat(path.Dir(name))
	if errors.Is(lstatError, fs.ErrNotExist) {
		return ErrParentMissing
	}
	if lstatError != nil {
		return lstatError
	}
	if !parentInfo.IsDir() {
		return ErrParentMissing
	}
	return nil
}

type rootInspector interface {
	Lstat(name string) (fs.FileInfo, error)
}

func parentDirectoriesOf(writes []*pendingWrite) []string {
	directories := []string{}
	for _, write := range writes {
		directory := path.Dir(write.name)
		if directory != "." && !slices.Contains(directories, directory) {
			directories = append(directories, directory)
		}
	}
	return directories
}
