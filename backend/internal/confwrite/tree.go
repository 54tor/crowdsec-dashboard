package confwrite

import (
	"errors"
	"io/fs"
	"os"
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

func parentDirectoriesOf(names []string) []string {
	directories := []string{}
	for _, name := range names {
		directory := path.Dir(name)
		if directory != "." && !slices.Contains(directories, directory) {
			directories = append(directories, directory)
		}
	}
	return directories
}

func syncDirectoriesOf(root *os.Root, names []string, syncDir func(*os.Root, string) error) error {
	syncErrors := []error{syncDir(root, ".")}
	for _, directory := range parentDirectoriesOf(names) {
		syncErrors = append(syncErrors, syncDir(root, directory))
	}
	return errors.Join(syncErrors...)
}
