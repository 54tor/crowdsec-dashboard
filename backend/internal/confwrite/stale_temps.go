package confwrite

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
)

var stageDirectoryParents = []string{"parsers", "postoverflows"}

func CleanStaleTemps(rootDir string) error {
	root, openError := openImportRoot(rootDir)
	if openError != nil {
		return openError
	}
	defer root.Close()
	editableDirectories, listError := editableDirectoriesOf(root)
	removeErrors := []error{listError}
	for _, editableDirectory := range editableDirectories {
		removeErrors = append(removeErrors, removeStaleTempsIn(root, editableDirectory))
	}
	return errors.Join(removeErrors...)
}

func editableDirectoriesOf(root *os.Root) ([]string, error) {
	editableDirectories := []string{"."}
	if isRealDirectory(root, acquisitionDirectory) {
		editableDirectories = append(editableDirectories, acquisitionDirectory)
	}
	listErrors := []error{}
	for _, stageParent := range stageDirectoryParents {
		stageDirectories, listError := stageDirectoriesUnder(root, stageParent)
		editableDirectories = append(editableDirectories, stageDirectories...)
		listErrors = append(listErrors, listError)
	}
	return editableDirectories, errors.Join(listErrors...)
}

func stageDirectoriesUnder(root *os.Root, stageParent string) ([]string, error) {
	if !isRealDirectory(root, stageParent) {
		return nil, nil
	}
	entries, listError := fs.ReadDir(root.FS(), stageParent)
	if listError != nil {
		return nil, listError
	}
	stageDirectories := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			stageDirectories = append(stageDirectories, path.Join(stageParent, entry.Name()))
		}
	}
	return stageDirectories, nil
}

func isRealDirectory(root *os.Root, name string) bool {
	dirInfo, lstatError := root.Lstat(name)
	return lstatError == nil && dirInfo.IsDir()
}

func removeStaleTempsIn(root *os.Root, directory string) error {
	entries, listError := fs.ReadDir(root.FS(), directory)
	if listError != nil {
		return listError
	}
	removeErrors := []error{}
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), tempFilePrefix) {
			removeErrors = append(removeErrors, root.Remove(path.Join(directory, entry.Name())))
		}
	}
	return errors.Join(removeErrors...)
}
