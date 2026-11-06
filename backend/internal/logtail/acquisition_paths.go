package logtail

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	fileSourceKind         = "file"
	engineConfDirPrefix    = "/etc/crowdsec/"
	defaultAcquisitionFile = "acquis.yaml"
	defaultAcquisitionDir  = "acquis.d"
)

type declaration struct {
	sourceKind string
	patterns   []string
}

type acquisitionDocument struct {
	Source    string   `yaml:"source"`
	Filename  string   `yaml:"filename"`
	Filenames []string `yaml:"filenames"`
}

type engineConfig struct {
	CrowdsecService struct {
		AcquisitionPath string `yaml:"acquisition_path"`
		AcquisitionDir  string `yaml:"acquisition_dir"`
	} `yaml:"crowdsec_service"`
}

func readDeclarations(confDir string) ([]declaration, error) {
	acquisitionFile, acquisitionDir := acquisitionLocations(confDir)
	files := []string{}
	if acquisitionFile != "" {
		files = append(files, acquisitionFile)
	}
	files = append(files, yamlFilesOf(acquisitionDir)...)
	declarations := []declaration{}
	for _, fichierCourant := range files {
		fileDeclarations, readError := declarationsOf(fichierCourant)
		if readError != nil {
			return nil, readError
		}
		declarations = append(declarations, fileDeclarations...)
	}
	return declarations, nil
}

func acquisitionLocations(confDir string) (file string, dir string) {
	file = filepath.Join(confDir, defaultAcquisitionFile)
	dir = filepath.Join(confDir, defaultAcquisitionDir)
	content, readError := os.ReadFile(filepath.Join(confDir, "config.yaml"))
	if readError != nil {
		return file, dir
	}
	var configured engineConfig
	if yaml.Unmarshal(content, &configured) != nil {
		return file, dir
	}
	if mapped := mapEnginePath(confDir, configured.CrowdsecService.AcquisitionPath); mapped != "" {
		file = mapped
	}
	if mapped := mapEnginePath(confDir, configured.CrowdsecService.AcquisitionDir); mapped != "" {
		dir = mapped
	}
	return file, dir
}

func mapEnginePath(confDir string, configuredPath string) string {
	if configuredPath == "" {
		return ""
	}
	relative, isUnderEngineDir := strings.CutPrefix(configuredPath, engineConfDirPrefix)
	if isUnderEngineDir && fs.ValidPath(relative) {
		return filepath.Join(confDir, relative)
	}
	if strings.HasPrefix(configuredPath, filepath.Clean(confDir)+string(filepath.Separator)) {
		return filepath.Clean(configuredPath)
	}
	return ""
}

func yamlFilesOf(dir string) []string {
	entries, readError := os.ReadDir(dir)
	if readError != nil {
		return nil
	}
	files := []string{}
	for _, entryCourante := range entries {
		extension := filepath.Ext(entryCourante.Name())
		if entryCourante.Type().IsRegular() && (extension == ".yaml" || extension == ".yml") {
			files = append(files, filepath.Join(dir, entryCourante.Name()))
		}
	}
	slices.Sort(files)
	return files
}

func declarationsOf(path string) ([]declaration, error) {
	file, openError := os.Open(path)
	if errors.Is(openError, fs.ErrNotExist) {
		return nil, nil
	}
	if openError != nil {
		return nil, ErrAcquisitionInvalid
	}
	defer file.Close()
	decoder := yaml.NewDecoder(file)
	declarations := []declaration{}
	for {
		var document acquisitionDocument
		decodeError := decoder.Decode(&document)
		if errors.Is(decodeError, io.EOF) {
			return declarations, nil
		}
		if decodeError != nil {
			return nil, ErrAcquisitionInvalid
		}
		if declarationCourante, isUsable := declarationOf(document); isUsable {
			declarations = append(declarations, declarationCourante)
		}
	}
}

func declarationOf(document acquisitionDocument) (declaration, bool) {
	patterns := slices.Clone(document.Filenames)
	if document.Filename != "" {
		patterns = append(patterns, document.Filename)
	}
	sourceKind := document.Source
	if sourceKind == "" && len(patterns) > 0 {
		sourceKind = fileSourceKind
	}
	if sourceKind == "" {
		return declaration{}, false
	}
	return declaration{sourceKind: sourceKind, patterns: patterns}, true
}
