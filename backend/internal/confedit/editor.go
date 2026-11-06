package confedit

import (
	"context"
	"errors"

	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/confschema"
	"crowdsec-dashboard/internal/confwrite"
)

const readOnlyConfigName = "config.yaml"

var (
	ErrDigestMismatch = errors.New("confedit: file changed since it was read")
	ErrSchemaInvalid  = errors.New("confedit: content has schema errors")
)

type File struct {
	Name     string
	Exists   bool
	ReadOnly bool
	Content  []byte
	Digest   string
}

type SaveRequest struct {
	Name           string
	Content        []byte
	ExpectedDigest string
	Delete         bool
}

type SaveResult struct {
	Created        bool
	Deleted        bool
	PreviousMasked []byte
	Digest         string
	RolledBack     bool
}

type Editor interface {
	Read(ctx context.Context, name string) (File, error)
	Validate(ctx context.Context, name string, content []byte) ([]confschema.Issue, error)
	Save(ctx context.Context, request SaveRequest) (SaveResult, error)
}

type dirEditor struct {
	confDir    string
	digester   Digester
	configTest func(ctx context.Context) error
}

func NewDirEditor(confDir string, digester Digester, configTest func(ctx context.Context) error) Editor {
	return dirEditor{confDir: confDir, digester: digester, configTest: configTest}
}

func (editor dirEditor) Read(_ context.Context, name string) (File, error) {
	current, readError := editor.readRaw(name)
	if readError != nil {
		return File{}, readError
	}
	return File{
		Name:     name,
		Exists:   current.Exists,
		ReadOnly: name == readOnlyConfigName,
		Content:  maskedContentOf(current),
		Digest:   editor.digestOf(current),
	}, nil
}

func (editor dirEditor) readRaw(name string) (confwrite.Current, error) {
	if name != readOnlyConfigName {
		if nameError := confwrite.ValidateEditableName(name); nameError != nil {
			return confwrite.Current{}, nameError
		}
	}
	current, readError := confwrite.ReadCurrentTree(editor.confDir, name)
	if readError != nil {
		return confwrite.Current{}, readError
	}
	if current.Oversized {
		return confwrite.Current{}, confwrite.ErrTooLarge
	}
	return current, nil
}

func (editor dirEditor) digestOf(current confwrite.Current) string {
	if !current.Exists {
		return AbsentDigest
	}
	return editor.digester.Of(current.Content)
}

func maskedContentOf(current confwrite.Current) []byte {
	if !current.Exists {
		return nil
	}
	return confread.Redact(current.Content)
}
