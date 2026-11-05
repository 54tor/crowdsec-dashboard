package api

import (
	"context"
	"io/fs"
	"path"
	"strings"

	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/sidecarclient"
)

type ConfigFiles interface {
	List(ctx context.Context) ([]string, error)
	Read(ctx context.Context, name string) ([]byte, error)
}

type dirConfigFiles struct{ dir string }

func (files dirConfigFiles) List(context.Context) ([]string, error) {
	return confread.List(files.dir)
}

func (files dirConfigFiles) Read(_ context.Context, name string) ([]byte, error) {
	return confread.Read(files.dir, name)
}

type sidecarConfigFiles struct{ sidecar *sidecarclient.Client }

func (files sidecarConfigFiles) List(ctx context.Context) ([]string, error) {
	return files.sidecar.ListFiles(ctx)
}

func (files sidecarConfigFiles) Read(ctx context.Context, name string) ([]byte, error) {
	return files.sidecar.ReadFile(ctx, name)
}

func isRequestableConfigFileName(name string) bool {
	isCleanRelativePath := fs.ValidPath(name) && name != "." && !strings.ContainsAny(name, "\\\x00")
	namesCredentials := strings.Contains(strings.ToLower(path.Base(name)), "credentials")
	return isCleanRelativePath && !namesCredentials
}
