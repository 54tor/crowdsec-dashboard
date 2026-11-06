package api

import (
	"context"
	"crypto/rand"

	"crowdsec-dashboard/internal/confedit"
	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/digest"
	"crowdsec-dashboard/internal/sidecarclient"
)

const localDigestKeyBytes = 32

type ConfigEditor interface {
	confedit.Editor
	Writable() bool
}

type localConfigEditor struct {
	confedit.Editor
	confDir string
}

func NewLocalConfigEditor(confDir string, configTest func(ctx context.Context) error) ConfigEditor {
	digestKey := make([]byte, localDigestKeyBytes)
	rand.Read(digestKey)
	return localConfigEditor{Editor: confedit.NewDirEditor(confDir, digest.NewDigester(digestKey), configTest), confDir: confDir}
}

func (editor localConfigEditor) Writable() bool {
	return confwrite.CheckWritable(editor.confDir) == nil
}

type sidecarConfigEditor struct{ confedit.Editor }

func newSidecarConfigEditor(sidecar *sidecarclient.Client) ConfigEditor {
	return sidecarConfigEditor{Editor: sidecar.Editor()}
}

func (sidecarConfigEditor) Writable() bool {
	return true
}
