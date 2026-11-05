package engines

import (
	"errors"
	"net/netip"
	"time"
)

var (
	ErrEngineExists   = errors.New("engine already exists")
	ErrEngineDeleting = errors.New("engine is being deleted")
	ErrEngineNotFound = errors.New("engine not found")
	ErrLocalReadOnly  = errors.New("local engine cannot be modified")
	ErrInvalidEngine  = errors.New("invalid engine")
	ErrSecretRequired = errors.New("secret must be provided again")
)

type Engine struct {
	ID                  int64
	Name                string
	IsLocal             bool
	LAPIURL             string
	MachineID           string
	Proxy               *Proxy
	AllowInsecureHTTP   bool
	PublicAddresses     []netip.Addr
	Enabled             bool
	SyncEnabled         bool
	CollectionCursor    int64
	LastCollectedAt     *time.Time
	LastCollectionError string
	CursorReset         bool
	HistoryIncomplete   bool
	Sidecar             *Sidecar
}

type Proxy struct {
	Kind           string
	URL            string
	HasCredentials bool
}

type Credentials struct {
	MachinePassword string `json:"-"`
	ProxyUsername   string `json:"-"`
	ProxyPassword   string `json:"-"`
}

type Input struct {
	Name              string
	LAPIURL           string
	MachineID         string
	MachinePassword   *string
	Proxy             *ProxyInput
	RemoveProxy       bool
	AllowInsecureHTTP *bool
	Enabled           *bool
	SyncEnabled       *bool
	PublicAddresses   *[]string
}

type ProxyInput struct {
	Kind             string
	URL              string
	Username         *string
	Password         *string
	ClearCredentials bool
}

func invalidField(field, reason string) error {
	return &fieldError{field: field, reason: reason}
}

type fieldError struct {
	field  string
	reason string
}

func (fieldFailure *fieldError) Error() string {
	if fieldFailure.reason == "" {
		return "invalid engine: field " + fieldFailure.field
	}
	return "invalid engine: field " + fieldFailure.field + " " + fieldFailure.reason
}

func (fieldFailure *fieldError) Unwrap() error {
	return ErrInvalidEngine
}
