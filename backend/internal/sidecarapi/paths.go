package sidecarapi

const (
	PathHealth                = "/healthz"
	PathPing                  = "/v1/ping"
	PathExec                  = "/v1/exec"
	PathFiles                 = "/v1/files"
	PathFilePrefix            = "/v1/files/"
	PathFlushMaxItems         = "/v1/config/flush-max-items"
	PathAcquisitionState      = "/v1/acquisition/state"
	PathAcquisitionFilePrefix = "/v1/acquisition/files/"
	PathConfigApply           = "/v1/config/apply"
	PathEditFilePrefix        = "/v1/config/edit/"
	PathEditValidate          = "/v1/config/edit-validate"
	PathEditSave              = "/v1/config/edit-save"
)
