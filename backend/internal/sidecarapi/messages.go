package sidecarapi

const PingStatusOK = "ok"

type ErrorResponse struct {
	Code          string       `json:"code"`
	Result        *ApplyResult `json:"result,omitempty"`
	AffectedFiles []string     `json:"affected_files,omitempty"`
}

type PingResponse struct {
	Status string `json:"status"`
}

type ExecRequest struct {
	Command string            `json:"command"`
	Fields  map[string]string `json:"fields"`
}

type ExecResponse struct {
	Output []byte `json:"output"`
}
