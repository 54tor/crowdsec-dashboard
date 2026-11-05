package sidecarapi

const PingStatusOK = "ok"

type ErrorResponse struct {
	Code string `json:"code"`
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
