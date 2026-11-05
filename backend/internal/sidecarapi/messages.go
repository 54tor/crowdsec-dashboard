package sidecarapi

const PingStatusOK = "ok"

type ErrorResponse struct {
	Code string `json:"code"`
}

type PingResponse struct {
	Status string `json:"status"`
}
