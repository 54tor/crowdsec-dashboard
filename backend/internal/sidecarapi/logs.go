package sidecarapi

type LogSource struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type LogUnreadable struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

type LogSourcesResponse struct {
	Sources    []LogSource     `json:"sources"`
	Unreadable []LogUnreadable `json:"unreadable"`
	Truncated  bool            `json:"truncated"`
}

type LogLinesResponse struct {
	Lines     []string `json:"lines"`
	FileSize  int64    `json:"file_size"`
	Truncated bool     `json:"truncated"`
}
