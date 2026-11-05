package sidecarapi

type FileListResponse struct {
	Files []string `json:"files"`
}

type FileResponse struct {
	Name    string `json:"name"`
	Content []byte `json:"content"`
}

type FlushMaxItemsResponse struct {
	MaxItems int  `json:"max_items"`
	Readable bool `json:"readable"`
}

type AcquisitionState struct {
	Writable        bool `json:"writable"`
	RecoveryPending bool `json:"recovery_pending"`
}

type AcquisitionFileResponse struct {
	Exists    bool   `json:"exists"`
	Oversized bool   `json:"oversized"`
	Digest    string `json:"digest"`
	Content   []byte `json:"content"`
}

type ApplyChange struct {
	Name    string `json:"name"`
	Content []byte `json:"content"`
}

type ApplyRequest struct {
	Changes []ApplyChange `json:"changes"`
}

type ApplyResult struct {
	Created    []string `json:"created"`
	Updated    []string `json:"updated"`
	Unchanged  []string `json:"unchanged"`
	RolledBack bool     `json:"rolled_back"`
}
