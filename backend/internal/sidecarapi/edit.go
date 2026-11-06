package sidecarapi

type EditFileResponse struct {
	Exists   bool   `json:"exists"`
	ReadOnly bool   `json:"read_only"`
	Digest   string `json:"digest"`
	Content  []byte `json:"content"`
}

type EditValidateRequest struct {
	Name    string `json:"name"`
	Content []byte `json:"content"`
}

type EditIssue struct {
	Line     int    `json:"line"`
	Path     string `json:"path"`
	Severity string `json:"severity"`
	Code     string `json:"code"`
}

type EditValidateResponse struct {
	Issues []EditIssue `json:"issues"`
}

type EditSaveRequest struct {
	Name           string `json:"name"`
	Content        []byte `json:"content"`
	ExpectedDigest string `json:"expected_digest"`
	Delete         bool   `json:"delete"`
}

type EditSaveResponse struct {
	Created        bool   `json:"created"`
	Deleted        bool   `json:"deleted"`
	Digest         string `json:"digest"`
	RolledBack     bool   `json:"rolled_back"`
	PreviousMasked []byte `json:"previous_masked"`
}
