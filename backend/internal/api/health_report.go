package api

import "net/http"

type healthReport struct {
	Version  string    `json:"version"`
	Bouncers []Bouncer `json:"bouncers"`
	Machines []Machine `json:"machines"`
	Degraded []string  `json:"degraded"`
}

type healthReportHandlers struct{ platform Platform }

func (handlers healthReportHandlers) get(responseWriter http.ResponseWriter, request *http.Request) {
	report := healthReport{Bouncers: []Bouncer{}, Machines: []Machine{}, Degraded: []string{}}
	version, versionError := handlers.platform.Version(request.Context())
	if versionError != nil {
		report.Degraded = append(report.Degraded, "version")
	}
	report.Version = version
	bouncers, bouncersError := handlers.platform.Bouncers(request.Context())
	if bouncersError != nil {
		report.Degraded = append(report.Degraded, "bouncers")
	} else {
		report.Bouncers = bouncers
	}
	machines, machinesError := handlers.platform.Machines(request.Context())
	if machinesError != nil {
		report.Degraded = append(report.Degraded, "machines")
	} else {
		report.Machines = machines
	}
	writeJSON(responseWriter, http.StatusOK, report)
}
