package api

import (
	"context"
	"net/http"
	"time"
)

type healthReport struct {
	Version       string         `json:"version"`
	Database      string         `json:"database"`
	SchemaVersion *int64         `json:"schema_version"`
	Collector     []engineHealth `json:"collector"`
	Bouncers      []Bouncer      `json:"bouncers"`
	Machines      []Machine      `json:"machines"`
	Degraded      []string       `json:"degraded"`
}

type healthReportHandlers struct {
	platform          Platform
	selfMachineID     string
	database          Pinger
	schemaVersion     SchemaVersionSource
	collectorStatus   CollectorStatusSource
	collectorInterval time.Duration
}

type SchemaVersionSource interface {
	SchemaVersion(ctx context.Context) (int64, error)
}

func (handlers healthReportHandlers) databaseState(ctx context.Context) string {
	if handlers.database == nil {
		return "unavailable"
	}
	pingContext, cancelPing := context.WithTimeout(ctx, healthPingTimeout)
	defer cancelPing()
	if pingError := handlers.database.PingContext(pingContext); pingError != nil {
		return "unavailable"
	}
	return "ok"
}

func (handlers healthReportHandlers) readSchemaVersion(ctx context.Context) *int64 {
	if handlers.schemaVersion == nil {
		return nil
	}
	schemaVersion, versionError := handlers.schemaVersion.SchemaVersion(ctx)
	if versionError != nil {
		return nil
	}
	return &schemaVersion
}

func (handlers healthReportHandlers) get(responseWriter http.ResponseWriter, request *http.Request) {
	report := healthReport{
		Bouncers:      []Bouncer{},
		Machines:      []Machine{},
		Degraded:      []string{},
		Database:      handlers.databaseState(request.Context()),
		SchemaVersion: handlers.readSchemaVersion(request.Context()),
		Collector:     collectorHealthOf(handlers.collectorStatus, time.Now(), staleIntervalMultiplier*handlers.collectorInterval),
	}
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
		for machineIndex := range machines {
			machines[machineIndex].Self = handlers.selfMachineID != "" && machines[machineIndex].MachineID == handlers.selfMachineID
		}
		report.Machines = machines
	}
	writeJSON(responseWriter, http.StatusOK, report)
}
