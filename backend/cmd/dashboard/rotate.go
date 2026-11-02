package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/secrets"
	"crowdsec-dashboard/internal/store"
)

const (
	rotateSecretsCommand = "rotate-secrets"
	rotationBatchSize    = 500
)

func runRotateSecrets(ctx context.Context, arguments []string, loadedConfig config.Config, output io.Writer) error {
	flags := flag.NewFlagSet(rotateSecretsCommand, flag.ContinueOnError)
	dryRun := flags.Bool("dry-run", false, "count the rows per key id without rewriting them")
	if parseError := flags.Parse(arguments); parseError != nil {
		return parseError
	}
	keyring, keyringError := loadSecretsKeyring(loadedConfig.SecretsKeyFile, loadedConfig.SecretsRetiredKeyFiles)
	if keyringError != nil {
		return fmt.Errorf("secrets key: %w", keyringError)
	}
	database, openError := store.Open(ctx, loadedConfig.DatabaseURL)
	if openError != nil {
		return fmt.Errorf("database: %w", openError)
	}
	defer database.Close()
	return rotateSecrets(ctx, database, keyring, *dryRun, output)
}

func rotateSecrets(ctx context.Context, database *bun.DB, keyring *secrets.Keyring, dryRun bool, output io.Writer) error {
	report, rotateError := secrets.Rotate(ctx, database, keyring, dryRun, rotationBatchSize)
	printRotationReport(output, report, dryRun)
	if !dryRun {
		audit.RecordOrLog(ctx, audit.NewPostgresRecorder(database), 0, audit.ActionSecretsRotated, strconv.FormatInt(report.Rewritten(), 10), "")
	}
	return rotateError
}

func printRotationReport(output io.Writer, report secrets.RotationReport, dryRun bool) {
	fmt.Fprintf(output, "current key id: %s\n", report.CurrentKeyID)
	for _, columnReport := range report.Columns {
		fmt.Fprintf(output, "%s\n", columnReport.Column)
		for _, keyID := range slices.Sorted(maps.Keys(columnReport.KeyIDCounts)) {
			fmt.Fprintf(output, "  key id %s: %d rows\n", keyID, columnReport.KeyIDCounts[keyID])
		}
		if !dryRun {
			fmt.Fprintf(output, "  rewritten: %d, skipped_concurrent: %d\n", columnReport.Rewritten, columnReport.SkippedConcurrent)
		}
		if len(columnReport.UnreadableIDs) > 0 {
			fmt.Fprintf(output, "  unreadable row ids: %v\n", columnReport.UnreadableIDs)
		}
	}
	if dryRun {
		fmt.Fprintln(output, "dry run: nothing was rewritten")
	}
}
