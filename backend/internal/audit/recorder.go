package audit

import (
	"context"
	"database/sql"
	"log"
	"strings"
	"unicode"

	"github.com/uptrace/bun"
)

type Action string

const (
	ActionLoginSuccess         Action = "login_success"
	ActionLoginFailure         Action = "login_failure"
	ActionSecondFactorFailure  Action = "second_factor_failure"
	ActionAccountLocked        Action = "account_locked"
	ActionLoginDenied          Action = "login_denied_access_rule"
	ActionRecoveryCodeUsed     Action = "recovery_code_used"
	ActionEnrollmentCompleted  Action = "enrollment_completed"
	ActionSecondFactorEnrolled Action = "second_factor_enrolled"
	ActionAccessRuleAdded      Action = "access_rule_added"
	ActionAccessRuleRemoved    Action = "access_rule_removed"
)

const maximumTargetRunes = 64

type Recorder interface {
	Record(ctx context.Context, accountID int64, action Action, target, clientIP string) error
}

type PostgresRecorder struct {
	database *bun.DB
}

func NewPostgresRecorder(database *bun.DB) *PostgresRecorder {
	return &PostgresRecorder{database: database}
}

func (recorder *PostgresRecorder) Record(ctx context.Context, accountID int64, action Action, target, clientIP string) error {
	var accountColumn sql.NullInt64
	if accountID != 0 {
		accountColumn = sql.NullInt64{Int64: accountID, Valid: true}
	}
	_, insertError := recorder.database.ExecContext(ctx,
		`INSERT INTO audit_event (audit_event_account_id, audit_event_action, audit_event_target, audit_event_client_ip)
		 VALUES (?, ?, ?, ?)`,
		accountColumn, string(action), sanitizeTarget(target), clientIP)
	return insertError
}

func sanitizeTarget(target string) string {
	withoutControlCharacters := strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return -1
		}
		return character
	}, strings.ToValidUTF8(target, ""))
	runes := []rune(withoutControlCharacters)
	if len(runes) > maximumTargetRunes {
		runes = runes[:maximumTargetRunes]
	}
	return string(runes)
}

func RecordOrLog(ctx context.Context, recorder Recorder, accountID int64, action Action, target, clientIP string) {
	if recordError := recorder.Record(ctx, accountID, action, target, clientIP); recordError != nil {
		log.Printf("audit: record %s: %v", action, recordError)
	}
}
