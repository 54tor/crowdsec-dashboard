package accounts

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

func (repository *Repository) RevokeSessions(ctx context.Context, executor bun.IDB, accountID int64) error {
	if _, deleteError := executor.ExecContext(ctx, `DELETE FROM session WHERE session_account_id = ?`, accountID); deleteError != nil {
		return fmt.Errorf("revoke account sessions: %w", deleteError)
	}
	return nil
}
