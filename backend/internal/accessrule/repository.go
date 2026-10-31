package accessrule

import (
	"context"
	"errors"
	"net/netip"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/geo"
)

var (
	ErrRuleExists             = errors.New("access rule already exists")
	ErrRuleNotFound           = errors.New("access rule not found")
	ErrWouldLockOut           = errors.New("rule set would deny the current client")
	ErrGeolocationUnavailable = geo.ErrGeolocationUnavailable
)

type Repository struct {
	database *bun.DB
}

func NewRepository(database *bun.DB) *Repository {
	return &Repository{database: database}
}

func (repository *Repository) List(ctx context.Context, accountID int64) ([]Rule, error) {
	return listRules(ctx, repository.database, accountID)
}

func (repository *Repository) Add(ctx context.Context, accountID int64, kind, value string, clientIP netip.Addr, geolocator geo.Geolocator) (Rule, error) {
	canonicalValue, canonicalError := Canonicalize(kind, value)
	if canonicalError != nil {
		return Rule{}, canonicalError
	}
	if kind == KindCountry {
		if _, lookupError := geolocator.CountryCode(ctx, clientIP.Unmap()); errors.Is(lookupError, geo.ErrGeolocationUnavailable) {
			return Rule{}, ErrGeolocationUnavailable
		}
	}
	var addedRule Rule
	transactionError := repository.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		currentRules, lockError := lockAndList(ctx, transaction, accountID)
		if lockError != nil {
			return lockError
		}
		for _, existingRule := range currentRules {
			if existingRule.Kind == kind && existingRule.Value == canonicalValue {
				return ErrRuleExists
			}
		}
		resultingRules := append(currentRules, Rule{Kind: kind, Value: canonicalValue})
		if !Allows(ctx, resultingRules, clientIP, geolocator) {
			return ErrWouldLockOut
		}
		addedRule = Rule{Kind: kind, Value: canonicalValue}
		return transaction.NewRaw(
			`INSERT INTO access_rule (access_rule_account_id, access_rule_kind, access_rule_value)
			 VALUES (?, ?, ?) RETURNING access_rule_id`,
			accountID, kind, canonicalValue).Scan(ctx, &addedRule.ID)
	})
	return addedRule, transactionError
}

func (repository *Repository) Delete(ctx context.Context, accountID, ruleID int64, clientIP netip.Addr, geolocator geo.Geolocator) error {
	return repository.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		currentRules, lockError := lockAndList(ctx, transaction, accountID)
		if lockError != nil {
			return lockError
		}
		remainingRules := make([]Rule, 0, len(currentRules))
		isFound := false
		for _, existingRule := range currentRules {
			if existingRule.ID == ruleID {
				isFound = true
				continue
			}
			remainingRules = append(remainingRules, existingRule)
		}
		if !isFound {
			return ErrRuleNotFound
		}
		if !Allows(ctx, remainingRules, clientIP, geolocator) {
			return ErrWouldLockOut
		}
		_, deleteError := transaction.ExecContext(ctx,
			`DELETE FROM access_rule WHERE access_rule_id = ? AND access_rule_account_id = ?`, ruleID, accountID)
		return deleteError
	})
}

func lockAndList(ctx context.Context, transaction bun.Tx, accountID int64) ([]Rule, error) {
	var lockedAccountID int64
	if lockError := transaction.NewRaw(
		`SELECT account_id FROM account WHERE account_id = ? FOR UPDATE`, accountID).Scan(ctx, &lockedAccountID); lockError != nil {
		return nil, lockError
	}
	return listRules(ctx, transaction, accountID)
}

func listRules(ctx context.Context, queryer bun.IDB, accountID int64) ([]Rule, error) {
	rows, queryError := queryer.QueryContext(ctx,
		`SELECT access_rule_id, access_rule_kind, access_rule_value FROM access_rule
		 WHERE access_rule_account_id = ? ORDER BY access_rule_id`, accountID)
	if queryError != nil {
		return nil, queryError
	}
	defer rows.Close()
	rules := []Rule{}
	for rows.Next() {
		var rule Rule
		if scanError := rows.Scan(&rule.ID, &rule.Kind, &rule.Value); scanError != nil {
			return nil, scanError
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}
