package secondfactor

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func (repository *Repository) BeginWebAuthnLogin(ctx context.Context, relyingParty *WebAuthn, accountID int64) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	if relyingParty == nil {
		return nil, nil, ErrWebAuthnFailed
	}
	user, loadError := repository.loadWebAuthnUser(ctx, accountID)
	if loadError != nil {
		return nil, nil, loadError
	}
	assertion, session, beginError := relyingParty.relyingParty.BeginLogin(user)
	if beginError != nil {
		return nil, nil, fmt.Errorf("begin webauthn login: %w", beginError)
	}
	return assertion, session, nil
}

func (repository *Repository) FinishWebAuthnLogin(ctx context.Context, relyingParty *WebAuthn, accountID int64, session webauthn.SessionData, responseBody []byte) error {
	if relyingParty == nil {
		return ErrWebAuthnFailed
	}
	user, loadError := repository.loadWebAuthnUser(ctx, accountID)
	if loadError != nil {
		return loadError
	}
	credential, validateError := relyingParty.validateLogin(user, session, responseBody)
	if validateError != nil {
		return validateError
	}
	return repository.recordWebAuthnUse(ctx, accountID, *credential)
}

func (repository *Repository) loadWebAuthnUser(ctx context.Context, accountID int64) (webAuthnUser, error) {
	var account struct {
		Name       string `bun:"account_name"`
		UserHandle []byte `bun:"account_webauthn_user_handle"`
	}
	accountError := repository.database.NewRaw(
		`SELECT account_name, account_webauthn_user_handle FROM account WHERE account_id = ?`, accountID).Scan(ctx, &account)
	if errors.Is(accountError, sql.ErrNoRows) {
		return webAuthnUser{}, ErrWebAuthnFailed
	}
	if accountError != nil {
		return webAuthnUser{}, fmt.Errorf("load webauthn user: %w", accountError)
	}
	var storedCredentials [][]byte
	credentialsError := repository.database.NewRaw(
		`SELECT credential_webauthn_data FROM credential
		 WHERE credential_account_id = ? AND credential_kind = ? ORDER BY credential_id`, accountID, webauthnKind).Scan(ctx, &storedCredentials)
	if credentialsError != nil && !errors.Is(credentialsError, sql.ErrNoRows) {
		return webAuthnUser{}, fmt.Errorf("load webauthn credentials: %w", credentialsError)
	}
	if len(account.UserHandle) == 0 || len(storedCredentials) == 0 {
		return webAuthnUser{}, ErrWebAuthnFailed
	}
	user := webAuthnUser{handle: account.UserHandle, name: account.Name}
	for _, storedCredential := range storedCredentials {
		var credential webauthn.Credential
		if decodeError := json.Unmarshal(storedCredential, &credential); decodeError != nil {
			return webAuthnUser{}, fmt.Errorf("decode webauthn credential: %w", decodeError)
		}
		user.credentials = append(user.credentials, credential)
	}
	return user, nil
}

func (repository *Repository) recordWebAuthnUse(ctx context.Context, accountID int64, credential webauthn.Credential) error {
	credentialData, marshalError := json.Marshal(credential)
	if marshalError != nil {
		return fmt.Errorf("encode webauthn credential: %w", marshalError)
	}
	updateResult, updateError := repository.database.ExecContext(ctx,
		`UPDATE credential SET credential_webauthn_data = ?::jsonb, credential_last_used_at = now()
		 WHERE credential_account_id = ? AND credential_kind = ? AND credential_webauthn_id = ?
		   AND (?::bigint = 0 OR COALESCE((credential_webauthn_data->'authenticator'->>'signCount')::bigint, 0) < ?::bigint)`,
		string(credentialData), accountID, webauthnKind, credential.ID, credential.Authenticator.SignCount, credential.Authenticator.SignCount)
	if updateError != nil {
		return fmt.Errorf("record webauthn use: %w", updateError)
	}
	affectedRows, rowsError := updateResult.RowsAffected()
	if rowsError != nil {
		return fmt.Errorf("count affected rows: %w", rowsError)
	}
	if affectedRows == 0 {
		return webAuthnFailure(errors.New("signature counter did not increase"))
	}
	return nil
}
