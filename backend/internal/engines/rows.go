package engines

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

const engineColumns = `engine_id, engine_name, engine_is_local, engine_lapi_url, engine_machine_id,
	engine_machine_password_sealed, engine_machine_password_key_id,
	engine_proxy_kind, engine_proxy_url, engine_proxy_credential_sealed, engine_proxy_credential_key_id,
	engine_allow_insecure_http, engine_public_address_list, engine_enabled, engine_sync_enabled,
	engine_collection_cursor, engine_last_collected_at, engine_last_collection_error, engine_history_incomplete`

type engineRow struct {
	ID                   int64      `bun:"engine_id"`
	Name                 string     `bun:"engine_name"`
	IsLocal              bool       `bun:"engine_is_local"`
	LAPIURL              string     `bun:"engine_lapi_url"`
	MachineID            string     `bun:"engine_machine_id"`
	PasswordSealed       []byte     `bun:"engine_machine_password_sealed"`
	PasswordKeyID        *string    `bun:"engine_machine_password_key_id"`
	ProxyKind            *string    `bun:"engine_proxy_kind"`
	ProxyURL             *string    `bun:"engine_proxy_url"`
	ProxyCredentialBytes []byte     `bun:"engine_proxy_credential_sealed"`
	ProxyCredentialKeyID *string    `bun:"engine_proxy_credential_key_id"`
	AllowInsecureHTTP    bool       `bun:"engine_allow_insecure_http"`
	PublicAddressJSON    []byte     `bun:"engine_public_address_list"`
	Enabled              bool       `bun:"engine_enabled"`
	SyncEnabled          bool       `bun:"engine_sync_enabled"`
	CollectionCursor     int64      `bun:"engine_collection_cursor"`
	LastCollectedAt      *time.Time `bun:"engine_last_collected_at"`
	LastCollectionError  *string    `bun:"engine_last_collection_error"`
	HistoryIncomplete    bool       `bun:"engine_history_incomplete"`
}

func (row engineRow) hasProxyCredentials() bool {
	return len(row.ProxyCredentialBytes) > 0
}

func (row engineRow) storedProxyCredential() sealedValue {
	return sealedValue{ciphertext: row.ProxyCredentialBytes, keyID: *row.ProxyCredentialKeyID}
}

func (row engineRow) toEngine() (Engine, error) {
	var rawAddresses []string
	if unmarshalError := json.Unmarshal(row.PublicAddressJSON, &rawAddresses); unmarshalError != nil {
		return Engine{}, fmt.Errorf("decode public addresses: %w", unmarshalError)
	}
	publicAddresses := make([]netip.Addr, 0, len(rawAddresses))
	for _, rawAddress := range rawAddresses {
		address, parseError := netip.ParseAddr(rawAddress)
		if parseError != nil {
			return Engine{}, fmt.Errorf("decode public address: %w", parseError)
		}
		publicAddresses = append(publicAddresses, address)
	}
	convertedEngine := Engine{
		ID: row.ID, Name: row.Name, IsLocal: row.IsLocal, LAPIURL: row.LAPIURL, MachineID: row.MachineID,
		AllowInsecureHTTP: row.AllowInsecureHTTP, PublicAddresses: publicAddresses,
		Enabled: row.Enabled, SyncEnabled: row.SyncEnabled, CollectionCursor: row.CollectionCursor,
		LastCollectedAt: row.LastCollectedAt, HistoryIncomplete: row.HistoryIncomplete,
	}
	if row.LastCollectionError != nil {
		convertedEngine.LastCollectionError = *row.LastCollectionError
	}
	if row.ProxyKind != nil && row.ProxyURL != nil {
		convertedEngine.Proxy = &Proxy{Kind: *row.ProxyKind, URL: *row.ProxyURL, HasCredentials: row.hasProxyCredentials()}
	}
	return convertedEngine, nil
}
