package secrets

type EncryptedColumn struct {
	Table                 string
	IDColumn              string
	CiphertextColumn      string
	KeyIDColumn           string
	Filter                string
	AssociatedDataColumns []string
	AssociatedData        func(values []string) []byte
	LegacyAssociatedData  func(values []string) []byte
}

const deletingEngineFilter = "engine_deleting_at IS NULL"

var EncryptedColumns = []EncryptedColumn{
	{
		Table:                 "credential",
		IDColumn:              "credential_id",
		CiphertextColumn:      "credential_secret_ciphertext",
		KeyIDColumn:           "credential_key_id",
		Filter:                "credential_kind = 'totp'",
		AssociatedDataColumns: []string{"credential_account_id"},
		AssociatedData:        labelledAssociatedData("totp"),
	},
	{
		Table:                 "engine",
		IDColumn:              "engine_id",
		CiphertextColumn:      "engine_machine_password_sealed",
		KeyIDColumn:           "engine_machine_password_key_id",
		Filter:                deletingEngineFilter,
		AssociatedDataColumns: []string{"engine_id", "engine_lapi_url"},
		AssociatedData: func(values []string) []byte {
			return engineMachinePasswordAssociatedData(values[0], values[1])
		},
		LegacyAssociatedData: labelledAssociatedData(machinePasswordLabel),
	},
	{
		Table:                 "engine",
		IDColumn:              "engine_id",
		CiphertextColumn:      "engine_proxy_credential_sealed",
		KeyIDColumn:           "engine_proxy_credential_key_id",
		Filter:                deletingEngineFilter,
		AssociatedDataColumns: []string{"engine_id", "engine_lapi_url", "engine_proxy_kind", "engine_proxy_url"},
		AssociatedData: func(values []string) []byte {
			return engineProxyCredentialAssociatedData(values[0], values[1], values[2], values[3])
		},
		LegacyAssociatedData: labelledAssociatedData(proxyCredentialLabel),
	},
	sidecarKeyColumn("engine_sidecar_signing_key_sealed", "engine_sidecar_signing_key_key_id", "engine_sidecar_signing_key_kid"),
	sidecarKeyColumn("engine_sidecar_next_signing_key_sealed", "engine_sidecar_next_signing_key_key_id", "engine_sidecar_next_signing_key_kid"),
}

func sidecarKeyColumn(ciphertextColumn, keyIDColumn, signingKeyIDColumn string) EncryptedColumn {
	return EncryptedColumn{
		Table:                 "engine",
		IDColumn:              "engine_id",
		CiphertextColumn:      ciphertextColumn,
		KeyIDColumn:           keyIDColumn,
		Filter:                deletingEngineFilter,
		AssociatedDataColumns: []string{"engine_id", "engine_sidecar_url", signingKeyIDColumn},
		AssociatedData: func(values []string) []byte {
			return engineSidecarKeyAssociatedData(values[0], values[1], values[2])
		},
	}
}

func labelledAssociatedData(label string) func(values []string) []byte {
	return func(values []string) []byte {
		return []byte(label + ":" + values[0])
	}
}

func (column EncryptedColumn) Name() string {
	return column.Table + "." + column.CiphertextColumn
}

func (column EncryptedColumn) filterClause() string {
	if column.Filter == "" {
		return "TRUE"
	}
	return column.Filter
}
