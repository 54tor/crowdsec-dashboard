package secrets

type EncryptedColumn struct {
	Table                string
	IDColumn             string
	CiphertextColumn     string
	KeyIDColumn          string
	Filter               string
	AssociatedDataLabel  string
	AssociatedDataColumn string
}

var EncryptedColumns = []EncryptedColumn{
	{
		Table:                "credential",
		IDColumn:             "credential_id",
		CiphertextColumn:     "credential_secret_ciphertext",
		KeyIDColumn:          "credential_key_id",
		Filter:               "credential_kind = 'totp'",
		AssociatedDataLabel:  "totp",
		AssociatedDataColumn: "credential_account_id",
	},
	{
		Table:                "engine",
		IDColumn:             "engine_id",
		CiphertextColumn:     "engine_machine_password_sealed",
		KeyIDColumn:          "engine_machine_password_key_id",
		AssociatedDataLabel:  "engine.machine_password",
		AssociatedDataColumn: "engine_id",
	},
	{
		Table:                "engine",
		IDColumn:             "engine_id",
		CiphertextColumn:     "engine_proxy_credential_sealed",
		KeyIDColumn:          "engine_proxy_credential_key_id",
		AssociatedDataLabel:  "engine.proxy_credential",
		AssociatedDataColumn: "engine_id",
	},
}

func (column EncryptedColumn) Name() string {
	return column.Table + "." + column.CiphertextColumn
}

func (column EncryptedColumn) associatedData(row sealedRow) []byte {
	return []byte(column.AssociatedDataLabel + ":" + row.AssociatedValue)
}

func (column EncryptedColumn) filterClause() string {
	if column.Filter == "" {
		return "TRUE"
	}
	return column.Filter
}
