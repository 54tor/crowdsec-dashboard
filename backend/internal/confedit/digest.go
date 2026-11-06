package confedit

import "crowdsec-dashboard/internal/digest"

const AbsentDigest = "absent"

type Digester = digest.Digester

func NewDigester(key []byte) Digester {
	return digest.NewDigester(key)
}
