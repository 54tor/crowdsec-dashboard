package engines

import (
	"fmt"
	"io"
	"log/slog"
)

const redactedCredentials = "engines.Credentials{redacted}"

func (Credentials) String() string {
	return redactedCredentials
}

func (Credentials) GoString() string {
	return redactedCredentials
}

func (Credentials) Format(formatState fmt.State, _ rune) {
	_, _ = io.WriteString(formatState, redactedCredentials)
}

func (Credentials) LogValue() slog.Value {
	return slog.StringValue(redactedCredentials)
}
