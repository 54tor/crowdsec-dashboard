package confread

import (
	"strings"
	"testing"
	"time"
)

func TestRedactSecretsTable(testContext *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{"plain password", "password: hunter2", "password: [REDACTED]"},
		{"upper case key", "PASSWORD: hunter2", "PASSWORD: [REDACTED]"},
		{"space before colon", "password : hunter2", "password : [REDACTED]"},
		{"double quoted key", `"password": "hunter2"`, `"password": [REDACTED]`},
		{"single quoted key", "'api_key': abc", "'api_key': [REDACTED]"},
		{"passwd", "passwd: x", "passwd: [REDACTED]"},
		{"apikey", "apikey: x", "apikey: [REDACTED]"},
		{"credential", "credential: x", "credential: [REDACTED]"},
		{"dsn", "db_dsn: postgres://user:pw@db/app", "db_dsn: [REDACTED]"},
		{"authorization header", "Authorization: Bearer xyz", "Authorization: [REDACTED]"},
		{"bearer in a value", `headers: "X-Auth: Bearer abc.def"`, `headers: "X-Auth: Bearer [REDACTED]"`},
		{"url credentials", "url: https://user:pass@example.com/path", "url: https://[REDACTED]@example.com/path"},
		{"url without credentials", "url: https://example.com:8080/path", "url: https://example.com:8080/path"},
		{"literal block", "secret_notes: |\n  line1\n  line2\nnext: ok", "secret_notes: [REDACTED]\nnext: ok"},
		{"folded block", "private_key: >-\n  AAA\n  BBB\nafter: 1", "private_key: [REDACTED]\nafter: 1"},
		{"indented sequence", "tokens:\n  - a\n  - b\nother: 1", "tokens: [REDACTED]\nother: 1"},
		{"sequence at key indent", "token:\n- a\n- b\nother: 1", "token: [REDACTED]\nother: 1"},
		{"nested mapping after empty key", "credentials:\n  user: bob\n  pass: x\nother: 1", "credentials: [REDACTED]\nother: 1"},
		{"inline mapping", "auth: {password: x, user: bob}", "auth: {password: [REDACTED], user: bob}"},
		{"inline quoted entry", `auth: {user: bob, "token": "t"}`, `auth: {user: bob, "token": [REDACTED]}`},
		{"untouched line", "listen_uri: 127.0.0.1:8080", "listen_uri: 127.0.0.1:8080"},
		{"block with comment", "password: | # c\n  s1\nnext: ok", "password: [REDACTED]\nnext: ok"},
		{"binary tag block", "password: !!binary |\n  s1\nnext: ok", "password: [REDACTED]\nnext: ok"},
		{"anchor block", "password: &a |\n  s1\nnext: ok", "password: [REDACTED]\nnext: ok"},
		{"plain multi-line", "password: part1\n  part2\nnext: ok", "password: [REDACTED]\nnext: ok"},
		{"quoted multi-line", "password: \"abc\n  def\"\nnext: ok", "password: [REDACTED]\nnext: ok"},
		{"at sign inside the password", "url: https://u:p@ss@h/x", "url: https://[REDACTED]@h/x"},
		{"bare token userinfo", "url: https://ghp_tok@github.com/org/repo", "url: https://[REDACTED]@github.com/org/repo"},
		{"sibling after block is kept", "password: x\n  more\nsibling: keep\n  child: keep", "password: [REDACTED]\nsibling: keep\n  child: keep"},
		{"sequence item key", "  - token: listed", "  - token: [REDACTED]"},
	}

	for _, testCase := range testCases {
		testContext.Run(testCase.name, func(subTest *testing.T) {
			obtained := string(redactSecrets([]byte(testCase.input)))
			if obtained != testCase.expected {
				subTest.Errorf("expected %q, got %q", testCase.expected, obtained)
			}
		})
	}
}

func TestRedactSecretsHandlesMaximumSizeInputQuickly(testContext *testing.T) {
	repeatedBlock := "password: |\n  secret line\nkey: value\nplain: https://user:pass@example.com/path\n"
	largeInput := []byte(strings.Repeat(repeatedBlock, maxFileBytes/len(repeatedBlock)))
	startTime := time.Now()

	redactSecrets(largeInput)

	if elapsed := time.Since(startTime); elapsed > time.Second {
		testContext.Errorf("redaction took %v", elapsed)
	}
}
