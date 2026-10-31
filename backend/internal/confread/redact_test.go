package confread

import "testing"

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
		{"literal block", "secret_notes: |\n  line1\n  line2\nnext: ok", "secret_notes: |\n  [REDACTED]\nnext: ok"},
		{"folded block", "private_key: >-\n  AAA\n  BBB\nafter: 1", "private_key: >-\n  [REDACTED]\nafter: 1"},
		{"indented sequence", "tokens:\n  - a\n  - b\nother: 1", "tokens:\n  [REDACTED]\nother: 1"},
		{"sequence at key indent", "token:\n- a\n- b\nother: 1", "token:\n  [REDACTED]\nother: 1"},
		{"nested mapping after empty key", "credentials:\n  user: bob\n  pass: x\nother: 1", "credentials:\n  [REDACTED]\nother: 1"},
		{"inline mapping", "auth: {password: x, user: bob}", "auth: {password: [REDACTED], user: bob}"},
		{"inline quoted entry", `auth: {user: bob, "token": "t"}`, `auth: {user: bob, "token": [REDACTED]}`},
		{"untouched line", "listen_uri: 127.0.0.1:8080", "listen_uri: 127.0.0.1:8080"},
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
