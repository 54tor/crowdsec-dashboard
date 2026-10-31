package confread

import "regexp"

var secretLinePattern = regexp.MustCompile(`(?im)^([ \t]*(?:-[ \t]+)?[^\n:#]*(?:password|token|secret|api_key|key)[^\n:#]*:[ \t]*)[^ \t\n#].*$`)

func redactSecrets(content []byte) []byte {
	return secretLinePattern.ReplaceAll(content, []byte("${1}[REDACTED]"))
}
