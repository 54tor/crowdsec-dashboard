package logtail

import "testing"

func TestMaskLine_masqueLesValeursSensibles(t *testing.T) {
	casDeTest := []struct {
		nom            string
		ligneEntree    string
		valeurAttendue string
	}{
		{"authorization", `GET / Authorization: Basic abc123 ok`, `GET / Authorization: [REDACTED]`},
		{"bearer", `curl -H "Bearer eyJhbGciOi.x.y" done`, `curl -H "Bearer [REDACTED]" done`},
		{"password", `login password=hunter2 user=bob`, `login password=[REDACTED] user=bob`},
		{"token", `GET /?token=abcdef&x=1 HTTP/1.1`, `GET /?token=[REDACTED]&x=1 HTTP/1.1`},
		{"api_key", `api_key=SECRET123 end`, `api_key=[REDACTED] end`},
		{"apikey", `apikey: SECRET123`, `apikey: [REDACTED]`},
		{"cookie", `Cookie: session=abc; other=def`, `Cookie: [REDACTED]`},
		{"set-cookie", `Set-Cookie: session=abc; Path=/`, `Set-Cookie: [REDACTED]`},
		{"json", `{"password":"hunter2","user":"bob"}`, `{"password":"[REDACTED]","user":"bob"}`},
		{"cle avec tiret", `api-key=abc123 end`, `api-key=[REDACTED] end`},
		{"access key", `access_key: abc123`, `access_key: [REDACTED]`},
		{"identifiants dans une url", `proxy https://bob:pw@host.example/path`, `proxy https://[REDACTED]@host.example/path`},
		{"ligne sans secret", `203.0.113.7 - - "GET /index.html"`, `203.0.113.7 - - "GET /index.html"`},
	}
	for _, casDeTestCourant := range casDeTest {
		t.Run(casDeTestCourant.nom, func(t *testing.T) {
			valeurObtenue := MaskLine(casDeTestCourant.ligneEntree)
			if valeurObtenue != casDeTestCourant.valeurAttendue {
				t.Fatalf("got %q, want %q", valeurObtenue, casDeTestCourant.valeurAttendue)
			}
		})
	}
}
