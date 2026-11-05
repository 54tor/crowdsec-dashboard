package sidecarclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type certificateChain struct {
	leafDER         []byte
	intermediateDER []byte
	leafKey         *ecdsa.PrivateKey
}

func newCertificateChain(testContext *testing.T) certificateChain {
	testContext.Helper()
	rootKey := mustGenerateKey(testContext)
	rootTemplate := certificateTemplate(1, "root", true)
	rootDER := mustSign(testContext, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCertificate, parseError := x509.ParseCertificate(rootDER)
	if parseError != nil {
		testContext.Fatalf("parse root: %v", parseError)
	}
	intermediateKey := mustGenerateKey(testContext)
	intermediateTemplate := certificateTemplate(2, "intermediate", true)
	intermediateDER := mustSign(testContext, intermediateTemplate, rootCertificate, &intermediateKey.PublicKey, rootKey)
	intermediateCertificate, parseError := x509.ParseCertificate(intermediateDER)
	if parseError != nil {
		testContext.Fatalf("parse intermediate: %v", parseError)
	}
	leafKey := mustGenerateKey(testContext)
	leafTemplate := certificateTemplate(3, "leaf", false)
	leafDER := mustSign(testContext, leafTemplate, intermediateCertificate, &leafKey.PublicKey, intermediateKey)
	return certificateChain{leafDER: leafDER, intermediateDER: intermediateDER, leafKey: leafKey}
}

func mustGenerateKey(testContext *testing.T) *ecdsa.PrivateKey {
	testContext.Helper()
	key, generateError := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if generateError != nil {
		testContext.Fatalf("generate key: %v", generateError)
	}
	return key
}

func certificateTemplate(serialNumber int64, commonName string, isCertificateAuthority bool) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serialNumber),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCertificateAuthority,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
}

func mustSign(testContext *testing.T, template, parent *x509.Certificate, subjectKey *ecdsa.PublicKey, signingKey *ecdsa.PrivateKey) []byte {
	testContext.Helper()
	certificateDER, createError := x509.CreateCertificate(rand.Reader, template, parent, subjectKey, signingKey)
	if createError != nil {
		testContext.Fatalf("create certificate: %v", createError)
	}
	return certificateDER
}

func spkiDigestOfCertificate(testContext *testing.T, certificateDER []byte) []byte {
	testContext.Helper()
	certificate, parseError := x509.ParseCertificate(certificateDER)
	if parseError != nil {
		testContext.Fatalf("parse certificate: %v", parseError)
	}
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return digest[:]
}

func TestPinMatchesOnlyTheLeafOfAPresentedChain(testContext *testing.T) {
	chain := newCertificateChain(testContext)
	server := httptest.NewUnstartedServer(http.NotFoundHandler())
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{chain.leafDER, chain.intermediateDER},
			PrivateKey:  chain.leafKey,
		}},
	}
	server.StartTLS()
	testContext.Cleanup(server.Close)
	pinCases := []struct {
		caseName      string
		pinnedDigest  []byte
		expectedError error
	}{
		{"pin on the intermediate", spkiDigestOfCertificate(testContext, chain.intermediateDER), ErrFingerprintMismatch},
		{"pin on the leaf", spkiDigestOfCertificate(testContext, chain.leafDER), nil},
	}
	for _, pinCase := range pinCases {
		testContext.Run(pinCase.caseName, func(subtestContext *testing.T) {
			transport := &http.Transport{TLSClientConfig: pinnedTLSConfig(pinCase.pinnedDigest), DisableKeepAlives: true}
			defer transport.CloseIdleConnections()

			response, getError := (&http.Client{Transport: transport}).Get(server.URL)

			if response != nil {
				_ = response.Body.Close()
			}
			if pinCase.expectedError == nil && getError != nil {
				subtestContext.Errorf("expected success, got %v", getError)
			}
			if pinCase.expectedError != nil && !errors.Is(getError, pinCase.expectedError) {
				subtestContext.Errorf("expected %v, got %v", pinCase.expectedError, getError)
			}
		})
	}
}
