package sidecarserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"time"
)

const (
	certificateFileName      = "tls.crt"
	privateKeyFileName       = "tls.key"
	certificateFileMode      = 0o644
	privateKeyFileMode       = 0o600
	certificateValidity      = 10 * 365 * 24 * time.Hour
	certificateCommonName    = "crowdsec-dashboard-sidecar"
	serialNumberBitLength    = 128
	groupOrOtherWritableBits = 0o022
	groupOrOtherAccessBits   = 0o077
)

var errInsecureDataDir = errors.New("sidecar data directory is writable by group or others")
var errInsecurePrivateKey = errors.New("sidecar private key file is accessible by group or others")
var errUnexpectedKeyType = errors.New("sidecar certificate key is not ECDSA P-256")

func LoadOrCreateCertificate(dataDir string, now func() time.Time) (tls.Certificate, string, error) {
	dataRoot, openError := openDataRoot(dataDir)
	if openError != nil {
		return tls.Certificate{}, "", openError
	}
	defer dataRoot.Close()

	bothFilesExist, existError := certificateFilesExist(dataRoot)
	if existError != nil {
		return tls.Certificate{}, "", existError
	}
	if !bothFilesExist {
		if createError := createCertificateFiles(dataRoot, now()); createError != nil {
			return tls.Certificate{}, "", createError
		}
	}
	certificate, loadError := loadCertificateFiles(dataRoot)
	if loadError != nil {
		return tls.Certificate{}, "", loadError
	}
	return certificate, SPKIFingerprint(certificate.Leaf), nil
}

func SPKIFingerprint(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(digest[:])
}

func openDataRoot(dataDir string) (*os.Root, error) {
	dataDirInfo, statError := os.Stat(dataDir)
	if statError != nil {
		return nil, fmt.Errorf("sidecar data directory: %w", statError)
	}
	if !dataDirInfo.IsDir() {
		return nil, fmt.Errorf("sidecar data directory %q is not a directory", dataDir)
	}
	if dataDirInfo.Mode().Perm()&groupOrOtherWritableBits != 0 {
		return nil, errInsecureDataDir
	}
	dataRoot, openError := os.OpenRoot(dataDir)
	if openError != nil {
		return nil, fmt.Errorf("sidecar data directory: %w", openError)
	}
	return dataRoot, nil
}

func certificateFilesExist(dataRoot *os.Root) (bool, error) {
	for _, fileName := range []string{certificateFileName, privateKeyFileName} {
		_, statError := dataRoot.Lstat(fileName)
		if errors.Is(statError, fs.ErrNotExist) {
			return false, nil
		}
		if statError != nil {
			return false, fmt.Errorf("sidecar certificate files: %w", statError)
		}
	}
	return true, nil
}

func loadCertificateFiles(dataRoot *os.Root) (tls.Certificate, error) {
	keyInfo, statError := dataRoot.Lstat(privateKeyFileName)
	if statError != nil {
		return tls.Certificate{}, fmt.Errorf("sidecar private key: %w", statError)
	}
	if !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm()&groupOrOtherAccessBits != 0 {
		return tls.Certificate{}, errInsecurePrivateKey
	}
	certificatePEM, certificateReadError := dataRoot.ReadFile(certificateFileName)
	if certificateReadError != nil {
		return tls.Certificate{}, fmt.Errorf("sidecar certificate: %w", certificateReadError)
	}
	privateKeyPEM, keyReadError := dataRoot.ReadFile(privateKeyFileName)
	if keyReadError != nil {
		return tls.Certificate{}, fmt.Errorf("sidecar private key: %w", keyReadError)
	}
	certificate, pairError := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if pairError != nil {
		return tls.Certificate{}, errors.New("sidecar certificate and private key do not form a valid pair")
	}
	publicKey, isECDSA := certificate.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !isECDSA || publicKey.Curve != elliptic.P256() {
		return tls.Certificate{}, errUnexpectedKeyType
	}
	return certificate, nil
}

func createCertificateFiles(dataRoot *os.Root, issuedAt time.Time) error {
	privateKey, generateError := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if generateError != nil {
		return fmt.Errorf("sidecar private key: %w", generateError)
	}
	certificateDER, certificateError := selfSignedCertificate(privateKey, issuedAt)
	if certificateError != nil {
		return certificateError
	}
	privateKeyDER, marshalError := x509.MarshalPKCS8PrivateKey(privateKey)
	if marshalError != nil {
		return fmt.Errorf("sidecar private key: %w", marshalError)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	if writeError := writeFileAtomically(dataRoot, privateKeyFileName, privateKeyPEM, privateKeyFileMode); writeError != nil {
		return writeError
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	return writeFileAtomically(dataRoot, certificateFileName, certificatePEM, certificateFileMode)
}

func selfSignedCertificate(privateKey *ecdsa.PrivateKey, issuedAt time.Time) ([]byte, error) {
	serialNumber, serialError := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialNumberBitLength))
	if serialError != nil {
		return nil, fmt.Errorf("sidecar certificate serial: %w", serialError)
	}
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: certificateCommonName},
		NotBefore:             issuedAt,
		NotAfter:              issuedAt.Add(certificateValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certificateDER, createError := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if createError != nil {
		return nil, fmt.Errorf("sidecar certificate: %w", createError)
	}
	return certificateDER, nil
}
