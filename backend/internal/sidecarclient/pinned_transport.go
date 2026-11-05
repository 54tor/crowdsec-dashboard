package sidecarclient

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
)

func pinnedTLSConfig(pinnedDigest []byte) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyConnection: func(connectionState tls.ConnectionState) error {
			peerDigest, hasLeaf := leafSPKIDigest(connectionState)
			isPinnedPeer := hasLeaf && subtle.ConstantTimeCompare(peerDigest, pinnedDigest) == 1
			if !isPinnedPeer {
				return ErrFingerprintMismatch
			}
			return nil
		},
	}
}

func leafSPKIDigest(connectionState tls.ConnectionState) ([]byte, bool) {
	if len(connectionState.PeerCertificates) == 0 {
		return nil, false
	}
	digest := sha256.Sum256(connectionState.PeerCertificates[0].RawSubjectPublicKeyInfo)
	return digest[:], true
}
