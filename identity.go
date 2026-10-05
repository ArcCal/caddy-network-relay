package networkrelay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// Identity is a client identity for profiles that authenticate a device
// with a certificate instead of a password (PayloadCertificateUUID): a key
// pair and a self-signed certificate in a password-protected PKCS#12 file.
//
// The relay needs no CA: the configuration pins each user's certificate by
// its SHA-256 fingerprint, and the TLS handshake proves that the device
// holds the key. Once installed, the key lives in the device's keychain and
// cannot be copied off it the way a password in a profile can.
type Identity struct {
	// P12 holds the key and the certificate, encrypted with Password.
	P12      []byte
	Password string
	// Fingerprint is the SHA-256 of the DER certificate, for the
	// user's certificate option, in hex.
	Fingerprint string
}

// GenerateIdentity makes an ECDSA P-256 key and a self-signed client
// certificate for user, valid for days days from now.
func GenerateIdentity(user string, days int) (*Identity, error) {
	if err := validateUserName(user); err != nil {
		return nil, err
	}
	if days < 1 || days > 3650 {
		return nil, errors.New("the certificate must be valid for 1 to 3650 days")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: user, Organization: []string{"network-relay"}},
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.AddDate(0, 0, days),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	password := RandomPassword()
	// The legacy encryption (3DES, SHA-1 MAC) is what every Apple OS
	// version imports; the password, not the cipher, protects the file.
	p12, err := pkcs12.LegacyDES.Encode(key, cert, nil, password)
	if err != nil {
		return nil, fmt.Errorf("encoding the PKCS#12 file: %w", err)
	}
	fp := sha256.Sum256(der)
	return &Identity{P12: p12, Password: password, Fingerprint: hex.EncodeToString(fp[:])}, nil
}
