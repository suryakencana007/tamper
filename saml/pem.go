package saml

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseCertPEM decodes a PEM-encoded X.509 certificate — the SP
// signing cert the crewjam/saml ServiceProvider needs at
// construction time.
func ParseCertPEM(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE PEM block, got %q", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// ParsePrivateKeyPEM decodes a PEM-encoded RSA or ECDSA private key.
// Accepts PKCS#1, "EC PRIVATE KEY", and PKCS#8 ("PRIVATE KEY")
// encodings to match the variety of operator toolchains.
func ParsePrivateKeyPEM(pemStr string) (any, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}
