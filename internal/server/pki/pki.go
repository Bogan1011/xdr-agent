// Package pki runs the server's private CA: it issues the server certificate
// and signs agent client certificates at enrollment.
package pki

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
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	caValidity     = 10 * 365 * 24 * time.Hour
	serverValidity = 2 * 365 * 24 * time.Hour
	AgentValidity  = 365 * 24 * time.Hour
)

type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     *ecdsa.PrivateKey
}

// LoadOrCreate reads ca.crt/ca.key from dir, creating them on first start.
func LoadOrCreate(dir string) (*CA, error) {
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	certPEM, err := os.ReadFile(certPath)
	if errors.Is(err, os.ErrNotExist) {
		return create(dir, certPath, keyPath)
	}
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("%s: no PEM block", keyPath)
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key}, nil
}

func create(dir, certPath, keyPath string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "XDR Agent CA", Organization: []string{"XDR"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key}, nil
}

// Fingerprint is the SHA-256 of the CA certificate, used by the installer to
// pin the CA it downloads.
func (ca *CA) Fingerprint() string {
	sum := sha256.Sum256(ca.Cert.Raw)
	return hex.EncodeToString(sum[:])
}

func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// ServerCert issues a fresh server certificate for the given DNS names and IPs.
func (ca *CA) ServerCert(names []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "xdr-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(serverValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if n != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Cert.Raw}, PrivateKey: key}, nil
}

// SignAgent signs an agent CSR. The subject is replaced so the certificate's
// common name is always the server-assigned agent id.
func (ca *CA) SignAgent(csrPEM []byte, agentID string) ([]byte, *x509.Certificate, error) {
	b, _ := pem.Decode(csrPEM)
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("csr is not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("csr signature: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: agentID, OrganizationalUnit: []string{"agent"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(AgentValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, nil
}

func parseCert(p []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(p)
	if b == nil {
		return nil, errors.New("no PEM certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}
