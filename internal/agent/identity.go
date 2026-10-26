package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

// Identity is the agent's enrolled client certificate.
type Identity struct {
	AgentID string
	Cert    tls.Certificate
	CAPool  *x509.CertPool
}

func (c *Config) path(name string) string { return filepath.Join(c.StateDir, name) }

func (c *Config) caPool() (*x509.CertPool, error) {
	raw, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("%s holds no PEM certificates", c.CAFile)
	}
	return pool, nil
}

// LoadOrEnroll returns the stored identity, enrolling first if there is none.
func LoadOrEnroll(ctx context.Context, c *Config, host *xdrv1.HostInfo) (*Identity, error) {
	pool, err := c.caPool()
	if err != nil {
		return nil, err
	}
	id, err := os.ReadFile(c.path("agent_id"))
	if err == nil {
		cert, err := tls.LoadX509KeyPair(c.path("agent.crt"), c.path("agent.key"))
		if err != nil {
			return nil, fmt.Errorf("load agent certificate: %w", err)
		}
		return &Identity{AgentID: string(id), Cert: cert, CAPool: pool}, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if c.EnrollmentToken == "" {
		return nil, errors.New("agent is not enrolled and no enrollment_token is configured")
	}
	return enroll(ctx, c, pool, host)
}

func enroll(ctx context.Context, c *Config, pool *x509.CertPool, host *xdrv1.HostInfo) (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: host.Hostname},
	}, key)
	if err != nil {
		return nil, err
	}

	creds := credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: c.ServerName, MinVersion: tls.VersionTLS13})
	conn, err := grpc.NewClient(c.EnrollServer, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := xdrv1.NewEnrollmentServiceClient(conn).Enroll(ctx, &xdrv1.EnrollRequest{
		EnrollmentToken: c.EnrollmentToken,
		CsrPem:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}),
		Host:            host,
	})
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return nil, err
	}
	for name, data := range map[string][]byte{
		"agent.key": keyPEM,
		"agent.crt": resp.CertificatePem,
	} {
		if err := os.WriteFile(c.path(name), data, 0o600); err != nil {
			return nil, err
		}
	}
	// agent_id is written last: its presence marks enrollment as complete.
	if err := os.WriteFile(c.path("agent_id"), []byte(resp.AgentId), 0o600); err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(resp.CertificatePem, keyPEM)
	if err != nil {
		return nil, err
	}
	return &Identity{AgentID: resp.AgentId, Cert: cert, CAPool: pool}, nil
}
