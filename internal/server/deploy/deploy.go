// Package deploy installs the agent on remote Linux hosts over SSH.
package deploy

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

const (
	maxParallel = 10
	jobTimeout  = 10 * time.Minute
)

// Request holds SSH credentials for one batch. They live only in memory for
// the duration of the jobs and are never stored.
type Request struct {
	Hosts      []string
	Port       int
	Username   string
	Password   string
	PrivateKey string
	Passphrase string
	// BaseURL is the console URL the target hosts download the installer from.
	BaseURL  string
	CASHA256 string
}

type Deployer struct {
	DB   *store.Postgres
	Log  *slog.Logger
	sem  chan struct{}
	once sync.Once
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9.\-:]+$`)

func (r *Request) validate() error {
	if len(r.Hosts) == 0 || len(r.Hosts) > 200 {
		return fmt.Errorf("give between 1 and 200 hosts")
	}
	for _, h := range r.Hosts {
		if !hostRe.MatchString(h) {
			return fmt.Errorf("invalid host %q", h)
		}
	}
	if r.Port <= 0 || r.Port > 65535 {
		return fmt.Errorf("invalid SSH port")
	}
	if r.Username == "" || strings.ContainsAny(r.Username, " '\"\\;") {
		return fmt.Errorf("invalid username")
	}
	if r.Password == "" && r.PrivateKey == "" {
		return fmt.Errorf("a password or a private key is required")
	}
	return nil
}

// Start creates one job per host and runs them in the background.
func (d *Deployer) Start(ctx context.Context, r Request) ([]int64, error) {
	d.once.Do(func() { d.sem = make(chan struct{}, maxParallel) })
	if err := r.validate(); err != nil {
		return nil, err
	}
	auth, err := authMethods(r)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for _, h := range r.Hosts {
		id, err := d.DB.CreateDeployJob(ctx, h, r.Port, r.Username)
		if err != nil {
			return ids, err
		}
		ids = append(ids, id)
		go d.run(id, h, r, auth)
	}
	return ids, nil
}

func authMethods(r Request) ([]ssh.AuthMethod, error) {
	var out []ssh.AuthMethod
	if r.PrivateKey != "" {
		var signer ssh.Signer
		var err error
		if r.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(r.PrivateKey), []byte(r.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(r.PrivateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("private key: %w", err)
		}
		out = append(out, ssh.PublicKeys(signer))
	}
	if r.Password != "" {
		out = append(out, ssh.Password(r.Password))
		pw := r.Password
		out = append(out, ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			ans := make([]string, len(qs))
			for i := range ans {
				ans[i] = pw
			}
			return ans, nil
		}))
	}
	return out, nil
}

// jobLog collects output and writes it to the job row at most once a second.
type jobLog struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	hostKey string
}

func (l *jobLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buf.Len() < 256*1024 {
		l.buf.Write(p)
	}
	return len(p), nil
}

func (l *jobLog) printf(format string, a ...any) { fmt.Fprintf(l, format+"\n", a...) }

func (l *jobLog) snapshot() (string, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String(), l.hostKey
}

func (d *Deployer) run(id int64, host string, r Request, auth []ssh.AuthMethod) {
	d.sem <- struct{}{}
	defer func() { <-d.sem }()

	ctx, cancel := context.WithTimeout(context.Background(), jobTimeout)
	defer cancel()
	l := &jobLog{}
	status := "running"
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				log, key := l.snapshot()
				_ = d.DB.UpdateDeployJob(context.Background(), id, status, key, log, false)
			}
		}
	}()

	err := d.install(ctx, host, r, auth, l)
	close(done)
	status = "succeeded"
	if err != nil {
		status = "failed"
		l.printf("ERROR: %v", err)
		d.Log.Warn("remote install failed", "host", host, "err", err)
	} else {
		d.Log.Info("remote install succeeded", "host", host)
	}
	log, key := l.snapshot()
	if err := d.DB.UpdateDeployJob(context.Background(), id, status, key, log, true); err != nil {
		d.Log.Error("update deploy job", "id", id, "err", err)
	}
}

func (d *Deployer) install(ctx context.Context, host string, r Request, auth []ssh.AuthMethod, l *jobLog) error {
	token, err := d.DB.CreateEnrollmentToken(ctx, "remote install: "+host, time.Hour, 1)
	if err != nil {
		return fmt.Errorf("create enrollment token: %w", err)
	}

	addr := net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(r.Port))
	l.printf("Connecting to %s as %s", addr, r.Username)
	cfg := &ssh.ClientConfig{
		User: r.Username,
		Auth: auth,
		// Trust on first use: the key is recorded in the job so it can be
		// checked. Pinning known host keys is planned for fleet management.
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			l.mu.Lock()
			l.hostKey = ssh.FingerprintSHA256(key)
			l.mu.Unlock()
			return nil
		},
		Timeout: 15 * time.Second,
	}
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return fmt.Errorf("ssh login: %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()
	_, key := l.snapshot()
	l.printf("Connected. Host key %s", key)

	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdout = l
	sess.Stderr = l

	install := fmt.Sprintf("curl -fsSL '%s/install.sh' | bash -s -- --token '%s' --ca-sha256 '%s'",
		r.BaseURL, token.Token, r.CASHA256)
	cmd := install
	if r.Username != "root" {
		if r.Password != "" {
			// sudo reads the password from stdin; it never appears in the command line.
			cmd = "sudo -S -p '' bash -c " + shellQuote(install)
			sess.Stdin = strings.NewReader(r.Password + "\n")
		} else {
			cmd = "sudo -n bash -c " + shellQuote(install)
		}
	}
	l.printf("Running installer")

	errc := make(chan error, 1)
	go func() { errc <- sess.Run(cmd) }()
	select {
	case err = <-errc:
	case <-ctx.Done():
		return fmt.Errorf("timed out after %s", jobTimeout)
	}
	if err != nil {
		return fmt.Errorf("installer failed: %w", err)
	}
	l.printf("Done. The host appears under Endpoints once the agent enrolls.")
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
