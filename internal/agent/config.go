// Package agent wires the collectors to the backend connection.
package agent

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Server is the mTLS telemetry endpoint, host:port.
	Server string `yaml:"server"`
	// EnrollServer is the enrollment endpoint, host:port.
	EnrollServer string `yaml:"enroll_server"`
	// ServerName overrides the TLS name checked on the server certificate.
	ServerName      string `yaml:"server_name"`
	CAFile          string `yaml:"ca_file"`
	EnrollmentToken string `yaml:"enrollment_token"`
	StateDir        string `yaml:"state_dir"`

	FilePaths       []string      `yaml:"file_paths"`
	FileExclude     []string      `yaml:"file_exclude"`
	MaxFileWatches  int           `yaml:"max_file_watches"`
	NetworkInterval time.Duration `yaml:"network_interval"`
	QueueSize       int           `yaml:"queue_size"`
	BatchSize       int           `yaml:"batch_size"`
	LogLevel        string        `yaml:"log_level"`
	// ScanMaxBytes is the largest file the YARA scanner reads.
	ScanMaxBytes int64 `yaml:"scan_max_bytes"`
}

func LoadConfig(path string) (*Config, error) {
	c := &Config{
		CAFile:   "/etc/xdr-agent/ca.crt",
		StateDir: "/var/lib/xdr-agent",
		FilePaths: []string{
			"/etc", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
			"/bin", "/sbin", "/tmp", "/var/tmp", "/dev/shm", "/root", "/home", "/var/www",
			"/var/spool/cron", "/lib/systemd/system", "/etc/systemd/system",
		},
		FileExclude: []string{
			"/var/lib/xdr-agent", "/etc/ld.so.cache",
		},
		MaxFileWatches:  8192,
		NetworkInterval: 5 * time.Second,
		QueueSize:       20000,
		BatchSize:       1000,
		LogLevel:        "info",
		ScanMaxBytes:    32 << 20,
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(raw, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Server == "" {
		return nil, fmt.Errorf("%s: server is required", path)
	}
	if c.EnrollServer == "" {
		return nil, fmt.Errorf("%s: enroll_server is required", path)
	}
	return c, nil
}
