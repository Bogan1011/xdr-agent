package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

const (
	// maxRecording caps the terminal output uploaded per session.
	maxRecording = 2 << 20
	// uploadedMarker in a session directory means the console has it.
	uploadedMarker = ".xdr-uploaded"
	// staleSession is when a session that never closed (sudo was killed) is
	// uploaded anyway.
	staleSession = 24 * time.Hour
)

// sessionDirs finds sudo I/O log directories that are finished and not yet
// uploaded. sudo removes the write bits from the timing file when a session
// ends.
func sessionDirs(root string) []string {
	var out []string
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "timing" {
			return nil
		}
		dir := filepath.Dir(path)
		if _, err := os.Stat(filepath.Join(dir, uploadedMarker)); err == nil {
			return nil
		}
		st, err := os.Stat(path)
		if err != nil {
			return nil
		}
		if st.Mode().Perm()&0o222 == 0 || time.Since(st.ModTime()) > staleSession {
			out = append(out, dir)
		}
		return nil
	})
	return out
}

// readSession turns one sudo I/O log directory into a recording.
func readSession(root, dir string) (*xdrv1.SessionRecording, error) {
	rel, _ := filepath.Rel(root, dir)
	r := &xdrv1.SessionRecording{}
	if raw, err := os.ReadFile(filepath.Join(dir, "log.json")); err == nil {
		parseLogJSON(raw, r)
	} else if raw, err := os.ReadFile(filepath.Join(dir, "log")); err == nil {
		parseLegacyLog(string(raw), r)
	} else {
		return nil, err
	}
	if raw, err := readMaybeGzip(filepath.Join(dir, "timing"), 8<<20); err == nil {
		r.DurationMs = timingDuration(string(raw))
	}
	for _, name := range []string{"ttyout", "stdout"} {
		out, err := readMaybeGzip(filepath.Join(dir, name), maxRecording+1)
		if err != nil || len(out) == 0 {
			continue
		}
		if len(out) > maxRecording {
			out, r.Truncated = out[:maxRecording], true
		}
		r.Output = out
		break
	}
	r.SessionId = rel + "@" + strconv.FormatInt(r.StartUnix, 10)
	return r, nil
}

func parseLogJSON(raw []byte, r *xdrv1.SessionRecording) {
	var l struct {
		Timestamp struct {
			Seconds int64 `json:"seconds"`
		} `json:"timestamp"`
		SubmitUser string   `json:"submituser"`
		RunUser    string   `json:"runuser"`
		TTYName    string   `json:"ttyname"`
		SubmitCwd  string   `json:"submitcwd"`
		Command    string   `json:"command"`
		RunArgv    []string `json:"runargv"`
	}
	if json.Unmarshal(raw, &l) != nil {
		return
	}
	r.StartUnix, r.User, r.RunasUser, r.Tty, r.Cwd = l.Timestamp.Seconds, l.SubmitUser, l.RunUser, l.TTYName, l.SubmitCwd
	r.Command = l.Command
	if len(l.RunArgv) > 0 {
		r.Command = strings.Join(l.RunArgv, " ")
	}
}

// parseLegacyLog reads the "log" file: time:user:runas_user:runas_group:tty
// (and on newer sudo :rows:cols), then the cwd, then the command line.
func parseLegacyLog(s string, r *xdrv1.SessionRecording) {
	lines := strings.SplitN(s, "\n", 3)
	f := strings.Split(lines[0], ":")
	if len(f) >= 5 {
		sec, _, _ := strings.Cut(f[0], ".")
		r.StartUnix, _ = strconv.ParseInt(sec, 10, 64)
		r.User, r.RunasUser, r.Tty = f[1], f[2], f[4]
	}
	if len(lines) > 1 {
		r.Cwd = lines[1]
	}
	if len(lines) > 2 {
		r.Command = strings.TrimSpace(lines[2])
	}
}

// timingDuration sums the delays in a timing file. Lines are
// "type delay [bytes|rows cols]" on sudo 1.8+, "delay bytes" before.
func timingDuration(s string) uint64 {
	var total float64
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		var d string
		switch {
		case len(f) >= 3:
			d = f[1]
		case len(f) == 2:
			d = f[0]
		default:
			continue
		}
		if v, err := strconv.ParseFloat(d, 64); err == nil && v > 0 {
			total += v
		}
	}
	return uint64(total * 1000)
}

// readMaybeGzip reads up to limit bytes, decompressing when sudo compressed
// the log (compress_io).
func readMaybeGzip(path string, limit int64) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		if int64(len(raw)) > limit {
			raw = raw[:limit]
		}
		return raw, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(io.LimitReader(zr, limit))
	// A session cut off mid-write leaves a truncated stream; keep what decoded.
	if err != nil && len(out) == 0 {
		return nil, err
	}
	return out, nil
}

func (p *PAM) uploadSessions(ctx context.Context) {
	dirs := sessionDirs(p.ioDir)
	if len(dirs) > 20 {
		dirs = dirs[:20]
	}
	for _, dir := range dirs {
		r, err := readSession(p.ioDir, dir)
		if err != nil {
			p.log.Warn("read sudo session", "dir", dir, "err", err)
			continue
		}
		r.RequestId = p.grantAt(r.User, time.Unix(r.StartUnix, 0))
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, err = p.client.UploadSessionRecording(cctx, r)
		cancel()
		if err != nil {
			p.log.Warn("upload sudo session", "dir", dir, "err", err)
			return
		}
		os.WriteFile(filepath.Join(dir, uploadedMarker), nil, 0o600)
		p.log.Info("sudo session uploaded", "user", r.User, "command", r.Command, "request_id", r.RequestId)
	}
}
