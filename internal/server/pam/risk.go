package pam

import (
	"fmt"
	"time"
)

// SessionFacts is what is known about a privileged session for scoring.
type SessionFacts struct {
	Account   string
	Emergency bool // self-approved break-glass access
	Incident  string
	// AlertsDuring counts alerts raised on the server while the session ran.
	AlertsDuring int
	// NewSource is true when the user never connected from this address before.
	NewSource bool
	Start     time.Time
}

// Risk scores a session from 0 to 100 and says why. It is a baseline the
// behaviour analytics in Security Intelligence will replace.
func Risk(f SessionFacts) (int, []string) {
	score, why := 0, []string{}
	add := func(n int, s string) { score += n; why = append(why, s) }
	if f.Account == "root" {
		add(15, "logged in as root")
	}
	if f.Emergency {
		add(30, "emergency self-approved access")
	}
	if f.Incident == "high" || f.Incident == "critical" {
		add(25, fmt.Sprintf("started while a %s alert was open", f.Incident))
	}
	if f.AlertsDuring > 0 {
		add(min(20*f.AlertsDuring, 40), fmt.Sprintf("%d alert(s) on the server during the session", f.AlertsDuring))
	}
	if f.NewSource {
		add(15, "first session from this address")
	}
	if h := f.Start.UTC().Hour(); !f.Start.IsZero() && (h < 6 || h >= 20) {
		add(10, "outside 06:00-20:00 UTC")
	}
	return min(score, 100), why
}
