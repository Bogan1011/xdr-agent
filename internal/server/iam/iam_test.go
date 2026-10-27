package iam

import (
	"testing"
	"time"
)

func TestTOTPRFC6238(t *testing.T) {
	// RFC 6238 appendix B, SHA-1 key "12345678901234567890", 8 digits
	// truncated to the last 6.
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	for _, c := range []struct {
		unix int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		got, err := totpAt(secret, uint64(c.unix/30))
		if err != nil || got != c.want {
			t.Errorf("t=%d: got %s, want %s (%v)", c.unix, got, c.want, err)
		}
		if !VerifyTOTP(secret, c.want, time.Unix(c.unix+30, 0)) {
			t.Errorf("t=%d: one step of drift should be accepted", c.unix)
		}
		if VerifyTOTP(secret, c.want, time.Unix(c.unix+120, 0)) {
			t.Errorf("t=%d: four steps of drift should be refused", c.unix)
		}
	}
}

func TestPasswords(t *testing.T) {
	salt, hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !PasswordMatches("correct horse battery", salt, hash) || PasswordMatches("wrong", salt, hash) {
		t.Fatal("password check is wrong")
	}
	if CheckPasswordPolicy("short") == nil || CheckPasswordPolicy("long enough pass") != nil {
		t.Fatal("password policy is wrong")
	}
}

func TestRoutePermissions(t *testing.T) {
	cases := map[string]string{
		"GET /api/v1/agents":                        View,
		"GET /api/v1/agents/{id}/maintenance-token": Secrets,
		"POST /api/v1/agents/{id}/commands":         ResponseRun,
		"POST /api/v1/some/new/route":               All,
		"DELETE /api/v1/users/{id}":                 IAMManage,
		"GET /api/v1/me":                            "",
	}
	for pattern, want := range cases {
		if got := RoutePermission(pattern); got != want {
			t.Errorf("%s: got %q, want %q", pattern, got, want)
		}
	}
	if !Audited("POST /api/v1/agents/{id}/revoke") || !Audited("GET /api/v1/pam/sessions/{id}") || Audited("GET /api/v1/agents") {
		t.Fatal("audit selection is wrong")
	}
	if !Has([]string{All}, IAMManage) || Has([]string{View}, IAMManage) || !Has(nil, "") {
		t.Fatal("Has is wrong")
	}
}
