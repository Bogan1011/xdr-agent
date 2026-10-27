package policy

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

const (
	passwordIterations = 200_000
	minPassword        = 8
	maxPassword        = 128
)

// SetPassword hashes a self-protection password typed in the console into
// the policy, so only the salt and hash are stored and sent to agents.
func SetPassword(sp *xdrv1.SelfProtectionPolicy) error {
	pw := sp.NewPassword
	sp.NewPassword = ""
	if pw == "" {
		return nil
	}
	if n := utf8.RuneCountInString(pw); n < minPassword || n > maxPassword {
		return fmt.Errorf("self-protection: the password must be %d to %d characters", minPassword, maxPassword)
	}
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key, err := pbkdf2.Key(sha256.New, pw, salt, passwordIterations, 32)
	if err != nil {
		return err
	}
	sp.PasswordSalt, sp.PasswordHash = hex.EncodeToString(salt), hex.EncodeToString(key)
	return nil
}

// PasswordMatches checks a password against a salt and hash from SetPassword.
func PasswordMatches(pw, saltHex, hashHex string) bool {
	if pw == "" || saltHex == "" || hashHex == "" {
		return false
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false
	}
	key, err := pbkdf2.Key(sha256.New, pw, salt, passwordIterations, 32)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(key)), []byte(strings.ToLower(hashHex))) == 1
}
