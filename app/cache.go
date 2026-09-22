package app

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const timeFormat = "2006-01-02T15:04:05Z"

// ClientRegistration is the OIDC client registration cached by AWS CLI.
type ClientRegistration struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	ExpiresAt    string `json:"expiresAt"`
	ReceivedAt   string `json:"receivedAt"`
}

// SSOToken is the cached SSO access token, compatible with AWS CLI format.
type SSOToken struct {
	StartURL     string `json:"startUrl"`
	Region       string `json:"region"`
	AccessToken  string `json:"accessToken"`
	ExpiresAt    string `json:"expiresAt"`
	ReceivedAt   string `json:"receivedAt"`
	RefreshToken string `json:"refreshToken,omitempty"`
}

func (t *SSOToken) ExpiresTime() (time.Time, error) {
	return time.Parse(timeFormat, t.ExpiresAt)
}

func (t *SSOToken) IsExpired() bool {
	exp, err := t.ExpiresTime()
	if err != nil {
		return true
	}
	return time.Now().UTC().After(exp)
}

func (t *SSOToken) TimeRemaining() time.Duration {
	exp, err := t.ExpiresTime()
	if err != nil {
		return 0
	}
	rem := time.Until(exp)
	if rem < 0 {
		return 0
	}
	return rem
}

// RemainingFraction returns the fraction of the token's lifetime remaining,
// in [0, 1] — 1 if the lifetime can't be determined.
func (t *SSOToken) RemainingFraction() float64 {
	received, err := time.Parse(timeFormat, t.ReceivedAt)
	if err != nil {
		return 1
	}
	exp, err := t.ExpiresTime()
	if err != nil {
		return 1
	}
	span := exp.Sub(received)
	if span <= 0 {
		return 1
	}
	f := float64(time.Until(exp)) / float64(span)
	switch {
	case f < 0:
		return 0
	case f > 1:
		return 1
	default:
		return f
	}
}

// CacheDir returns ~/.aws/sso/cache/
func CacheDir() string {
	return filepath.Join(homeDir(), ".aws", "sso", "cache")
}

// TokenCacheFile returns the path for a given start URL's token cache.
func TokenCacheFile(startURL string) string {
	h := sha1.Sum([]byte(startURL))
	return filepath.Join(CacheDir(), fmt.Sprintf("%x.json", h))
}

// ClientCacheFile returns the path for a given region's client registration cache.
func ClientCacheFile(region string) string {
	return filepath.Join(CacheDir(), fmt.Sprintf("aws-sso-login-ui-pkce-%s.json", region))
}

// LoadToken reads the cached SSO token for a start URL.
func LoadToken(startURL string) (*SSOToken, error) {
	data, err := os.ReadFile(TokenCacheFile(startURL))
	if err != nil {
		return nil, err
	}
	var token SSOToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

// SaveToken writes the SSO token to the cache atomically.
func SaveToken(token *SSOToken) error {
	return atomicWriteJSON(TokenCacheFile(token.StartURL), token)
}

// LoadClientRegistration reads the cached client registration.
func LoadClientRegistration(region string) (*ClientRegistration, error) {
	data, err := os.ReadFile(ClientCacheFile(region))
	if err != nil {
		return nil, err
	}
	var reg ClientRegistration
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, err
	}
	return &reg, nil
}

// SaveClientRegistration writes the client registration to the cache atomically.
func SaveClientRegistration(region string, reg *ClientRegistration) error {
	return atomicWriteJSON(ClientCacheFile(region), reg)
}

// atomicWriteJSON writes data as indented JSON to dest atomically.
// It writes to a temp file in the same directory, then renames.
func atomicWriteJSON(dest string, v interface{}) error {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		return err
	}
	// CreateTemp respects umask. Set umask to restrict permissions before creating.
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Immediately restrict permissions before writing sensitive data.
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, dest)
}
