package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAtomicWriteJSON(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "test.json")

	data := map[string]string{"key": "value"}
	err := atomicWriteJSON(dest, data)
	require.NoError(t, err)

	// Read back and verify
	raw, err := os.ReadFile(dest)
	require.NoError(t, err)

	var got map[string]string
	require.NoError(t, json.Unmarshal(raw, &got))
	require.Equal(t, "value", got["key"])

	// Verify permissions
	info, err := os.Stat(dest)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestAtomicWriteJSON_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "test.json")

	// Write initial
	require.NoError(t, atomicWriteJSON(dest, map[string]string{"v": "1"}))

	// Overwrite
	require.NoError(t, atomicWriteJSON(dest, map[string]string{"v": "2"}))

	raw, err := os.ReadFile(dest)
	require.NoError(t, err)
	var got map[string]string
	require.NoError(t, json.Unmarshal(raw, &got))
	require.Equal(t, "2", got["v"])
}

func TestAtomicWriteJSON_NoTempFileOnSuccess(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "test.json")

	require.NoError(t, atomicWriteJSON(dest, "hello"))

	// No .tmp files should remain
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.False(t, strings.HasPrefix(e.Name(), ".tmp-"), "temp file left behind: %s", e.Name())
	}
}

func TestSSOToken_IsExpired(t *testing.T) {
	// Valid token
	token := &SSOToken{
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour).Format(timeFormat),
	}
	require.False(t, token.IsExpired())

	// Expired token
	token.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour).Format(timeFormat)
	require.True(t, token.IsExpired())

	// Malformed expiry
	token.ExpiresAt = "garbage"
	require.True(t, token.IsExpired())
}

func TestSSOToken_TimeRemaining(t *testing.T) {
	// Valid token — should be close to 1 hour
	token := &SSOToken{
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour).Format(timeFormat),
	}
	rem := token.TimeRemaining()
	require.InDelta(t, float64(1*time.Hour), float64(rem), float64(2*time.Second))

	// Expired token
	token.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour).Format(timeFormat)
	require.Equal(t, time.Duration(0), token.TimeRemaining())

	// Malformed
	token.ExpiresAt = "garbage"
	require.Equal(t, time.Duration(0), token.TimeRemaining())
}

func TestSaveAndLoadToken(t *testing.T) {
	// Override cache dir for test
	origHome := os.Getenv("HOME")
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	token := &SSOToken{
		StartURL:    "https://example.awsapps.com/start",
		Region:      "us-east-1",
		AccessToken: "test-access-token",
		ExpiresAt:   time.Now().UTC().Add(8 * time.Hour).Format(timeFormat),
		ReceivedAt:  time.Now().UTC().Format(timeFormat),
	}

	err := SaveToken(token)
	require.NoError(t, err)

	loaded, err := LoadToken(token.StartURL)
	require.NoError(t, err)
	require.Equal(t, token.AccessToken, loaded.AccessToken)
	require.Equal(t, token.StartURL, loaded.StartURL)
	require.Equal(t, token.Region, loaded.Region)
}

func TestLoadToken_NotFound(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	_, err := LoadToken("https://nonexistent.example.com/start")
	require.Error(t, err)
}

func TestSaveAndLoadClientRegistration(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	reg := &ClientRegistration{
		ClientID:     "test-client-id",
		ClientSecret: "test-secret",
		ExpiresAt:    time.Now().UTC().Add(90 * 24 * time.Hour).Format(timeFormat),
		ReceivedAt:   time.Now().UTC().Format(timeFormat),
	}

	err := SaveClientRegistration("us-east-1", reg)
	require.NoError(t, err)

	loaded, err := LoadClientRegistration("us-east-1")
	require.NoError(t, err)
	require.Equal(t, reg.ClientID, loaded.ClientID)
	require.Equal(t, reg.ClientSecret, loaded.ClientSecret)
}
