package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseSSOInstances_MultipleInstances(t *testing.T) {
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	awsDir := filepath.Join(tmpHome, ".aws")
	require.NoError(t, os.MkdirAll(awsDir, 0700))

	config := `[profile dev]
sso_start_url = https://company.awsapps.com/start
sso_region = us-east-1
sso_account_id = 111111111111
sso_role_name = DevRole

[profile prod]
sso_start_url = https://company.awsapps.com/start
sso_region = us-east-1
sso_account_id = 222222222222
sso_role_name = ProdRole

[profile other-org]
sso_start_url = https://other.awsapps.com/start
sso_region = eu-west-1
sso_account_id = 333333333333
sso_role_name = AdminRole
`
	require.NoError(t, os.WriteFile(filepath.Join(awsDir, "config"), []byte(config), 0600))

	instances, err := ParseSSOInstances()
	require.NoError(t, err)
	// Two unique instances (company deduped, other-org separate)
	require.Len(t, instances, 2)
}

func TestParseSSOInstances_MissingFields(t *testing.T) {
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	awsDir := filepath.Join(tmpHome, ".aws")
	require.NoError(t, os.MkdirAll(awsDir, 0700))

	// Profile with only start URL, no region
	config := `[profile broken]
sso_start_url = https://company.awsapps.com/start
`
	require.NoError(t, os.WriteFile(filepath.Join(awsDir, "config"), []byte(config), 0600))

	_, err := ParseSSOInstances()
	require.Error(t, err)
}

func TestParseSSOInstances_EmptyFile(t *testing.T) {
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	awsDir := filepath.Join(tmpHome, ".aws")
	require.NoError(t, os.MkdirAll(awsDir, 0700))

	require.NoError(t, os.WriteFile(filepath.Join(awsDir, "config"), []byte(""), 0600))

	_, err := ParseSSOInstances()
	require.Error(t, err)
}

func TestParseSSOInstances_NoFile(t *testing.T) {
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	_, err := ParseSSOInstances()
	require.Error(t, err)
}
