package app

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseSSOInstances(t *testing.T) {
	instances, err := ParseSSOInstances()
	require.NoError(t, err)
	require.NotEmpty(t, instances)

	// All instances should have start URL and region
	for _, inst := range instances {
		require.NotEmpty(t, inst.StartURL)
		require.NotEmpty(t, inst.Region)
	}
}

func TestTokenCacheFile(t *testing.T) {
	path := TokenCacheFile("https://example.awsapps.com/start")
	require.Contains(t, path, "e8be5486177c5b5392bd9aa76563515b29358e6e.json")
}

func TestLoadExistingToken(t *testing.T) {
	instances, err := ParseSSOInstances()
	require.NoError(t, err)

	token, err := LoadToken(instances[0].StartURL)
	require.NoError(t, err)
	require.Equal(t, instances[0].StartURL, token.StartURL)
	require.NotEmpty(t, token.AccessToken)
}
