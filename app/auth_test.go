package app

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsNetworkError(t *testing.T) {
	require.True(t, isNetworkError(errors.New("dial tcp: lookup oidc.us-east-2.amazonaws.com: i/o timeout")))
	require.True(t, isNetworkError(errors.New("Post https://example.com: dial tcp: connection refused")))
	require.True(t, isNetworkError(errors.New("lookup example.com: no such host")))
	require.True(t, isNetworkError(errors.New("connect: network is unreachable")))
	require.True(t, isNetworkError(errors.New("dial tcp 1.2.3.4:443: no route to host")))
	// Wrapped errors (as returned by Authenticate)
	require.True(t, isNetworkError(fmt.Errorf("start device auth: %w",
		errors.New("operation error: dial tcp: lookup host: i/o timeout"))))
	// Non-network errors
	require.False(t, isNetworkError(errors.New("AuthorizationPendingException")))
	require.False(t, isNetworkError(errors.New("auto-confirm failed")))
	require.False(t, isNetworkError(nil))
}
