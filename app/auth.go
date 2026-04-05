package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
)

const (
	clientName       = "aws-sso-login-ui"
	clientType       = "public"
	grantType        = "authorization_code"
	refreshGrantType = "refresh_token"
	redirectPath     = "/oauth/callback"
	ssoScope         = "sso:account:access"
)

// Auth failure reasons — each produces a different UI indicator.
var (
	ErrStaleAttempt = errors.New("stale auth attempt after sleep/wake")
)

// Authenticate performs the SSO OIDC authorization_code + PKCE flow: it stands
// up a loopback callback listener, opens the system browser to the
// authorization endpoint, catches the redirect, and exchanges the code for a
// token.
func Authenticate(ctx context.Context, inst SSOInstance) (*SSOToken, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(inst.Region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	client := ssooidc.NewFromConfig(cfg)

	reg, err := getOrRegisterClient(ctx, client, inst)
	if err != nil {
		return nil, fmt.Errorf("register client: %w", err)
	}

	verifier, challenge := pkce()
	state := randToken(16)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d%s", port, redirectPath)

	type callbackResult struct {
		code, state, errDesc string
	}
	resultCh := make(chan callbackResult, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(redirectPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			http.Error(w, "Sign-in failed: "+e, http.StatusBadRequest)
			resultCh <- callbackResult{errDesc: e + ": " + q.Get("error_description")}
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, callbackHTML)
		resultCh <- callbackResult{code: q.Get("code"), state: q.Get("state")}
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	authURL := fmt.Sprintf("https://oidc.%s.amazonaws.com/authorize", inst.Region) + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {reg.ClientID},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"scopes":                {ssoScope},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	log.Printf("Opening browser for authorization (redirect_uri=%s)", redirectURI)
	openBrowser(authURL)

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	var code string
	select {
	case <-waitCtx.Done():
		return nil, fmt.Errorf("waiting for sign-in: %w", waitCtx.Err())
	case r := <-resultCh:
		if r.errDesc != "" {
			return nil, fmt.Errorf("authorize: %s", r.errDesc)
		}
		if r.state != state {
			return nil, fmt.Errorf("state mismatch")
		}
		code = r.code
	}

	tokenResp, err := client.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     &reg.ClientID,
		ClientSecret: &reg.ClientSecret,
		GrantType:    aws.String(grantType),
		Code:         aws.String(code),
		CodeVerifier: aws.String(verifier),
		RedirectUri:  aws.String(redirectURI),
	})
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}
	if tokenResp.ExpiresIn <= 0 {
		return nil, fmt.Errorf("create token: server returned invalid ExpiresIn: %d", tokenResp.ExpiresIn)
	}

	now := time.Now().UTC()
	token := &SSOToken{
		StartURL:    inst.StartURL,
		Region:      inst.Region,
		AccessToken: *tokenResp.AccessToken,
		ExpiresAt:   now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(timeFormat),
		ReceivedAt:  now.Format(timeFormat),
	}
	if tokenResp.RefreshToken != nil {
		token.RefreshToken = *tokenResp.RefreshToken
	}

	if err := SaveToken(token); err != nil {
		return nil, fmt.Errorf("save token: %w", err)
	}
	log.Printf("Token obtained via authorization_code (expires in %ds)", tokenResp.ExpiresIn)
	return token, nil
}

func pkce() (verifier, challenge string) {
	verifier = randToken(32)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

const callbackHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Signed in</title></head>` +
	`<body style="font-family:-apple-system,BlinkMacSystemFont,sans-serif;text-align:center;margin-top:4rem;color:#1d1d1f">` +
	`<h2>&#10003; Signed in</h2><p>You can close this tab and return to the menu bar.</p></body></html>`

// RefreshToken attempts to refresh an existing token using its refresh token.
func RefreshToken(ctx context.Context, inst SSOInstance, token *SSOToken) (*SSOToken, error) {
	if token.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(inst.Region))
	if err != nil {
		return nil, err
	}
	client := ssooidc.NewFromConfig(cfg)

	reg, err := LoadClientRegistration(inst.Region)
	if err != nil {
		return nil, fmt.Errorf("load client registration: %w", err)
	}

	tokenResp, err := client.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     &reg.ClientID,
		ClientSecret: &reg.ClientSecret,
		GrantType:    aws.String(refreshGrantType),
		RefreshToken: &token.RefreshToken,
	})
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}
	if tokenResp.ExpiresIn <= 0 {
		return nil, fmt.Errorf("refresh token: server returned invalid ExpiresIn: %d", tokenResp.ExpiresIn)
	}

	now := time.Now().UTC()
	newToken := &SSOToken{
		StartURL:    inst.StartURL,
		Region:      inst.Region,
		AccessToken: *tokenResp.AccessToken,
		ExpiresAt:   now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(timeFormat),
		ReceivedAt:  now.Format(timeFormat),
	}
	if tokenResp.RefreshToken != nil {
		newToken.RefreshToken = *tokenResp.RefreshToken
	} else {
		newToken.RefreshToken = token.RefreshToken
	}

	if err := SaveToken(newToken); err != nil {
		return nil, err
	}
	return newToken, nil
}

// getOrRegisterClient loads a cached client registration for the region, or
// registers a new public client with the authorization_code + PKCE grant
// (plus refresh_token) against the instance's start URL.
func getOrRegisterClient(ctx context.Context,
	client *ssooidc.Client, inst SSOInstance,
) (*ClientRegistration, error) {
	if reg, err := LoadClientRegistration(inst.Region); err == nil {
		exp, _ := time.Parse(timeFormat, reg.ExpiresAt)
		if time.Now().UTC().Before(exp) {
			return reg, nil
		}
	}

	resp, err := client.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName:   aws.String(clientName),
		ClientType:   aws.String(clientType),
		GrantTypes:   []string{grantType, refreshGrantType},
		RedirectUris: []string{"http://127.0.0.1" + redirectPath},
		IssuerUrl:    aws.String(inst.StartURL),
		Scopes:       []string{ssoScope},
	})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	reg := &ClientRegistration{
		ClientID:     *resp.ClientId,
		ClientSecret: *resp.ClientSecret,
		ExpiresAt:    time.Unix(resp.ClientSecretExpiresAt, 0).UTC().Format(timeFormat),
		ReceivedAt:   now.Format(timeFormat),
	}
	if err := SaveClientRegistration(inst.Region, reg); err != nil {
		return nil, err
	}
	return reg, nil
}

func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "i/o timeout") ||
		contains(msg, "no such host") ||
		contains(msg, "connection refused") ||
		contains(msg, "network is unreachable") ||
		contains(msg, "no route to host")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func openBrowser(rawURL string) {
	switch runtime.GOOS {
	case "darwin":
		exec.Command("open", rawURL).Start()
	case "linux":
		exec.Command("xdg-open", rawURL).Start()
	}
}
