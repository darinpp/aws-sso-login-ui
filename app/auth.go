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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
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

	// interactiveWaitTimeout bounds how long a visible, user-initiated
	// sign-in waits for the browser redirect. backgroundWaitTimeout bounds
	// a silent/background attempt far more tightly, so a flow that can't
	// complete silently (e.g. needs real interactive login) fails fast
	// instead of leaving a real, visible tab sitting in the browser for
	// minutes.
	interactiveWaitTimeout = 5 * time.Minute
	backgroundWaitTimeout  = 20 * time.Second
)

// Auth failure reasons — each produces a different UI indicator.
var (
	ErrStaleAttempt = errors.New("stale auth attempt after sleep/wake")
)

// Authenticate performs the SSO OIDC authorization_code + PKCE flow: it stands
// up a loopback callback listener, opens the system browser to the
// authorization endpoint, catches the redirect, and exchanges the code for a
// token.
func Authenticate(ctx context.Context, inst SSOInstance, background bool) (*SSOToken, error) {
	setupCtx, setupCancel := context.WithTimeout(ctx, networkTimeout)
	defer setupCancel()

	cfg, err := config.LoadDefaultConfig(setupCtx, config.WithRegion(inst.Region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	client := ssooidc.NewFromConfig(cfg)

	reg, err := getOrRegisterClient(setupCtx, client, inst)
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
	if cleanup := openBrowser(authURL, background); cleanup != nil {
		defer cleanup()
	}

	waitTimeout := interactiveWaitTimeout
	if background {
		waitTimeout = backgroundWaitTimeout
	}
	waitCtx, cancel := context.WithTimeout(ctx, waitTimeout)
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

	tokenCtx, tokenCancel := context.WithTimeout(ctx, networkTimeout)
	defer tokenCancel()

	tokenResp, err := client.CreateToken(tokenCtx, &ssooidc.CreateTokenInput{
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
	log.Printf("Token refreshed via refresh_token for %s (expires in %ds)", inst.StartURL, tokenResp.ExpiresIn)
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

// openBrowser opens rawURL and, if it launched a process that needs to be
// torn down afterward (e.g. a disposable headless Chrome instance), returns
// a cleanup func — nil if there's nothing to clean up. A background open
// only ever tries the headless, cookie-only method: if that isn't available
// or fails, it does nothing further, so an automatic renewal attempt can
// never show a real, visible browser window — only a manual Login click can.
func openBrowser(rawURL string, background bool) func() {
	switch runtime.GOOS {
	case "darwin":
		if background {
			return openHeadlessCookieProfile(rawURL)
		}
		exec.Command("open", rawURL).Start()
	case "linux":
		exec.Command("xdg-open", rawURL).Start()
	}
	return nil
}

// skipHeadlessOnce forces the next openHeadlessCookieProfile call to decline,
// so a test can exercise the AppleScript/open -g fallback chain instead. It
// is consumed (reset to false) by that one call.
var skipHeadlessOnce atomic.Bool

// openHeadlessCookieProfile launches a fully headless Chrome against an
// isolated, disposable copy of the selected profile's cookies, so the
// silent authorization redirect can complete without ever creating a
// visible window. Returns a cleanup func if launched, or nil if this
// method couldn't be attempted, in which case the caller should fall back
// to the next method.
func openHeadlessCookieProfile(rawURL string) func() {
	if skipHeadlessOnce.Swap(false) {
		return nil
	}
	chromeBin := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	if _, err := os.Stat(chromeBin); err != nil {
		return nil
	}
	profileDir, err := selectedChromeProfileDir()
	if err != nil {
		return nil
	}
	srcCookies := filepath.Join(chromeUserDataDir(), profileDir, "Cookies")
	if _, err := os.Stat(srcCookies); err != nil {
		return nil
	}

	tmpProfile, err := os.MkdirTemp("", "aws-sso-login-ui-chrome-")
	if err != nil {
		return nil
	}
	cleanupDir := func() { os.RemoveAll(tmpProfile) }

	defaultDir := filepath.Join(tmpProfile, "Default")
	if err := os.MkdirAll(defaultDir, 0o700); err != nil {
		cleanupDir()
		return nil
	}
	dstCookies := filepath.Join(defaultDir, "Cookies")
	backup := exec.Command("sqlite3", srcCookies, fmt.Sprintf(".backup '%s'", dstCookies))
	if out, err := backup.CombinedOutput(); err != nil {
		log.Printf("headless cookie profile: sqlite3 backup failed: %v: %s", err, out)
		cleanupDir()
		return nil
	}

	// Strip Google's own session cookies from the copy. Chrome performs
	// background GAIA account-consistency checks on startup using whatever
	// Google session cookies a profile holds, independent of what URL is
	// navigated to. Carrying a copy of them into a second, simultaneously
	// running Chrome process makes Google's backend see the same session
	// used from two places at once, which it treats as session theft and
	// revokes — signing the real browser out of Gmail. These cookies are
	// never needed for the AWS/Entra SSO flow.
	filterOut := exec.Command("sqlite3", dstCookies, `DELETE FROM cookies WHERE `+
		`host_key LIKE '%google.com' OR host_key LIKE '%gmail.com' OR `+
		`host_key LIKE '%youtube.com' OR host_key LIKE '%googleusercontent.com' OR `+
		`host_key LIKE '%gstatic.com' OR host_key LIKE '%googleapis.com' OR `+
		`host_key LIKE '%googlevideo.com' OR host_key LIKE '%doubleclick.net';`)
	if out, err := filterOut.CombinedOutput(); err != nil {
		log.Printf("headless cookie profile: filtering Google cookies failed: %v: %s", err, out)
		cleanupDir()
		return nil
	}

	// Launch via "open -a" (Launch Services) rather than exec'ing Chrome's
	// binary directly — a direct exec trips macOS's App Management privacy
	// prompt ("prevented from modifying apps"), since it looks like this
	// process is controlling Chrome's execution rather than a normal,
	// user-facing app launch. -n forces a new process even though Chrome
	// (with a different profile) is already running.
	openArgs := []string{
		"-a", "Google Chrome",
		"-n",
		"--args",
		"--headless=new",
		"--user-data-dir=" + tmpProfile,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		rawURL,
	}
	if err := exec.Command("open", openArgs...).Run(); err != nil {
		log.Printf("headless cookie profile: launch failed: %v", err)
		cleanupDir()
		return nil
	}
	log.Printf("headless cookie profile: launched against profile %q", profileDir)

	return func() {
		// The real Chrome process isn't a child of ours (open -a launched
		// it via Launch Services), so it's found by its unique, disposable
		// --user-data-dir rather than a held *os.Process.
		_ = exec.Command("pkill", "-f", tmpProfile).Run()
		cleanupDir()
	}
}
