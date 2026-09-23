package app

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

// SessionState represents the current state of the SSO session.
type SessionState int

const (
	StateValid      SessionState = iota // Green — session active
	StateWarning                        // Yellow — expiring within 15 minutes
	StateExpired                        // Red — expired, needs re-auth
	StateRenewing                       // Renewal in progress
	StateNeedsLogin                     // SSO session expired, needs manual browser login
	StateOffline                        // Network unavailable, waiting for connectivity
)

const warningThreshold = 15 * time.Minute
const connectivityCheckInterval = 15 * time.Second
const networkTimeout = 30 * time.Second

// SessionStatus is broadcast by the monitor to the UI.
type SessionStatus struct {
	State           SessionState
	Remaining       time.Duration
	Fraction        float64 // fraction of the token's lifetime remaining, in [0, 1]
	Instance        SSOInstance
	HasRefreshToken bool
}

// Monitor watches SSO token expiry and attempts renewal.
type Monitor struct {
	instances        []SSOInstance
	statusCh         chan SessionStatus
	authCh           chan SSOInstance // signals UI to trigger re-auth
	authInFlight     sync.Map         // tracks in-progress auth per StartURL
	lastRenewAttempt sync.Map         // per-StartURL time.Time of last proactive renewal attempt
	reactiveGivenUp  sync.Map         // per-StartURL: true once a reactive (fully-expired) auto re-auth has failed
	proactiveDone    sync.Map         // per-StartURL: true once a proactive short-TTL auto re-auth has been tried
	initialDone      chan struct{}    // closed when initial auth completes
	wg               sync.WaitGroup   // tracks in-flight goroutines for graceful shutdown
}

func NewMonitor(instances []SSOInstance) *Monitor {
	return &Monitor{
		instances:   instances,
		statusCh:    make(chan SessionStatus, 1),
		authCh:      make(chan SSOInstance, 1),
		initialDone: make(chan struct{}),
	}
}

// InitialAuthDone signals the monitor that initial authentication has completed.
func (m *Monitor) InitialAuthDone() {
	select {
	case <-m.initialDone:
		// already closed
	default:
		close(m.initialDone)
	}
}

// Wait blocks until all in-flight auth attempts finish.
func (m *Monitor) Wait() {
	m.wg.Wait()
}

func (m *Monitor) StatusCh() <-chan SessionStatus {
	return m.statusCh
}

func (m *Monitor) AuthCh() <-chan SSOInstance {
	return m.authCh
}

func checkConnectivity(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", "1.1.1.1:53")
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func waitForConnectivity(ctx context.Context) bool {
	log.Printf("waiting for connectivity (checking every %s)...", connectivityCheckInterval)
	ticker := time.NewTicker(connectivityCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			if checkConnectivity(ctx) {
				return true
			}
		}
	}
}

func (m *Monitor) authenticateWithRetry(ctx context.Context, inst SSOInstance, background bool) (*SSOToken, error) {
	for {
		token, err := Authenticate(ctx, inst, background)
		if err == nil {
			return token, nil
		}
		if !isNetworkError(err) {
			return nil, err
		}
		log.Printf("network error for %s, waiting for connectivity...", inst.StartURL)
		select {
		case m.statusCh <- SessionStatus{State: StateOffline, Instance: inst}:
		default:
		}
		if !waitForConnectivity(ctx) {
			return nil, ctx.Err()
		}
		log.Printf("connectivity restored, retrying auth for %s", inst.StartURL)
		select {
		case m.statusCh <- SessionStatus{State: StateRenewing, Instance: inst}:
		default:
		}
	}
}

// TriggerAuth is called by the UI when the user initiates re-authentication.
// It prevents concurrent auth attempts for the same SSO instance.
func (m *Monitor) TriggerAuth(ctx context.Context, inst SSOInstance, background bool) {
	if _, loaded := m.authInFlight.LoadOrStore(inst.StartURL, true); loaded {
		return // auth already in progress for this instance
	}
	m.wg.Add(1)
	defer m.wg.Done()
	defer m.authInFlight.Delete(inst.StartURL)

	select {
	case m.statusCh <- SessionStatus{State: StateRenewing, Instance: inst}:
	default:
	}

	token, err := m.authenticateWithRetry(ctx, inst, background)
	if err != nil {
		// Stale attempt after sleep/wake — the next monitor tick will start
		// a fresh attempt automatically.
		if errors.Is(err, ErrStaleAttempt) {
			log.Printf("stale auth attempt for %s (sleep/wake), will retry", inst.StartURL)
			return
		}

		log.Printf("authentication failed for %s: %v", inst.StartURL, err)
		select {
		case m.statusCh <- SessionStatus{
			State:    StateExpired,
			Instance: inst,
		}:
		default:
		}
		return
	}

	// A manual success always re-arms automatic renewal for next time. An
	// automatic success only re-arms it once the token is back to a normal
	// length — a still-short result means whatever's constraining it hasn't
	// cleared, so retrying again immediately would just repeat the same
	// short-lived cycle every tick.
	if !background || !isShortTTL(token) {
		m.reactiveGivenUp.Delete(inst.StartURL)
		m.proactiveDone.Delete(inst.StartURL)
	}
	m.sendStatus(token, inst)
}

func (m *Monitor) Run(ctx context.Context) {
	// Wait for initial auth to finish before starting the monitor loop.
	select {
	case <-ctx.Done():
		return
	case <-m.initialDone:
	}

	m.checkAll(ctx)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkAll(ctx)
		}
	}
}

// refreshWithTimeout bounds a single RefreshToken attempt so a hung network
// call can never block checkAll — and therefore Monitor.Run's ticker loop —
// indefinitely.
func refreshWithTimeout(ctx context.Context, inst SSOInstance, token *SSOToken) (*SSOToken, error) {
	ctx, cancel := context.WithTimeout(ctx, networkTimeout)
	defer cancel()
	return RefreshToken(ctx, inst, token)
}

func (m *Monitor) checkAll(ctx context.Context) {
	for _, inst := range m.instances {
		// Skip instances that already have auth in progress
		if _, inFlight := m.authInFlight.Load(inst.StartURL); inFlight {
			continue
		}

		token, err := LoadToken(inst.StartURL)
		if err != nil || token.IsExpired() {
			if token != nil && token.RefreshToken != "" {
				refreshed, err := refreshWithTimeout(ctx, inst, token)
				if err == nil {
					m.clearRenewBackoff(inst.StartURL)
					m.sendStatus(refreshed, inst)
					continue
				}
				log.Printf("refresh failed for %s: %v", inst.StartURL, err)
			}

			select {
			case m.statusCh <- SessionStatus{
				State:    StateExpired,
				Instance: inst,
			}:
			default:
			}
			if m.shouldReactiveAutoAuth(inst.StartURL) {
				m.reactiveGivenUp.Store(inst.StartURL, true)
				select {
				case m.authCh <- inst:
				default:
				}
			}
			continue
		}

		if token.RefreshToken != "" && m.shouldRenew(inst.StartURL, token) {
			if isShortTTL(token) {
				// A short original TTL means the refresh token is likely
				// riding the same AWS/Entra ceiling, so re-authenticate via
				// a fresh, silent browser flow instead of just extending
				// within the same limited session.
				if m.shouldProactiveAutoAuth(inst.StartURL) {
					m.proactiveDone.Store(inst.StartURL, true)
					go m.TriggerAuth(ctx, inst, true)
				}
			} else {
				refreshed, err := refreshWithTimeout(ctx, inst, token)
				if err == nil {
					m.clearRenewBackoff(inst.StartURL)
					m.sendStatus(refreshed, inst)
					continue
				}
				log.Printf("proactive renewal failed for %s: %v", inst.StartURL, err)
				m.lastRenewAttempt.Store(inst.StartURL, time.Now())
			}
		}
		m.sendStatus(token, inst)
	}
}

// earlyRenewThreshold is the fixed lead time used to renew a token whose
// original TTL is under minDisplayTTL: a short-lived token is a symptom of
// approaching the AWS/Entra session ceiling, so it's renewed as soon as this
// much time is left rather than waiting for a fraction of its already-short
// span to elapse, which would leave little margin for a retry.
const earlyRenewThreshold = 20 * time.Minute

// shouldRenew reports whether a still-valid token is due for proactive
// renewal, and the retry backoff (a quarter of the token's lifetime) has
// elapsed since the last renewal attempt. A token with the normal ~1h TTL is
// due once two thirds of its lifetime have elapsed (leaving 20 minutes); a
// token issued with a shorter TTL is due once earlyRenewThreshold is left,
// regardless of its own span. A successful renewal clears the backoff via
// clearRenewBackoff, so the next threshold is never throttled — the backoff
// only gates retries after a failed attempt.
func (m *Monitor) shouldRenew(startURL string, token *SSOToken) bool {
	received, exp, ok := tokenTimes(token)
	if !ok {
		return false
	}
	span := exp.Sub(received)
	if span <= 0 {
		return false
	}

	var due bool
	if span < minDisplayTTL {
		due = time.Until(exp) <= earlyRenewThreshold
	} else {
		due = !time.Now().Before(received.Add(span * 2 / 3))
	}
	if !due {
		return false
	}

	lastAttempt, _ := m.lastRenewAttempt.Load(startURL)
	last, _ := lastAttempt.(time.Time)
	return time.Since(last) >= span/4
}

// tokenTimes parses a token's received/expiry timestamps.
func tokenTimes(token *SSOToken) (received, exp time.Time, ok bool) {
	received, err := time.Parse(timeFormat, token.ReceivedAt)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	exp, err = token.ExpiresTime()
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	return received, exp, true
}

// isShortTTL reports whether a token's original TTL was under minDisplayTTL.
func isShortTTL(token *SSOToken) bool {
	received, exp, ok := tokenTimes(token)
	return ok && exp.Sub(received) < minDisplayTTL
}

func (m *Monitor) clearRenewBackoff(startURL string) {
	m.lastRenewAttempt.Delete(startURL)
}

// shouldReactiveAutoAuth reports whether a fully-expired token is still
// worth an automatic re-authentication attempt. A failed attempt can't
// succeed by retrying on the next tick — the identity provider needs a
// fresh interactive login either way — so it's tried at most once per
// expiry episode and then left alone until a TriggerAuth success (automatic
// with a normal-length result, or manual) resets it for next time.
func (m *Monitor) shouldReactiveAutoAuth(startURL string) bool {
	_, gaveUp := m.reactiveGivenUp.Load(startURL)
	return !gaveUp
}

// shouldProactiveAutoAuth reports whether a still-valid, short-TTL token is
// still worth an automatic proactive re-authentication attempt. Without
// this, a token whose entire span is under earlyRenewThreshold would
// re-qualify the instant it's issued, so a successful-but-still-short
// result would retrigger on every following tick.
func (m *Monitor) shouldProactiveAutoAuth(startURL string) bool {
	_, done := m.proactiveDone.Load(startURL)
	return !done
}

func (m *Monitor) sendStatus(token *SSOToken, inst SSOInstance) {
	remaining := token.TimeRemaining()
	state := StateValid
	if remaining < warningThreshold {
		state = StateWarning
	}
	// Non-blocking send: drop stale status if UI isn't reading.
	// The UI refreshes every second via its own ticker, so a dropped
	// update will be superseded by the next tick's recalculation.
	select {
	case m.statusCh <- SessionStatus{
		State:           state,
		Remaining:       remaining,
		Fraction:        token.RemainingFraction(),
		Instance:        inst,
		HasRefreshToken: token.RefreshToken != "",
	}:
	default:
	}
}
