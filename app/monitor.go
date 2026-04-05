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

// SessionStatus is broadcast by the monitor to the UI.
type SessionStatus struct {
	State     SessionState
	Remaining time.Duration
	Instance  SSOInstance
}

// Monitor watches SSO token expiry and attempts renewal.
type Monitor struct {
	instances    []SSOInstance
	statusCh     chan SessionStatus
	authCh       chan SSOInstance // signals UI to trigger re-auth
	authInFlight sync.Map         // tracks in-progress auth per StartURL
	initialDone  chan struct{}    // closed when initial auth completes
	wg           sync.WaitGroup   // tracks in-flight goroutines for graceful shutdown
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

func (m *Monitor) authenticateWithRetry(ctx context.Context, inst SSOInstance) (*SSOToken, error) {
	for {
		token, err := Authenticate(ctx, inst)
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
func (m *Monitor) TriggerAuth(ctx context.Context, inst SSOInstance) {
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

	token, err := m.authenticateWithRetry(ctx, inst)
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

func (m *Monitor) checkAll(ctx context.Context) {
	for _, inst := range m.instances {
		// Skip instances that already have auth in progress
		if _, inFlight := m.authInFlight.Load(inst.StartURL); inFlight {
			continue
		}

		token, err := LoadToken(inst.StartURL)
		if err != nil || token.IsExpired() {
			if token != nil && token.RefreshToken != "" {
				refreshed, err := RefreshToken(ctx, inst, token)
				if err == nil {
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
			select {
			case m.authCh <- inst:
			default:
			}
			continue
		}
		m.sendStatus(token, inst)
	}
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
		State:     state,
		Remaining: remaining,
		Instance:  inst,
	}:
	default:
	}
}
