package app

import (
	"context"
	"fmt"
	"time"

	"github.com/getlantern/systray"
)

// Package-level shutdown state so onExit can clean up.
var (
	shutdownCancel context.CancelFunc
	shutdownMon    *Monitor
)

func Run() {
	systray.Run(onReady, onExit)
}

// Quit triggers a graceful shutdown from outside the UI (e.g., signal handler).
func Quit() {
	systray.Quit()
}

func onReady() {
	systray.SetTitle("SSO")
	systray.SetTooltip("AWS SSO Login")

	mStatus := systray.AddMenuItem("Loading...", "Session status")
	mStatus.Disable()
	systray.AddSeparator()
	mLogin := systray.AddMenuItem("Login", "Re-authenticate SSO")
	mExpire := systray.AddMenuItem("Force Expire", "Expire current token for testing")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit", "Quit aws-sso-login-ui")

	instances, err := ParseSSOInstances()
	if err != nil {
		systray.SetTitle("SSO ERR")
		mStatus.SetTitle(fmt.Sprintf("Error: %v", err))
		handleQuit(mQuit)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	mon := NewMonitor(instances)

	// Store for onExit cleanup
	shutdownCancel = cancel
	shutdownMon = mon

	// Check for existing valid token
	hasValid := false
	for _, inst := range instances {
		token, err := LoadToken(inst.StartURL)
		if err == nil && !token.IsExpired() {
			hasValid = true
		}
	}

	// If no valid token, authenticate immediately; signal monitor when done.
	if !hasValid {
		go func() {
			for _, inst := range instances {
				mon.TriggerAuth(ctx, inst)
			}
			mon.InitialAuthDone()
		}()
	} else {
		mon.InitialAuthDone()
	}

	go mon.Run(ctx)

	// UI update ticker for countdown
	uiTicker := time.NewTicker(500 * time.Millisecond)

	var lastStatus SessionStatus
	var hasStatus bool
	var cachedExpiry time.Time // in-memory token expiry to avoid disk reads every tick
	spinnerFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinnerIdx := 0

	go func() {
		for {
			select {
			case status := <-mon.StatusCh():
				lastStatus = status
				hasStatus = true
				if status.State == StateValid || status.State == StateWarning {
					if token, err := LoadToken(status.Instance.StartURL); err == nil {
						cachedExpiry, _ = token.ExpiresTime()
					}
				}
				updateUI(mStatus, &status)
			case inst := <-mon.AuthCh():
				updateExpired(mStatus)
				go mon.TriggerAuth(ctx, inst)
			case <-mLogin.ClickedCh:
				go func() {
					for _, inst := range instances {
						mon.TriggerAuth(ctx, inst)
					}
				}()
			case <-uiTicker.C:
				if hasStatus && lastStatus.State == StateRenewing {
					systray.SetTitle("🔴 " + spinnerFrames[spinnerIdx%len(spinnerFrames)])
					spinnerIdx++
				}
				if hasStatus && (lastStatus.State == StateValid || lastStatus.State == StateWarning) {
					// Recalculate remaining from cached expiry (no disk read)
					remaining := time.Until(cachedExpiry)
					if remaining < 0 {
						remaining = 0
					}
					state := StateValid
					if remaining < warningThreshold {
						state = StateWarning
					}
					if remaining == 0 {
						state = StateExpired
					}
					s := SessionStatus{
						State:     state,
						Remaining: remaining,
						Instance:  lastStatus.Instance,
					}
					lastStatus = s
					updateUI(mStatus, &s)
				}
			case <-mExpire.ClickedCh:
				go func() {
					for _, inst := range instances {
						token, err := LoadToken(inst.StartURL)
						if err != nil {
							continue
						}
						token.ExpiresAt = time.Now().UTC().Add(-1 * time.Second).Format(timeFormat)
						SaveToken(token)
					}
				}()
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func onExit() {
	if shutdownCancel != nil {
		shutdownCancel()
	}
	if shutdownMon != nil {
		done := make(chan struct{})
		go func() { shutdownMon.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
		}
	}
}

func updateUI(mStatus *systray.MenuItem, status *SessionStatus) {
	remaining := status.Remaining.Round(time.Second)
	switch status.State {
	case StateValid:
		h := int(remaining.Hours())
		m := int(remaining.Minutes()) % 60
		systray.SetTitle(fmt.Sprintf("🟢 %dh%02dm", h, m))
		mStatus.SetTitle(fmt.Sprintf("Session valid — %s remaining", formatDuration(remaining)))
	case StateWarning:
		m := int(remaining.Minutes())
		s := int(remaining.Seconds()) % 60
		systray.SetTitle(fmt.Sprintf("🟢 %dm%02ds", m, s))
		mStatus.SetTitle(fmt.Sprintf("Expiring soon — %s remaining", formatDuration(remaining)))
	case StateRenewing:
		mStatus.SetTitle("Renewing session...")
	case StateExpired:
		updateExpired(mStatus)
	case StateNeedsLogin:
		systray.SetTitle("🔴 Auth")
		mStatus.SetTitle("SSO session expired — click Login to open browser")
	case StateOffline:
		systray.SetTitle("🔴 Net")
		mStatus.SetTitle("Network unavailable — waiting for connectivity")
	}
}

func updateExpired(mStatus *systray.MenuItem) {
	systray.SetTitle("🔴 !")
	mStatus.SetTitle("Session expired — click Login")
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func handleQuit(mQuit *systray.MenuItem) {
	go func() {
		<-mQuit.ClickedCh
		systray.Quit()
	}()
}
