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

// Menu-bar title glyphs: moon phases show remaining TTL as a waning
// sequence; 🚫 marks no session / error, 📡 marks offline/retrying.
const (
	emojiFullMoon       = "\U0001F315" // 100%–80% remaining
	emojiWaxingGibbous  = "\U0001F314" // 80%–60% remaining
	emojiFirstQuarter   = "\U0001F313" // 60%–40% remaining
	emojiWaxingCrescent = "\U0001F312" // 40%–20% remaining
	emojiNewMoon        = "\U0001F311" // 20%–0% remaining
	emojiProhibited     = "\U0001F6AB" // no session / error
	emojiOffline        = "\U0001F4E1" // network unreachable, retrying
)

// moonPhase picks the moon-phase glyph for the fraction of the token's
// lifetime remaining, waning from full moon (fresh) to new moon (about to
// expire).
func moonPhase(remaining float64) string {
	switch {
	case remaining > 0.8:
		return emojiFullMoon
	case remaining > 0.6:
		return emojiWaxingGibbous
	case remaining > 0.4:
		return emojiFirstQuarter
	case remaining > 0.2:
		return emojiWaxingCrescent
	default:
		return emojiNewMoon
	}
}

func Run() {
	systray.Run(onReady, onExit)
}

// Quit triggers a graceful shutdown from outside the UI (e.g., signal handler).
func Quit() {
	systray.Quit()
}

func onReady() {
	systray.SetTitle(emojiProhibited)
	systray.SetTooltip("AWS SSO session")

	mSession := systray.AddMenuItem("AWS SSO", "AWS SSO session")
	mStatus := mSession.AddSubMenuItem("Loading...", "Session status")
	mStatus.Disable()
	mLogin := mSession.AddSubMenuItem("Login", "Re-authenticate SSO")
	mTokenMenu := mSession.AddSubMenuItem("Token", "Token test helpers")
	mTokenRefresh := mTokenMenu.AddSubMenuItem("Refresh",
		"Expire access token; refresh token stays valid")
	mTokenFederation := mTokenMenu.AddSubMenuItem("Federation",
		"Expire token and invalidate refresh token; re-authenticates via the identity provider")
	mTokenRemove := mTokenMenu.AddSubMenuItem("Remove",
		"Expire token and invalidate refresh token")
	addChromeProfileMenu(mSession)
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit", "Quit aws-sso-login-ui")

	instances, err := ParseSSOInstances()
	if err != nil {
		systray.SetTitle(emojiProhibited)
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
				mon.TriggerAuth(ctx, inst, false)
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
	var cachedReceivedAt, cachedExpiry time.Time // in-memory token span to avoid disk reads every tick
	var cachedHasRefresh bool
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
						cachedReceivedAt, _ = time.Parse(timeFormat, token.ReceivedAt)
						cachedHasRefresh = token.RefreshToken != ""
					}
				}
				updateUI(mStatus, &status)
			case inst := <-mon.AuthCh():
				lastStatus = SessionStatus{State: StateExpired, Instance: inst}
				updateExpired(mStatus)
				go mon.TriggerAuth(ctx, inst, true)
			case <-mLogin.ClickedCh:
				go func() {
					for _, inst := range instances {
						mon.TriggerAuth(ctx, inst, false)
					}
				}()
			case <-uiTicker.C:
				if hasStatus && lastStatus.State == StateRenewing {
					systray.SetTitle(spinnerFrames[spinnerIdx%len(spinnerFrames)])
					spinnerIdx++
				}
				if hasStatus && (lastStatus.State == StateValid || lastStatus.State == StateWarning) {
					// Recalculate remaining from cached span (no disk read)
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
					fraction := remainingFraction(remaining, cachedExpiry.Sub(cachedReceivedAt))
					s := SessionStatus{
						State:           state,
						Remaining:       remaining,
						Fraction:        fraction,
						Instance:        lastStatus.Instance,
						HasRefreshToken: cachedHasRefresh,
					}
					lastStatus = s
					updateUI(mStatus, &s)
				}
			case <-mTokenRefresh.ClickedCh:
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
			case <-mTokenFederation.ClickedCh:
				go func() {
					for _, inst := range instances {
						token, err := LoadToken(inst.StartURL)
						if err != nil {
							continue
						}
						token.ExpiresAt = time.Now().UTC().Add(-1 * time.Second).Format(timeFormat)
						token.RefreshToken = "invalid"
						SaveToken(token)
					}
				}()
			case <-mTokenRemove.ClickedCh:
				go func() {
					skipHeadlessOnce.Store(true)
					for _, inst := range instances {
						token, err := LoadToken(inst.StartURL)
						if err != nil {
							continue
						}
						token.ExpiresAt = time.Now().UTC().Add(-1 * time.Second).Format(timeFormat)
						token.RefreshToken = "invalid"
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
		systray.SetTitle(moonPhase(status.Fraction))
		systray.SetTooltip(fmt.Sprintf("AWS SSO — %s left", formatDuration(remaining)))
		if status.HasRefreshToken {
			mStatus.SetTitle(fmt.Sprintf("%s left, has refresh token", formatDuration(remaining)))
		} else {
			mStatus.SetTitle(fmt.Sprintf("%s left", formatDuration(remaining)))
		}
	case StateWarning:
		systray.SetTitle(moonPhase(status.Fraction))
		systray.SetTooltip(fmt.Sprintf("Expiring soon — %s left", formatDuration(remaining)))
		mStatus.SetTitle(fmt.Sprintf("Expiring soon — %s remaining", formatDuration(remaining)))
	case StateRenewing:
		mStatus.SetTitle("Renewing session...")
	case StateExpired:
		updateExpired(mStatus)
	case StateNeedsLogin:
		systray.SetTitle(emojiProhibited)
		systray.SetTooltip("SSO session expired")
		mStatus.SetTitle("SSO session expired — click Login to open browser")
	case StateOffline:
		systray.SetTitle(emojiOffline)
		systray.SetTooltip("Network unavailable — retrying")
		mStatus.SetTitle("Network unavailable — waiting for connectivity")
	}
}

func updateExpired(mStatus *systray.MenuItem) {
	systray.SetTitle(emojiProhibited)
	systray.SetTooltip("Session expired")
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

// addChromeProfileMenu adds a submenu letting the user override which Chrome
// profile the silent, headless renewal path copies cookies from — useful
// when the auto-detected last-used profile isn't the one signed in to Entra.
func addChromeProfileMenu(parent *systray.MenuItem) {
	profiles, err := ListChromeProfiles()
	if err != nil || len(profiles) == 0 {
		return
	}
	override := LoadSettings().ChromeProfile

	autoLabel := "Auto"
	if defaultDir, err := defaultChromeProfileDir(); err == nil {
		for _, p := range profiles {
			if p.Dir == defaultDir {
				autoLabel = fmt.Sprintf("Auto (%s)", p.Label)
				break
			}
		}
	}

	mProfile := parent.AddSubMenuItem("Chrome Profile", "Choose which Chrome profile to use for silent renewal")
	items := make(map[string]*systray.MenuItem, len(profiles)+1)
	items[""] = mProfile.AddSubMenuItemCheckbox(autoLabel,
		"Use whichever profile Chrome itself would open", override == "")
	for _, p := range profiles {
		item := mProfile.AddSubMenuItemCheckbox(p.Label, p.Dir, p.Dir == override)
		items[p.Dir] = item
	}
	for dir, item := range items {
		dir, item := dir, item
		go func() {
			for range item.ClickedCh {
				_ = SaveSettings(Settings{ChromeProfile: dir})
				for d, it := range items {
					if d == dir {
						it.Check()
					} else {
						it.Uncheck()
					}
				}
			}
		}()
	}
}
