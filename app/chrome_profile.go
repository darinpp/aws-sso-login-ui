package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func chromeUserDataDir() string {
	return filepath.Join(homeDir(), "Library", "Application Support", "Google", "Chrome")
}

// ChromeProfile is a Chrome profile directory paired with a human-readable label.
type ChromeProfile struct {
	Dir   string
	Label string
}

type chromeLocalState struct {
	Profile struct {
		LastUsed  string `json:"last_used"`
		InfoCache map[string]struct {
			Name     string `json:"name"`
			GaiaName string `json:"gaia_name"`
			UserName string `json:"user_name"`
		} `json:"info_cache"`
	} `json:"profile"`
}

func readChromeLocalState() (*chromeLocalState, error) {
	data, err := os.ReadFile(filepath.Join(chromeUserDataDir(), "Local State"))
	if err != nil {
		return nil, err
	}
	var ls chromeLocalState
	if err := json.Unmarshal(data, &ls); err != nil {
		return nil, err
	}
	return &ls, nil
}

// ListChromeProfiles returns every profile Chrome knows about, labeled with
// its signed-in account when available, falling back to the profile's
// display name.
func ListChromeProfiles() ([]ChromeProfile, error) {
	ls, err := readChromeLocalState()
	if err != nil {
		return nil, err
	}
	var profiles []ChromeProfile
	for dir, info := range ls.Profile.InfoCache {
		label := info.Name
		if info.GaiaName != "" && info.UserName != "" {
			label = fmt.Sprintf("%s (%s)", info.GaiaName, info.UserName)
		}
		profiles = append(profiles, ChromeProfile{Dir: dir, Label: label})
	}
	return profiles, nil
}

// defaultChromeProfileDir mirrors how Chrome itself picks a profile on a
// plain relaunch: the last-used profile directory recorded in Local State.
func defaultChromeProfileDir() (string, error) {
	ls, err := readChromeLocalState()
	if err != nil {
		return "", err
	}
	if ls.Profile.LastUsed == "" {
		return "", fmt.Errorf("no last_used profile in Chrome's Local State")
	}
	return ls.Profile.LastUsed, nil
}

// selectedChromeProfileDir returns the user's configured override, if any,
// else the profile Chrome itself would open on a plain relaunch.
func selectedChromeProfileDir() (string, error) {
	if p := LoadSettings().ChromeProfile; p != "" {
		return p, nil
	}
	return defaultChromeProfileDir()
}
