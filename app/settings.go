package app

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Settings holds user-configurable app preferences, persisted separately
// from cached tokens/registrations.
type Settings struct {
	ChromeProfile string `json:"chromeProfile,omitempty"`
}

func settingsFile() string {
	return filepath.Join(homeDir(), ".aws-sso-login-ui", "settings.json")
}

// LoadSettings reads persisted settings, returning a zero-value Settings if
// none have been saved yet.
func LoadSettings() Settings {
	data, err := os.ReadFile(settingsFile())
	if err != nil {
		return Settings{}
	}
	var s Settings
	_ = json.Unmarshal(data, &s)
	return s
}

// SaveSettings writes settings to disk atomically.
func SaveSettings(s Settings) error {
	return atomicWriteJSON(settingsFile(), s)
}
