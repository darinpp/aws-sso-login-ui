package app

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SSOInstance represents a unique SSO Identity Center instance.
type SSOInstance struct {
	StartURL string
	Region   string
}

// ParseSSOInstances reads ~/.aws/config and returns deduplicated SSO instances.
func ParseSSOInstances() ([]SSOInstance, error) {
	configPath := filepath.Join(homeDir(), ".aws", "config")
	f, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", configPath, err)
	}
	defer f.Close()

	seen := map[SSOInstance]bool{}
	var current SSOInstance
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			if current.StartURL != "" && current.Region != "" {
				seen[current] = true
			}
			current = SSOInstance{}
			continue
		}
		k, v, ok := parseKV(line)
		if !ok {
			continue
		}
		switch k {
		case "sso_start_url":
			current.StartURL = v
		case "sso_region":
			current.Region = v
		}
	}
	if current.StartURL != "" && current.Region != "" {
		seen[current] = true
	}

	var instances []SSOInstance
	for inst := range seen {
		instances = append(instances, inst)
	}
	if len(instances) == 0 {
		return nil, fmt.Errorf("no SSO instances found in %s", configPath)
	}
	return instances, nil
}

func parseKV(line string) (key, value string, ok bool) {
	if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
		return "", "", false
	}
	parts := strings.SplitN(line, "=", 2)
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func homeDir() string {
	h, _ := os.UserHomeDir()
	return h
}
