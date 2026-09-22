package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

const plistLabel = "com.darinpp.aws-sso-login-ui"

// installDir is where the installed binary and LaunchAgent state live.
func installDir() string {
	return filepath.Join(os.Getenv("HOME"), ".aws-sso-login-ui")
}

// doInstall copies the running binary to a stable location and registers a
// per-user LaunchAgent so the menu-bar tool starts at login (and runs now).
func doInstall() error {
	home := os.Getenv("HOME")
	src, err := os.Executable()
	if err != nil {
		return err
	}

	dir := installDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	binary := filepath.Join(dir, "aws-sso-login-ui")

	uid := strconv.Itoa(os.Getuid())
	domain := "gui/" + uid
	// stop any running instance before overwriting the binary
	_ = exec.Command("launchctl", "bootout", domain+"/"+plistLabel).Run()

	if err := copyExecutable(src, binary); err != nil {
		return fmt.Errorf("install binary: %w", err)
	}

	logPath := filepath.Join(home, "Library", "Logs", "aws-sso-login-ui.log")
	laDir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(laDir, 0o755); err != nil {
		return err
	}
	plistPath := filepath.Join(laDir, plistLabel+".plist")
	if err := os.WriteFile(plistPath, []byte(renderPlist(binary, logPath)), 0o644); err != nil {
		return err
	}

	if out, err := exec.Command("launchctl", "bootstrap", domain, plistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %w: %s", err, out)
	}
	_ = exec.Command("launchctl", "kickstart", "-k", domain+"/"+plistLabel).Run()

	log.Printf("installed binary: %s", binary)
	log.Printf("launch agent registered: %s (starts at login; running now)", plistPath)
	log.Printf("logs: %s", logPath)
	return nil
}

// doUninstall removes the LaunchAgent and installed binary.
func doUninstall() error {
	home := os.Getenv("HOME")
	uid := strconv.Itoa(os.Getuid())
	_ = exec.Command("launchctl", "bootout", "gui/"+uid+"/"+plistLabel).Run()

	plistPath := filepath.Join(home, "Library", "LaunchAgents", plistLabel+".plist")
	_ = os.Remove(plistPath)
	_ = os.Remove(filepath.Join(installDir(), "aws-sso-login-ui"))
	log.Printf("removed launch agent and installed binary")
	return nil
}

func copyExecutable(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}

// renderPlist builds the LaunchAgent plist. --foreground is passed so the
// process runs in place (launchd supervises it) rather than self-daemonizing.
func renderPlist(binary, logPath string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>--foreground</string>
	</array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><false/>
	<key>LimitLoadToSessionType</key><string>Aqua</string>
	<key>StandardOutPath</key><string>%s</string>
	<key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, plistLabel, binary, logPath, logPath)
}
