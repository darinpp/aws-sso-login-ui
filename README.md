# aws-sso-login-ui

A macOS menu-bar app that keeps an AWS IAM Identity Center (SSO) session alive: it signs in via the browser using an authorization_code + PKCE flow, caches the token in the same format the AWS CLI uses (`~/.aws/sso/cache/`), and silently renews it in the background before it expires.

## Requirements

- macOS on Apple Silicon (arm64)
- An SSO instance configured in `~/.aws/config` (`sso_start_url` + `sso_region`)

## Install

1. Download the latest `aws-sso-login-ui-macos-arm64.zip` from [Releases](../../releases).
2. Unzip it, then remove the quarantine flag macOS puts on downloaded files (skipping this makes the binary refuse to run):
   ```
   xattr -d com.apple.quarantine aws-sso-login-ui
   ```
3. Register it to start automatically at login:
   ```
   ./aws-sso-login-ui --install
   ```
   This copies the binary to `~/.aws-sso-login-ui/`, registers a LaunchAgent, and starts it immediately. Logs go to `~/Library/Logs/aws-sso-login-ui.log`.

To remove it: `./aws-sso-login-ui --uninstall` (run from anywhere, using either the downloaded copy or the installed one).

## Usage

The menu-bar icon is a moon phase showing how much of the current token's lifetime is left (🌕 fresh → 🌑 about to expire), 🚫 for no session/error, 📡 for offline/retrying. Click it for:

- **Login** — re-authenticate now (opens the browser)
- **Renew** — manually trigger a silent renewal (test helper)
- **Force Expire** — mark the current token expired, for testing
- **Quit**

## Running without installing

- `--foreground` — run in place, logs to the terminal
- `--test-auth` — one-shot CLI login test, no menu bar
