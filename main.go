package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/darinpp/aws-sso-login-ui/app"
)

func main() {
	args := os.Args[1:]
	hasFlag := func(flag string) bool {
		for _, a := range args {
			if a == flag {
				return true
			}
		}
		return false
	}

	if hasFlag("--test-auth") {
		testAuth()
		return
	}

	// Unless --foreground is set, re-exec as a detached background process.
	if !hasFlag("--foreground") && !hasFlag("--daemon") {
		execPath, err := os.Executable()
		if err != nil {
			log.Fatalf("could not find executable path: %v", err)
		}
		daemonArgs := append([]string{"--daemon"}, args...)
		cmd := exec.Command(execPath, daemonArgs...)
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.Stdin = nil
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			log.Fatalf("failed to start background process: %v", err)
		}
		fmt.Printf("aws-sso-login-ui started (pid %d)\n", cmd.Process.Pid)
		os.Exit(0)
	}

	// Handle SIGTERM/SIGINT for graceful shutdown in daemon mode
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received %s, shutting down...", sig)
		app.Quit()
	}()

	app.Run()
}

func testAuth() {
	log.SetFlags(log.Ltime)

	instances, err := app.ParseSSOInstances()
	if err != nil {
		log.Fatalf("Failed to parse SSO instances: %v", err)
	}

	fmt.Printf("Found %d SSO instance(s):\n", len(instances))
	for i, inst := range instances {
		fmt.Printf("  %d. %s (%s)\n", i+1, inst.StartURL, inst.Region)
	}

	inst := instances[0]
	fmt.Printf("\nTesting auth for: %s\n", inst.StartURL)

	// Check existing token
	if token, err := app.LoadToken(inst.StartURL); err == nil {
		if token.IsExpired() {
			fmt.Printf("Existing token is EXPIRED (was valid until %s)\n", token.ExpiresAt)
		} else {
			fmt.Printf("Existing token is VALID (%s remaining)\n", token.TimeRemaining().Round(time.Second))
			fmt.Println("Proceeding with fresh auth anyway...")
		}
	} else {
		fmt.Println("No cached token found")
	}

	fmt.Println("\nStarting authentication (browser should open)...")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	token, err := app.Authenticate(ctx, inst)
	if err != nil {
		log.Fatalf("Authentication FAILED: %v", err)
	}

	fmt.Println("\nAuthentication SUCCEEDED!")
	fmt.Printf("  Access token: %s...%s\n", token.AccessToken[:8], token.AccessToken[len(token.AccessToken)-4:])
	fmt.Printf("  Expires at:   %s\n", token.ExpiresAt)
	fmt.Printf("  Remaining:    %s\n", token.TimeRemaining().Round(time.Second))
	fmt.Printf("  Has refresh:  %v\n", token.RefreshToken != "")
	fmt.Printf("  Saved to:     %s\n", app.TokenCacheFile(inst.StartURL))
}
