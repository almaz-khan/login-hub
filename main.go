package main

// Entry point. `hub` serves (configuration: README «Настройка»); the subcommands are tools for
// the Mac:
//
//	hub keygen            a new HUB_SIGNING_KEY and its kid
//	hub secret            a new client secret and the secret_sha256 for access.json
//	hub check [file]      checks access.json (default config/access.json), as the server would

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) > 1 {
		os.Exit(tool(os.Args[1:]))
	}
	env := func(k, fallback string) string { return or(os.Getenv(k), fallback) }
	accessFile := env("ACCESS_FILE", "/srv/access.json")
	access, err := loadAccess(accessFile)
	if err != nil {
		err = fmt.Errorf("%s: %w", accessFile, err)
	}
	handler := newApp(Config{
		Access:        access,
		AccessErr:     err,
		ClientID:      os.Getenv("TG_CLIENT_ID"),
		ClientSecret:  os.Getenv("TG_CLIENT_SECRET"),
		Audience:      os.Getenv("TG_AUDIENCE"),
		SessionSecret: os.Getenv("SESSION_SECRET"),
		PublicURL:     os.Getenv("PUBLIC_URL"),
		SigningKey:    os.Getenv("HUB_SIGNING_KEY"),
		SigningKeyOld: os.Getenv("HUB_SIGNING_KEY_OLD"),
		BotToken:      os.Getenv("TG_BOT_TOKEN"),
	})
	srv := &http.Server{Addr: ":" + env("PORT", "8080"), Handler: handler, ReadHeaderTimeout: 10 * time.Second}

	// On SIGTERM (a redeploy) stop taking connections, finish the requests in flight and the bot
	// messages still sending, then exit. Codes in memory are lost: those logins start again.
	done := make(chan struct{})
	go func() {
		defer close(done)
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
		handler.waitNotify(ctx)
	}()
	if access != nil {
		log.Printf("listening on %s, %d apps, %d people", srv.Addr, len(access.Apps), len(access.People))
	}
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	<-done // ListenAndServe returns as soon as Shutdown starts, not when it ends
}

func tool(args []string) int {
	switch args[0] {
	case "keygen":
		seed := make([]byte, ed25519.SeedSize)
		_, _ = rand.Read(seed)
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		fmt.Printf("HUB_SIGNING_KEY=%s\nkid: %s\n", base64.StdEncoding.EncodeToString(seed), kidOf(pub))
		return 0
	case "secret":
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		secret := hex.EncodeToString(b) // hex: nothing to escape in Basic auth or a shell
		sum := sha256.Sum256([]byte(secret))
		fmt.Printf("OIDC_CLIENT_SECRET=%s   (the app's Railway variable only)\nsecret_sha256: %s   (access.json)\n", secret, hex.EncodeToString(sum[:]))
		return 0
	case "check":
		file := "config/access.json"
		if len(args) > 1 {
			file = args[1]
		}
		a, err := loadAccess(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", file, err)
			return 1
		}
		fmt.Printf("%s: ok, %d apps, %d people\n", file, len(a.Apps), len(a.People))
		for id, c := range a.Apps {
			fmt.Printf("  %s (%s): %d people\n", id, c.Name, len(c.allowed))
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, "usage: hub [keygen | secret | check [file]]")
	return 2
}
