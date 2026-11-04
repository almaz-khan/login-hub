package main

// The hub's binary. `hub` serves (configuration: README «Настройка»); the subcommands are tools
// for the Mac (`go run ./cmd/hub <tool>`):
//
//	hub keygen                     a new HUB_SIGNING_KEY and its kid
//	hub secret                     a new client secret and the secret_sha256 for the app
//	hub check [seed.json]          checks a seed (default private/seed.json), as the server would
//	hub import [-db file] seed.json  a seed into an empty database (default ./data/hub.db)

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"hub/internal/hub"
	"hub/internal/store"
)

func main() {
	if len(os.Args) > 1 {
		os.Exit(tool(os.Args[1:]))
	}
	env := func(k, fallback string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return fallback
	}
	dbFile := filepath.Join(env("DATA_DIR", "/data"), "hub.db")
	db, err := store.Open(dbFile, nil)
	if err != nil {
		err = fmt.Errorf("%s: %w", dbFile, err)
	} else {
		defer func() { _ = db.Close() }()
	}
	handler := hub.New(hub.Config{
		Store:         db,
		StoreErr:      err,
		Seed:          []byte(os.Getenv("HUB_SEED")),
		Admin:         os.Getenv("HUB_ADMIN"),
		BackupToken:   os.Getenv("HUB_BACKUP_TOKEN"),
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
		handler.WaitNotify(ctx)
	}()
	log.Printf("listening on %s", srv.Addr)
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
		fmt.Printf("HUB_SIGNING_KEY=%s\nkid: %s\n", base64.StdEncoding.EncodeToString(seed), hub.KeyID(pub))
		return 0
	case "secret":
		secret, sum := store.NewClientSecret()
		fmt.Printf("OIDC_CLIENT_SECRET=%s   (the app's Railway variable only)\nsecret_sha256: %s   (the seed, or the admin UI makes one itself)\n", secret, hex.EncodeToString(sum))
		return 0
	case "check":
		file := "private/seed.json"
		if len(args) > 1 {
			file = args[1]
		}
		f, err := readSeed(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", file, err)
			return 1
		}
		fmt.Printf("%s: ok, %d people, %d groups, %d apps\n", file, len(f.People), len(f.Groups), len(f.Apps))
		return 0
	case "import":
		fs := flag.NewFlagSet("import", flag.ContinueOnError)
		db := fs.String("db", "data/hub.db", "database file")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "usage: hub import [-db file] seed.json")
			return 2
		}
		f, err := readSeed(fs.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", fs.Arg(0), err)
			return 1
		}
		s, err := store.Open(*db, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", *db, err)
			return 1
		}
		defer func() { _ = s.Close() }()
		if err := s.Import(f, "hub import"); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", *db, err)
			return 1
		}
		fmt.Printf("%s: imported %d people, %d apps\n", *db, len(f.People), len(f.Apps))
		return 0
	}
	fmt.Fprintln(os.Stderr, "usage: hub [keygen | secret | check [seed.json] | import [-db file] seed.json]")
	return 2
}

func readSeed(file string) (*store.Seed, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return store.ParseSeed(raw)
}
