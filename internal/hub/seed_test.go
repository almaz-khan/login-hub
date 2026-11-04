package hub

import (
	"bytes"
	"database/sql"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hub/internal/store"
)

func TestHubSeed(t *testing.T) {
	var logs bytes.Buffer
	cfg := Config{SessionSecret: strings.Repeat("s", 32), ClientID: "1", ClientSecret: "2", PublicURL: "https://login.example", SigningKey: keyA, Log: log.New(&logs, "", 0)}

	cfg.Store, cfg.Seed = emptyStore(t), []byte(seedJSON())
	if a := New(cfg); len(a.missing) > 0 {
		t.Fatal(a.missing)
	}
	if !strings.Contains(logs.String(), "seeded: 3 people, 5 apps") {
		t.Fatal(logs.String())
	}
	// the next start with the variable still set: ignored, said so
	logs.Reset()
	if a := New(cfg); len(a.missing) > 0 || !strings.Contains(logs.String(), "HUB_SEED ignored") {
		t.Fatalf("%v %s", a.missing, logs.String())
	}
	// a broken seed on an empty database: nothing served, nothing written
	cfg.Store, cfg.Seed = emptyStore(t), []byte(strings.Replace(seedJSON(), `"group:club"`, `"group:nope"`, 1))
	if a := New(cfg); len(a.missing) == 0 || !strings.Contains(strings.Join(a.missing, ""), "HUB_SEED: ") {
		t.Fatalf("broken seed: %v", a.missing)
	}
	if n, _ := cfg.Store.Count("people"); n != 0 {
		t.Fatal("a refused seed wrote people")
	}
}

func TestUnknownTelegramAccount(t *testing.T) {
	e := setup(t)
	e.tg.as(dave, "Dave", "dave")
	b := e.browser()
	resp := b.get(e.rp("running-club").start().url)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body(resp), "@dave") {
		t.Fatalf("unknown account: %d", resp.StatusCode)
	}
	e.app.Load().wg.Wait()
	if m := e.bot.messages(); len(m) != 1 || !strings.Contains(m[0]["text"].(string), "Not in the hub") {
		t.Fatalf("bot: %v", m)
	}
	// once the admin adds them, the same hub session works
	e.exec(`INSERT INTO people (key, name, telegram_id, created_at) VALUES ('Dave', 'Dave', ?, 0)`, dave)
	e.exec(`INSERT INTO app_access (app, person) VALUES ('running-club', 'Dave')`)
	if idt := e.rp("running-club").login(b); idt.Subject != "Dave" {
		t.Fatal(idt.Subject)
	}
	var seen sql.NullInt64
	_ = e.cfg.Store.DB().QueryRow(`SELECT last_seen_at FROM people WHERE key = 'Dave'`).Scan(&seen)
	if !seen.Valid {
		t.Fatal("last_seen_at not set")
	}
}

func TestBackup(t *testing.T) {
	e := setup(t)
	u := e.url + "/admin/backup"
	anon := e.browser()
	for name, h := range map[string][]string{
		"nothing":     nil,
		"wrong token": {"Authorization", "Bearer " + strings.Repeat("x", 40)},
		"short token": {"Authorization", "Bearer abc"},
	} {
		if resp := anon.get(u, h...); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	check := func(resp *http.Response) {
		t.Helper()
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/vnd.sqlite3" {
			t.Fatalf("backup: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		path := filepath.Join(t.TempDir(), "copy.db")
		if err := os.WriteFile(path, []byte(body(resp)), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := store.Open(path, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		if n, _ := s.Count("people"); n != 3 {
			t.Fatalf("backup has %d people", n)
		}
	}
	check(anon.get(u, "Authorization", "Bearer "+backupToken))

	// the admin, logged in: a typed URL or a link on the hub, not another site's
	admin := e.adminBrowser()
	check(admin.get(u, "Sec-Fetch-Site", "none"))
	if resp := admin.get(u, "Sec-Fetch-Site", "cross-site"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site: %d", resp.StatusCode)
	}
	// someone else, logged in
	e.tg.as(bob, "Bob", "bob")
	other := e.browser()
	e.rp("stub").login(other)
	if resp := other.get(u); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("not admin: %d", resp.StatusCode)
	}
	// no temporary copies left next to the database
	entries, _ := os.ReadDir(filepath.Dir(e.cfg.Store.Path()))
	for _, en := range entries {
		if strings.HasPrefix(en.Name(), ".backup-") {
			t.Fatalf("left behind: %s", en.Name())
		}
	}
}
