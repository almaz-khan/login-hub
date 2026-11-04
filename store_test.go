package main

import (
	"bytes"
	"database/sql"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeedChecks(t *testing.T) {
	good := seedJSON()
	if _, err := parseSeed([]byte(good)); err != nil {
		t.Fatal(err)
	}
	rcHash := `"secret_sha256":"` + sha(secrets["running-club"]) + `"`
	for name, c := range map[string]struct{ from, to, want string }{
		"unknown person":    {`"allow":["group:club"]`, `"allow":["Zed"]`, `"Zed" is not in people`},
		"unknown group":     {`"allow":["group:club"]`, `"allow":["group:nope"]`, `unknown group "nope"`},
		"group member":      {`"club":["Alice"]`, `"club":["Zed"]`, `groups.club: "Zed" is not in people`},
		"http redirect":     {`http://localhost:1/auth/callback`, `http://running.example/auth/callback`, `is not https`},
		"fragment":          {`http://localhost:1/auth/callback`, `https://running.example/auth/callback#x`, `has a fragment`},
		"relative redirect": {`http://localhost:1/auth/callback`, `/auth/callback`, `not an absolute URL`},
		"no secret":         {rcHash, `"secret_sha256":""`, `secret_sha256`},
		"upper hex secret":  {rcHash, strings.ToUpper(rcHash), `secret_sha256`},
		"misspelt key":      {`"allow":["group:club"]`, `"allows":["group:club"]`, `unknown field "allows"`},
		"notify outsider":   {`"notify":"Alice"`, `"notify":"Zed"`, `notify: "Zed"`},
		"notify no tg":      {`"name":"Кэрол","telegram":"333"`, `"name":"Кэрол"`, ``},
		"bad client id":     {`"running-club":{`, `"Running Club":{`, `bad client id`},
		"bad person key":    {`"Carol":{`, `"Carol Smith":{`, `bad key "Carol Smith"`},
		"same telegram":     {`"telegram":"333"`, `"telegram":"222"`, `Bob and Carol have the same Telegram id`},
		"bad telegram":      {`"telegram":"333"`, `"telegram":"@carol"`, `is not a Telegram id`},
		"unknown method":    {`"login":["telegram"]`, `"login":["sms"]`, `unknown method "sms"`},
		"not json":          {`{`, `[`, `invalid character`},
	} {
		raw := strings.Replace(good, c.from, c.to, 1)
		if raw == good {
			t.Fatalf("%s: %q not in the seed", name, c.from)
		}
		_, err := parseSeed([]byte(raw))
		if c.want == "" { // allowed
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a notify person without a Telegram id can't be messaged
	raw := strings.Replace(strings.Replace(good, `"notify":"Alice"`, `"notify":"Carol"`, 1), `"name":"Кэрол","telegram":"333"`, `"name":"Кэрол"`, 1)
	if _, err := parseSeed([]byte(raw)); err == nil || !strings.Contains(err.Error(), "no Telegram id") {
		t.Errorf("notify without telegram: %v", err)
	}
}

func TestStoreReopenAndVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	s, err := openStore(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := parseSeed([]byte(seedJSON()))
	if err := s.Import(f, "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.Import(f, "test"); err == nil {
		t.Fatal("a second import into a full database")
	}
	_ = s.Close()

	s, err = openStore(path, nil) // migrations already applied: nothing to do, data still there
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := s.PersonByTelegram(alice); p == nil || p.Key != "Alice" || p.Name != "Алиса" {
		t.Fatalf("after reopen: %+v", p)
	}
	var v int
	_ = s.db.QueryRow(`PRAGMA user_version`).Scan(&v)
	if v != len(migrations) {
		t.Fatalf("user_version %d", v)
	}
	// a database from a newer hub is refused, not half-understood
	_, _ = s.db.Exec(`PRAGMA user_version = 99`)
	_ = s.Close()
	if _, err := openStore(path, nil); err == nil || !strings.Contains(err.Error(), "older hub") {
		t.Fatalf("newer database: %v", err)
	}
}

func TestCorruptDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	if err := os.WriteFile(path, bytes.Repeat([]byte("not a database "), 500), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openStore(path, nil); err == nil {
		t.Fatal("garbage opened as a database")
	}
}

func TestAccessQueriesAndCascades(t *testing.T) {
	s := testStore(t, seedJSON())
	for _, c := range []struct {
		app, person string
		want        bool
	}{
		{"running-club", "Alice", true}, // via group:club
		{"running-club", "Bob", false},
		{"stub", "Bob", true}, // directly
		{"stub", "Carol", false},
		{"nope", "Alice", false},
	} {
		if got, err := s.Allowed(c.app, c.person); err != nil || got != c.want {
			t.Errorf("%s %s: %v %v", c.app, c.person, got, err)
		}
	}
	c, err := s.App("running-club")
	if err != nil || c == nil || c.Name != "Running Club Wrapped" || !c.redirects[appURL("running-club")+"/auth/callback"] || !c.logouts[appURL("running-club")+"/"] || !c.Telegram || c.Passkey || len(c.secretHash) != 32 {
		t.Fatalf("app: %+v %v", c, err)
	}
	if c, err := s.App("nope"); c != nil || err != nil {
		t.Fatalf("unknown app: %+v %v", c, err)
	}
	// deleting a person takes their access and group places with them
	if _, err := s.db.Exec(`DELETE FROM people WHERE key = 'Bob'`); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.db.QueryRow(`SELECT count(*) FROM app_access WHERE person = 'Bob'`).Scan(&n)
	if n != 0 {
		t.Fatal("access rows outlived the person")
	}
	// a group renamed keeps its members and its access
	if _, err := s.db.Exec(`UPDATE groups SET name = 'runners' WHERE name = 'club'`); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Allowed("running-club", "Alice"); !ok {
		t.Fatal("rename lost access")
	}
	// access rows name a person or a group, not both, not neither
	if _, err := s.db.Exec(`INSERT INTO app_access (app) VALUES ('stub')`); err == nil {
		t.Fatal("an empty access row")
	}
	// an app needs at least one login method
	if _, err := s.db.Exec(`UPDATE apps SET login_telegram = 0 WHERE id = 'stub'`); err == nil {
		t.Fatal("an app nobody can log in to")
	}
	var audit string
	_ = s.db.QueryRow(`SELECT action || ' ' || detail FROM audit`).Scan(&audit)
	if audit != "import 3 people, 1 groups, 5 apps" {
		t.Fatal(audit)
	}
}

func TestHubSeed(t *testing.T) {
	var logs bytes.Buffer
	cfg := Config{SessionSecret: strings.Repeat("s", 32), ClientID: "1", ClientSecret: "2", PublicURL: "https://login.example", SigningKey: keyA, Log: log.New(&logs, "", 0)}

	cfg.Store, cfg.Seed = emptyStore(t), []byte(seedJSON())
	if a := newApp(cfg); len(a.missing) > 0 {
		t.Fatal(a.missing)
	}
	if !strings.Contains(logs.String(), "seeded: 3 people, 5 apps") {
		t.Fatal(logs.String())
	}
	// the next start with the variable still set: ignored, said so
	logs.Reset()
	if a := newApp(cfg); len(a.missing) > 0 || !strings.Contains(logs.String(), "HUB_SEED ignored") {
		t.Fatalf("%v %s", a.missing, logs.String())
	}
	// a broken seed on an empty database: nothing served, nothing written
	cfg.Store, cfg.Seed = emptyStore(t), []byte(strings.Replace(seedJSON(), `"group:club"`, `"group:nope"`, 1))
	if a := newApp(cfg); len(a.missing) == 0 || !strings.Contains(strings.Join(a.missing, ""), "HUB_SEED: ") {
		t.Fatalf("broken seed: %v", a.missing)
	}
	if n, _ := cfg.Store.count("people"); n != 0 {
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
	if m := e.bot.messages(); len(m) != 1 || !strings.Contains(m[0]["text"].(string), "такого человека нет") {
		t.Fatalf("bot: %v", m)
	}
	// once the admin adds them, the same hub session works
	e.exec(`INSERT INTO people (key, name, telegram_id, created_at) VALUES ('Dave', 'Дэйв', ?, 0)`, dave)
	e.exec(`INSERT INTO app_access (app, person) VALUES ('running-club', 'Dave')`)
	if idt := e.rp("running-club").login(b); idt.Subject != "Dave" {
		t.Fatal(idt.Subject)
	}
	var seen sql.NullInt64
	_ = e.cfg.Store.db.QueryRow(`SELECT last_seen_at FROM people WHERE key = 'Dave'`).Scan(&seen)
	if !seen.Valid {
		t.Fatal("last_seen_at not set")
	}
}

func TestBackup(t *testing.T) {
	e := setup(t)
	u := e.srv.URL + "/admin/backup"
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
		s, err := openStore(path, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		if n, _ := s.count("people"); n != 3 {
			t.Fatalf("backup has %d people", n)
		}
	}
	check(anon.get(u, "Authorization", "Bearer "+backupToken))

	// the admin, logged in: a typed URL or a link on the hub, not another site's
	admin := e.browser()
	e.rp("running-club").login(admin)
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
	entries, _ := os.ReadDir(filepath.Dir(e.cfg.Store.path))
	for _, en := range entries {
		if strings.HasPrefix(en.Name(), ".backup-") {
			t.Fatalf("left behind: %s", en.Name())
		}
	}
}
