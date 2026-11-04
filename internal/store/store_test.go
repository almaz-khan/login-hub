package store

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeedChecks(t *testing.T) {
	good := seedJSON()
	if _, err := ParseSeed([]byte(good)); err != nil {
		t.Fatal(err)
	}
	rcHash := `"secret_sha256":"` + sha(secrets["running-club"]) + `"`
	for name, c := range map[string]struct{ from, to, want string }{
		"unknown person":    {`"allow":["group:club"]`, `"allow":["Zed"]`, `"Zed" is not in people`},
		"unknown group":     {`"allow":["group:club"]`, `"allow":["group:nope"]`, `unknown group "nope"`},
		"group member":      {`"club":["Alice"]`, `"club":["Zed"]`, `groups.club: "Zed" is not in people`},
		"http redirect":     {`http://[::1]:1/auth/callback`, `http://running.example/auth/callback`, `is not https`},
		"fragment":          {`http://[::1]:1/auth/callback`, `https://running.example/auth/callback#x`, `has a fragment`},
		"relative redirect": {`http://[::1]:1/auth/callback`, `/auth/callback`, `not an absolute URL`},
		"no secret":         {rcHash, `"secret_sha256":""`, `secret_sha256`},
		"upper hex secret":  {rcHash, strings.ToUpper(rcHash), `secret_sha256`},
		"misspelt key":      {`"allow":["group:club"]`, `"allows":["group:club"]`, `unknown field "allows"`},
		"notify outsider":   {`"notify":"Alice"`, `"notify":"Zed"`, `notify: "Zed"`},
		"notify no tg":      {`"name":"Carol","telegram":"333"`, `"name":"Carol"`, ``},
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
		_, err := ParseSeed([]byte(raw))
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
	raw := strings.Replace(strings.Replace(good, `"notify":"Alice"`, `"notify":"Carol"`, 1), `"name":"Carol","telegram":"333"`, `"name":"Carol"`, 1)
	if _, err := ParseSeed([]byte(raw)); err == nil || !strings.Contains(err.Error(), "no Telegram id") {
		t.Errorf("notify without telegram: %v", err)
	}
}

func TestStoreReopenAndVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	s, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := ParseSeed([]byte(seedJSON()))
	if err := s.Import(f, "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.Import(f, "test"); err == nil {
		t.Fatal("a second import into a full database")
	}
	_ = s.Close()

	s, err = Open(path, nil) // migrations already applied: nothing to do, data still there
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := s.PersonByTelegram(alice); p == nil || p.Key != "Alice" || p.Name != "Alice" {
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
	if _, err := Open(path, nil); err == nil || !strings.Contains(err.Error(), "older hub") {
		t.Fatalf("newer database: %v", err)
	}
}

func TestCorruptDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	if err := os.WriteFile(path, bytes.Repeat([]byte("not a database "), 500), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, nil); err == nil {
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
	if err != nil || c == nil || c.Name != "Running Club Wrapped" || !c.Redirects[appURL("running-club")+"/auth/callback"] || !c.Logouts[appURL("running-club")+"/"] || !c.Telegram || c.Passkey || len(c.SecretHash) != 32 {
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
