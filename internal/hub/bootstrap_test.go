package hub

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestTelegramOff(t *testing.T) {
	e := setup(t, func(c *Config) { c.ClientID, c.ClientSecret = "", "" })
	b := e.browser()
	// a Telegram-only app: nothing to offer, said plainly
	resp := b.get(e.rp("running-club").start().url)
	if page := body(resp); resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(page, "Telegram пока выключен") {
		t.Fatalf("telegram-only app: %d %s", resp.StatusCode, page)
	}
	if resp := b.get(e.url + "/login/telegram?next=/"); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/login/telegram: %d", resp.StatusCode)
	}
	// an app that takes either goes straight to the passkey login
	b.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if loc, _ := b.get(e.rp("both").start().url).Location(); loc == nil || loc.Path != "/login/passkey" {
		t.Fatalf("both: %v", loc)
	}
	// and passkeys work as ever
	soft := e.enroll("Alice")
	b.CheckRedirect = e.browser().CheckRedirect
	nextOf(t, e.passkey(b, soft, "/"))
	if idt := e.rp("both").login(b); idt.Subject != "Alice" {
		t.Fatal(idt.Subject)
	}
	if e.tg.authCount() != 0 {
		t.Fatal("went to Telegram")
	}
}

func TestTelegramHalfConfigured(t *testing.T) {
	cfg := Config{SessionSecret: strings.Repeat("s", 32), ClientID: "1", PublicURL: "https://login.example", SigningKey: keyA, Store: testStore(t, seedJSON()), Log: log.New(&bytes.Buffer{}, "", 0)}
	a := New(cfg)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://login.example/healthz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("only TG_CLIENT_ID: %d", w.Code)
	}
}

func TestSeedWithoutApps(t *testing.T) {
	var logs bytes.Buffer
	seed := `{"people":{"Admin":{"name":"Админ"}}}`
	cfg := Config{SessionSecret: strings.Repeat("s", 32), PublicURL: "https://login.example", SigningKey: keyA, Store: emptyStore(t), Seed: []byte(seed), Admin: "Admin", Log: log.New(&logs, "", 0)}
	a := New(cfg)
	if len(a.missing) > 0 {
		t.Fatalf("a seed with people and no apps: %v", a.missing)
	}
	// the admin has no passkey and there is no Telegram: the log has the way in
	m := regexp.MustCompile(`Make one here \(single use, 24 h\): https://login\.example/enroll\?t=([\w-]+)`).FindStringSubmatch(logs.String())
	if m == nil {
		t.Fatal(logs.String())
	}
	if who, _ := cfg.Store.Enrollment(m[1]); who != "Admin" {
		t.Fatalf("link for %q", who)
	}
}

func TestAdminLinkOnlyWithoutPasskey(t *testing.T) {
	e := setup(t)
	if !strings.Contains(e.logs.String(), "Alice has no passkey yet") {
		t.Fatal(e.logs.String())
	}
	e.enroll("Alice")
	before := e.logs.String()
	e.reconfigure()
	if strings.Contains(strings.TrimPrefix(e.logs.String(), before), "no passkey yet") {
		t.Fatal("a link for an admin who has a passkey")
	}
}
