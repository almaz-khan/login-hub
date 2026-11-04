package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestOneMethodGoesStraightToIt(t *testing.T) {
	e := setup(t)
	b := e.browser()
	b.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for app, method := range map[string]string{"running-club": "telegram", "pk": "passkey"} {
		a := e.rp(app).start()
		loc, err := b.get(a.url).Location()
		if err != nil || loc.Path != "/login/"+method || !strings.HasPrefix(loc.Query().Get("next"), "/authorize?") {
			t.Errorf("%s: %v", app, loc)
		}
	}
}

func TestChooserForBoth(t *testing.T) {
	e := setup(t)
	b := e.browser()
	resp := b.get(e.rp("both").start().url)
	page := body(resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, `href="/login/telegram?next=%2Fauthorize%3F`) || !strings.Contains(page, `href="/login/passkey?next=%2Fauthorize%3F`) || !strings.Contains(page, "Вход на «Both»") {
		t.Fatalf("chooser: %d %s", resp.StatusCode, page)
	}
	// with Telegram proven, an app that accepts both lets them through, amr says how
	e.rp("running-club").login(b)
	idt := e.rp("both").login(b)
	var c struct {
		AMR []string `json:"amr"`
	}
	_ = idt.Claims(&c)
	if strings.Join(c.AMR, ",") != "telegram" {
		t.Fatalf("amr %v", c.AMR)
	}
}

func TestStepUp(t *testing.T) {
	e := setup(t)
	b := e.browser()
	e.rp("running-club").login(b) // Telegram proven
	pk := e.rp("pk")
	resp := b.get(pk.start().url)
	page := body(resp)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Location") != "" || !strings.Contains(page, "нужен вход через passkey") || !strings.Contains(page, "<b>Алиса</b>") || strings.Contains(page, "/login/telegram") {
		t.Fatalf("step-up: %d %s", resp.StatusCode, page)
	}
	// prompt=none: the app hears it needs a login, nothing more
	a := pk.start(oauth2.SetAuthURLParam("prompt", "none"))
	if loc, _ := b.get(a.url).Location(); loc == nil || loc.Query().Get("error") != "login_required" {
		t.Fatalf("prompt=none: %v", loc)
	}
	if e.tg.authCount() != 1 {
		t.Fatal("step-up went to Telegram")
	}
}

func TestProofsExpire(t *testing.T) {
	e := setup(t)
	b := e.browser()
	rc := e.rp("running-club")
	rc.login(b)
	e.shift.Store(int64((sessionTTL + time.Hour) / time.Second))
	rc.login(b)
	if e.tg.authCount() != 2 {
		t.Fatalf("a proof older than %v still counted: %d logins", sessionTTL, e.tg.authCount())
	}
}

func TestHomeAndLoginPaths(t *testing.T) {
	e := setup(t)
	b := e.browser()
	if page := body(b.get(e.srv.URL + "/")); !strings.Contains(page, "Один вход на все сайты") {
		t.Fatal(page)
	}
	e.rp("running-club").login(b)
	if page := body(b.get(e.srv.URL + "/")); !strings.Contains(page, "<b>Алиса</b> (@alice), через Telegram") {
		t.Fatal(page)
	}
	// /login itself is gone: each method has its own path
	if resp := b.get(e.srv.URL + "/login?next=" + url.QueryEscape("/authorize?x")); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/login: %d", resp.StatusCode)
	}
}
