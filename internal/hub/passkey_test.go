package hub

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// enroll: a passkey for person, registered through go-webauthn as enrollment will do it
func (e *env) enroll(person string) *softAuthenticator {
	e.t.Helper()
	a := e.app.Load()
	p, err := e.cfg.Store.Person(person)
	if err != nil || p == nil {
		e.t.Fatal(person, err)
	}
	u, err := a.waUser(p)
	if err != nil {
		e.t.Fatal(err)
	}
	opts, session, err := a.wa.BeginRegistration(u,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}))
	if err != nil {
		e.t.Fatal(err)
	}
	soft := newSoftAuthenticator(e.url, "localhost")
	parsed, err := protocol.ParseCredentialCreationResponseBytes(soft.register(opts))
	if err != nil {
		e.t.Fatal(err)
	}
	cred, err := a.wa.CreateCredential(u, *session, parsed)
	if err != nil {
		e.t.Fatal(err)
	}
	data, _ := json.Marshal(cred)
	if err := e.cfg.Store.AddPasskey(person, cred.ID, data, "test", "test"); err != nil {
		e.t.Fatal(err)
	}
	return soft
}

func (b *browser) postJSON(u string, v any, headers ...string) *http.Response {
	body, _ := json.Marshal(v)
	req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := b.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	b.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// options: a login challenge, as the page's script asks for it
func (e *env) options(b *browser) (string, *protocol.CredentialAssertion) {
	e.t.Helper()
	resp := b.postJSON(e.url+"/login/passkey/options", map[string]any{})
	var o struct {
		Challenge string                        `json:"challenge"`
		Options   *protocol.CredentialAssertion `json:"options"`
	}
	if err := json.Unmarshal([]byte(body(resp)), &o); err != nil || resp.StatusCode != http.StatusOK {
		e.t.Fatalf("options: %d %v", resp.StatusCode, err)
	}
	return o.Challenge, o.Options
}

// passkey: the whole passkey login with soft, then on to next; the verify response
func (e *env) passkey(b *browser, soft *softAuthenticator, next string) *http.Response {
	e.t.Helper()
	challenge, opts := e.options(b)
	return b.postJSON(e.url+"/login/passkey/verify", map[string]any{"challenge": challenge, "next": next, "credential": json.RawMessage(soft.authenticate(opts))})
}

func nextOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	var out struct {
		Next  string `json:"next"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal([]byte(body(resp)), &out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("passkey login: %d %s", resp.StatusCode, out.Error)
	}
	return out.Next
}

func TestPasskeyLogin(t *testing.T) {
	e := setup(t)
	soft := e.enroll("Alice")
	b := e.browser()
	b.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	pk := e.rp("pk")
	a := pk.start()
	loc, err := b.get(a.url).Location() // a passkey-only app with no session: the passkey page
	if err != nil || loc.Path != "/login/passkey" {
		t.Fatalf("to the passkey page: %v", loc)
	}
	page := b.get(loc.String())
	if csp := page.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'sha256-") || !strings.Contains(csp, "connect-src 'self'") || !strings.Contains(body(page), `data-next="/authorize?`) {
		t.Fatalf("passkey page: %s", csp)
	}
	next := nextOf(t, e.passkey(b, soft, loc.Query().Get("next")))
	if !strings.HasPrefix(next, "/authorize?") {
		t.Fatalf("next %q", next)
	}
	code := pk.back(b.get(e.url+next), a)
	idt, err := pk.exchange(code, a)
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		AMR        []string `json:"amr"`
		TelegramID string   `json:"telegram_id"`
		Username   string   `json:"preferred_username"`
	}
	_ = idt.Claims(&c)
	if idt.Subject != "Alice" || strings.Join(c.AMR, ",") != "passkey" || c.TelegramID != alice || c.Username != "" {
		t.Fatalf("token: %s %+v", idt.Subject, c)
	}
	if e.tg.authCount() != 0 {
		t.Fatal("a passkey login went to Telegram")
	}
	var used int64
	_ = e.cfg.Store.DB().QueryRow(`SELECT last_used_at FROM passkeys WHERE person = 'Alice'`).Scan(&used)
	if used == 0 {
		t.Fatal("last_used_at not set")
	}

	// the same passkey session opens an app that accepts both, silently
	b.CheckRedirect = nil
	b2 := &browser{t: t, Client: &http.Client{Jar: b.Jar, CheckRedirect: e.browser().CheckRedirect}}
	e.rp("both").login(b2)
	// a Telegram-only app asks for Telegram on top
	resp := b2.get(e.rp("running-club").start().url)
	if page := body(resp); resp.StatusCode != http.StatusOK || !strings.Contains(page, "needs a sign-in with Telegram") || strings.Contains(page, "/login/passkey") {
		t.Fatalf("step-up to Telegram: %d %s", resp.StatusCode, page)
	}
	// both proven, for the same person: amr says both
	e.rp("running-club").stepUp(b2, "telegram")
	idt = e.rp("both").login(b2)
	_ = idt.Claims(&c)
	if strings.Join(c.AMR, ",") != "telegram,passkey" {
		t.Fatalf("amr %v", c.AMR)
	}
}

func TestPasskeyRefusals(t *testing.T) {
	e := setup(t)
	soft := e.enroll("Alice")
	b := e.browser()
	refused := func(name string, resp *http.Response, status int, want string) {
		t.Helper()
		page := body(resp)
		if resp.StatusCode != status || !strings.Contains(page, want) {
			t.Errorf("%s: %d %s", name, resp.StatusCode, page)
		}
		if strings.Contains(strings.Join(resp.Header.Values("Set-Cookie"), ";"), "hub_session=") {
			t.Errorf("%s: a session cookie", name)
		}
	}

	soft.forge = true
	refused("forged signature", e.passkey(b, soft, "/"), http.StatusForbidden, "couldn't be verified")
	soft.forge = false

	stranger := newSoftAuthenticator(e.url, "localhost")
	stranger.userHandle = []byte("x")
	refused("unknown credential", e.passkey(b, stranger, "/"), http.StatusForbidden, "isn't known here")

	for name, mod := range map[string]func(*softAuthenticator){
		"wrong origin": func(s *softAuthenticator) { s.origin = "https://evil.example" },
		"wrong RP ID":  func(s *softAuthenticator) { s.rpID = "evil.example" },
		"no UV":        func(s *softAuthenticator) { s.noUV = true },
	} {
		c := *soft
		mod(&c)
		refused(name, e.passkey(b, &c, "/"), http.StatusForbidden, "couldn't be verified")
	}

	// a challenge works once
	challenge, opts := e.options(b)
	answer := json.RawMessage(soft.authenticate(opts))
	ok := b.postJSON(e.url+"/login/passkey/verify", map[string]any{"challenge": challenge, "next": "/", "credential": answer})
	nextOf(t, ok)
	refused("replayed", b.postJSON(e.url+"/login/passkey/verify", map[string]any{"challenge": challenge, "next": "/", "credential": answer}), http.StatusBadRequest, "expired")

	// and for 5 minutes
	challenge, opts = e.options(b)
	e.shift.Add(int64((challengeTTL + time.Second) / time.Second))
	refused("expired", b.postJSON(e.url+"/login/passkey/verify", map[string]any{"challenge": challenge, "next": "/", "credential": json.RawMessage(soft.authenticate(opts))}), http.StatusBadRequest, "expired")
	e.shift.Store(0)

	// only the hub's own page may ask
	refused("cross-site options", b.postJSON(e.url+"/login/passkey/options", map[string]any{}, "Sec-Fetch-Site", "same-site"), http.StatusForbidden, "Only")
	refused("form post", b.post(e.url+"/login/passkey/options", url.Values{}, "Sec-Fetch-Site", "same-origin"), http.StatusForbidden, "Only")
	if resp := b.get(e.url + "/login/passkey/verify"); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET verify: %d", resp.StatusCode)
	}

	// next is checked like everywhere else
	if next := nextOf(t, e.passkey(b, soft, "https://evil.example/")); next != "/" {
		t.Errorf("next %q", next)
	}
}

func TestPasskeyHandleAltered(t *testing.T) {
	e := setup(t)
	soft := e.enroll("Alice")
	soft.overrideHandle = []byte("something a password manager made up")
	b := e.browser()
	nextOf(t, e.passkey(b, soft, "/"))
	if !strings.Contains(e.logs.String(), "user handle differs") {
		t.Fatal("not logged")
	}
}

func TestRemovedPasskeyEndsItsProof(t *testing.T) {
	e := setup(t)
	soft := e.enroll("Alice")
	b := e.browser()
	nextOf(t, e.passkey(b, soft, "/"))
	e.rp("both").login(b)
	e.exec(`DELETE FROM passkeys WHERE person = 'Alice'`)
	// the session cookie still has the proof, but the passkey behind it is gone
	resp := b.get(e.rp("both").start().url)
	if page := body(resp); resp.StatusCode != http.StatusOK || !strings.Contains(page, "Sign in to “Both”") || strings.Contains(page, "You're signed in") {
		t.Fatalf("after removal: %d %s", resp.StatusCode, page)
	}
}

func TestProofsOfTwoPeopleDontMix(t *testing.T) {
	e := setup(t)
	soft := e.enroll("Alice")
	e.tg.as(bob, "Bob", "bob")
	b := e.browser()
	e.rp("stub").login(b)              // Bob, by Telegram
	nextOf(t, e.passkey(b, soft, "/")) // then Alice's passkey on the same browser
	if page := body(b.get(e.url + "/")); !strings.Contains(page, "<b>Alice</b>, with passkey") {
		t.Fatalf("home: %s", page)
	}
	// Bob's Telegram proof is gone: a Telegram-only app asks again rather than letting Alice in as Bob
	before := e.tg.authCount()
	idt := e.rp("stub").stepUp(b, "telegram")
	if e.tg.authCount() != before+1 || idt.Subject != "Bob" {
		t.Fatalf("sub %s, telegram logins %d", idt.Subject, e.tg.authCount())
	}
	// and now the newer proof (Bob's Telegram) has replaced Alice's passkey
	if page := body(b.get(e.url + "/")); !strings.Contains(page, "<b>Bob</b> (@bob), with Telegram") {
		t.Fatalf("home after: %s", page)
	}
}
