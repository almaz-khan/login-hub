package main

// The hub runs as a real HTTP server against a fake Telegram, and the apps are played by go-oidc
// and golang.org/x/oauth2, the same libraries a Go app uses, so discovery, JWKS, PKCE, the code
// exchange and ID token checks are tested the way apps will see them.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

const (
	tgClient = "7000000001"
	tgSecret = "tg-secret"
	botToken = "123:TEST-BOT-TOKEN"

	alice = "111" // in club: running-club and stub
	bob   = "222" // stub only
	carol = "333" // nobody's
)

// app secrets (hex, as `hub secret` makes them); "plus" has one that needs form-encoding
var secrets = map[string]string{
	"running-club": strings.Repeat("ab", 32),
	"stub":         strings.Repeat("cd", 32),
	"plus":         "a+b/c=d",
}

func appURL(client string) string {
	port := map[string]string{"running-club": "1", "stub": "2", "plus": "3"}[client]
	return "http://localhost:" + port
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func accessJSON(allowRC ...string) string {
	if allowRC == nil {
		allowRC = []string{"group:club"}
	}
	apps := map[string]any{}
	for id, allow := range map[string][]string{"running-club": allowRC, "stub": {"group:club", bob}, "plus": {alice}} {
		apps[id] = map[string]any{
			"name":                      map[string]string{"running-club": "Running Club Wrapped", "stub": "Stub", "plus": "Plus"}[id],
			"redirect_uris":             []string{appURL(id) + "/auth/callback"},
			"post_logout_redirect_uris": []string{appURL(id) + "/"},
			"secret_sha256":             sha(secrets[id]),
			"allow":                     allow,
		}
	}
	b, _ := json.Marshal(map[string]any{
		"notify": alice,
		"people": map[string]string{alice: "Alice", bob: "Bob", carol: "Carol"},
		"groups": map[string][]string{"club": {alice}},
		"apps":   apps,
	})
	return string(b)
}

// fakeTG plays oauth.telegram.org: /auth logs in `user` at once, /token checks Basic auth and PKCE
type fakeTG struct {
	*httptest.Server
	key      *rsa.PrivateKey
	mu       sync.Mutex
	user     map[string]any
	auths    int
	nonce    map[string]string // code → nonce, challenge
	chal     map[string]string
	badNonce bool
}

func newFakeTG(t *testing.T) *fakeTG {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTG{key: key, nonce: map[string]string{}, chal: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		q := r.URL.Query()
		f.auths++
		code := "code-" + random()
		f.nonce[code], f.chal[code] = q.Get("nonce"), q.Get("code_challenge")
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+q.Get("state"), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		user, pass, ok := r.BasicAuth()
		_ = r.ParseForm()
		code := r.PostForm.Get("code")
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		switch {
		case !ok || user != tgClient || pass != tgSecret:
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		case f.chal[code] == "" || b64.EncodeToString(sum[:]) != f.chal[code]:
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		default:
			claims := map[string]any{"iss": f.URL, "aud": tgClient, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": f.nonce[code]}
			if f.badNonce {
				claims["nonce"] = "other"
			}
			for k, v := range f.user {
				claims[k] = v
			}
			delete(f.chal, code)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "x", "token_type": "Bearer", "id_token": f.sign(t, claims)})
		}
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeTG) sign(t *testing.T, claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(claims)
	jws, err := signer.Sign(body)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := jws.CompactSerialize()
	return s
}

func (f *fakeTG) as(id, name, username string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.user = map[string]any{"sub": "tg-" + id, "id": json.Number(id), "name": name, "preferred_username": username}
}

func (f *fakeTG) authCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.auths
}

// fakeBot plays api.telegram.org and keeps every sendMessage it gets
type fakeBot struct {
	*httptest.Server
	mu   sync.Mutex
	sent []map[string]any
}

func newFakeBot(t *testing.T) *fakeBot {
	b := &fakeBot{}
	b.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		if r.URL.Path == "/bot"+botToken+"/sendMessage" {
			b.sent = append(b.sent, m)
		}
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(b.Close)
	return b
}

func (b *fakeBot) messages() []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]map[string]any(nil), b.sent...)
}

type env struct {
	t     *testing.T
	tg    *fakeTG
	bot   *fakeBot
	srv   *httptest.Server
	app   atomic.Pointer[app]
	cfg   Config
	logs  *syncBuffer
	shift atomic.Int64 // seconds added to the hub's clock
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

var keyA, keyB = seed(), seed()

func seed() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func setup(t *testing.T, mod ...func(*Config)) *env {
	e := &env{t: t, tg: newFakeTG(t), bot: newFakeBot(t), logs: &syncBuffer{}}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.app.Load().ServeHTTP(w, r) }))
	t.Cleanup(e.srv.Close)
	access, err := parseAccess([]byte(accessJSON()))
	if err != nil {
		t.Fatal(err)
	}
	e.cfg = Config{
		Access:        access,
		ClientID:      tgClient,
		ClientSecret:  tgSecret,
		SessionSecret: strings.Repeat("s", 32),
		PublicURL:     e.srv.URL,
		SigningKey:    keyA,
		BotToken:      botToken,
		TGBase:        e.tg.URL,
		BotAPI:        e.bot.URL,
		Log:           log.New(e.logs, "", 0),
		Now:           func() time.Time { return time.Now().Add(time.Duration(e.shift.Load()) * time.Second) },
	}
	e.reconfigure(mod...)
	e.tg.as(alice, "Alice A", "alice")
	return e
}

// reconfigure: a redeploy of the hub with a changed Config (same session secret unless changed)
func (e *env) reconfigure(mod ...func(*Config)) {
	for _, m := range mod {
		m(&e.cfg)
	}
	a := newApp(e.cfg)
	if len(a.missing) > 0 {
		e.t.Fatalf("not configured: %v", a.missing)
	}
	e.app.Store(a)
	e.t.Cleanup(func() { a.wg.Wait() })
}

func withAccess(t *testing.T, raw string) func(*Config) {
	return func(c *Config) {
		a, err := parseAccess([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		c.Access = a
	}
}

// browser: a cookie jar that follows redirects through the hub and Telegram and stops at an app
type browser struct {
	*http.Client
	t *testing.T
}

func (e *env) browser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: e.t, Client: &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Hostname() == "localhost" {
			return http.ErrUseLastResponse
		}
		return nil
	}}}
}

func (b *browser) get(u string, headers ...string) *http.Response {
	req, _ := http.NewRequest(http.MethodGet, u, nil)
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

func (b *browser) post(u string, form url.Values, headers ...string) *http.Response {
	req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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

func body(r *http.Response) string {
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

// rp: one app, as a Go app would set it up: discovery, oauth2 config, ID token verifier
type rp struct {
	e        *env
	id       string
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func (e *env) rp(id string) *rp {
	ctx := context.Background()
	p, err := oidc.NewProvider(ctx, e.srv.URL)
	if err != nil {
		e.t.Fatal(err)
	}
	ep := p.Endpoint()
	ep.AuthStyle = oauth2.AuthStyleInHeader // what the hub supports; auto-detect would retry without Basic and hide the error
	return &rp{e: e, id: id,
		oauth:    oauth2.Config{ClientID: id, ClientSecret: secrets[id], Endpoint: ep, RedirectURL: appURL(id) + "/auth/callback", Scopes: []string{oidc.ScopeOpenID, "profile"}},
		verifier: p.Verifier(&oidc.Config{ClientID: id, SupportedSigningAlgs: []string{oidc.EdDSA}}),
	}
}

type attempt struct {
	url, state, nonce, verifier string
}

func (r *rp) start(extra ...oauth2.AuthCodeOption) attempt {
	a := attempt{state: random(), nonce: random(), verifier: oauth2.GenerateVerifier()}
	opts := append([]oauth2.AuthCodeOption{oidc.Nonce(a.nonce), oauth2.S256ChallengeOption(a.verifier)}, extra...)
	a.url = r.oauth.AuthCodeURL(a.state, opts...)
	return a
}

// back: the app's callback the browser stopped at; the code after checking state and iss
func (r *rp) back(resp *http.Response, a attempt) string {
	r.e.t.Helper()
	loc, err := resp.Location()
	if err != nil {
		r.e.t.Fatalf("no redirect to the app: %d %.300s", resp.StatusCode, body(resp))
	}
	if !strings.HasPrefix(loc.String(), appURL(r.id)+"/auth/callback?") {
		r.e.t.Fatalf("redirect to %s, not to %s", loc, r.id)
	}
	q := loc.Query()
	if q.Get("state") != a.state || q.Get("iss") != r.e.srv.URL {
		r.e.t.Fatalf("state/iss: %v", q)
	}
	if q.Get("error") != "" {
		r.e.t.Fatalf("error from hub: %v", q)
	}
	return q.Get("code")
}

func (r *rp) exchange(code string, a attempt) (*oidc.IDToken, error) {
	ctx := context.Background()
	tok, err := r.oauth.Exchange(ctx, code, oauth2.VerifierOption(a.verifier))
	if err != nil {
		return nil, err
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := r.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	if idt.Nonce != a.nonce {
		return nil, fmt.Errorf("nonce %q", idt.Nonce)
	}
	return idt, nil
}

// login: the whole thing for app id, in browser b; the verified ID token
func (r *rp) login(b *browser) *oidc.IDToken {
	r.e.t.Helper()
	a := r.start()
	code := r.back(b.get(a.url), a)
	idt, err := r.exchange(code, a)
	if err != nil {
		r.e.t.Fatal(err)
	}
	return idt
}

func TestFlow(t *testing.T) {
	e := setup(t)
	b := e.browser()
	rc := e.rp("running-club")
	idt := rc.login(b)
	var c struct {
		Name     string `json:"name"`
		Username string `json:"preferred_username"`
		AuthTime int64  `json:"auth_time"`
	}
	_ = idt.Claims(&c)
	if idt.Subject != alice || idt.Audience[0] != "running-club" || c.Name != "Alice A" || c.Username != "alice" || c.AuthTime == 0 {
		t.Fatalf("token: sub %q aud %v claims %+v", idt.Subject, idt.Audience, c)
	}
	if left := time.Until(idt.Expiry); left > 5*time.Minute || left < 4*time.Minute {
		t.Fatalf("expiry in %v", left)
	}
	if e.tg.authCount() != 1 {
		t.Fatalf("telegram logins: %d", e.tg.authCount())
	}
	// a second app: straight back with a code, no Telegram
	stub := e.rp("stub")
	if idt := stub.login(b); idt.Subject != alice {
		t.Fatal(idt.Subject)
	}
	if e.tg.authCount() != 1 {
		t.Fatalf("second app went to Telegram: %d", e.tg.authCount())
	}
	// and the same app again later
	rc.login(b)
	if e.tg.authCount() != 1 {
		t.Fatal("third login went to Telegram")
	}
}

func TestBadClientOrRedirectNeverRedirects(t *testing.T) {
	e := setup(t)
	b := e.browser()
	rc := e.rp("running-club")
	rc.login(b) // with a session, too
	for name, mod := range map[string]func(url.Values){
		"unknown client": func(q url.Values) { q.Set("client_id", "evil") },
		"other redirect": func(q url.Values) { q.Set("redirect_uri", "https://evil.example/cb") },
		"another app's":  func(q url.Values) { q.Set("redirect_uri", appURL("stub")+"/auth/callback") },
		"trailing slash": func(q url.Values) { q.Set("redirect_uri", appURL("running-club")+"/auth/callback/") },
		"no redirect":    func(q url.Values) { q.Del("redirect_uri") },
		"twice":          func(q url.Values) { q.Add("redirect_uri", "https://evil.example/cb") },
	} {
		a := rc.start()
		u, _ := url.Parse(a.url)
		q := u.Query()
		mod(q)
		u.RawQuery = q.Encode()
		resp := b.get(u.String())
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" || !strings.Contains(body(resp), "Неверная ссылка") {
			t.Errorf("%s: %d %q", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

func TestAuthorizeErrorsGoBackToTheApp(t *testing.T) {
	e := setup(t)
	b := e.browser()
	rc := e.rp("running-club")
	for name, c := range map[string]struct {
		mod  func(url.Values)
		code string
	}{
		"no PKCE":       {func(q url.Values) { q.Del("code_challenge") }, "invalid_request"},
		"plain PKCE":    {func(q url.Values) { q.Set("code_challenge_method", "plain") }, "invalid_request"},
		"no nonce":      {func(q url.Values) { q.Del("nonce") }, "invalid_request"},
		"no openid":     {func(q url.Values) { q.Set("scope", "profile") }, "invalid_scope"},
		"token flow":    {func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type"},
		"fragment mode": {func(q url.Values) { q.Set("response_mode", "fragment") }, "invalid_request"},
		"prompt none":   {func(q url.Values) { q.Set("prompt", "none") }, "login_required"},
	} {
		a := rc.start()
		u, _ := url.Parse(a.url)
		q := u.Query()
		c.mod(q)
		u.RawQuery = q.Encode()
		loc, err := b.get(u.String()).Location()
		if err != nil || loc.Query().Get("error") != c.code || loc.Query().Get("state") != a.state || !strings.HasPrefix(loc.String(), appURL("running-club")) {
			t.Errorf("%s: %v", name, loc)
		}
	}
	// no state: still an error, back to the app
	a := rc.start()
	u, _ := url.Parse(a.url)
	q := u.Query()
	q.Del("state")
	u.RawQuery = q.Encode()
	if loc, _ := b.get(u.String()).Location(); loc == nil || loc.Query().Get("error") != "invalid_request" {
		t.Errorf("no state: %v", loc)
	}
	if e.tg.authCount() != 0 {
		t.Fatal("a refused request went to Telegram")
	}
}

func TestTokenRefusals(t *testing.T) {
	e := setup(t)
	b := e.browser()
	rc := e.rp("running-club")
	rc.login(b)
	fresh := func() (string, attempt) {
		a := rc.start()
		return rc.back(b.get(a.url), a), a
	}

	code, a := fresh()
	wrong := *rc
	wrong.oauth.ClientSecret = secrets["stub"]
	if _, err := wrong.exchange(code, a); err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("wrong secret: %v", err)
	}
	// the code survived the unauthenticated attempt
	if _, err := rc.exchange(code, a); err != nil {
		t.Fatalf("code spent by a wrong secret: %v", err)
	}
	// reused
	if _, err := rc.exchange(code, a); err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("reused code: %v", err)
	}

	code, a = fresh()
	bad := a
	bad.verifier = oauth2.GenerateVerifier()
	if _, err := rc.exchange(code, bad); err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("bad verifier: %v", err)
	}
	if _, err := rc.exchange(code, a); err == nil {
		t.Fatal("a code refused once still works")
	}

	code, a = fresh()
	e.shift.Add(61)
	if _, err := rc.exchange(code, a); err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("expired code: %v", err)
	}
	e.shift.Store(0)

	// running-club's code at stub's credentials
	code, a = fresh()
	stub := e.rp("stub")
	if _, err := stub.exchange(code, a); err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("another app's code: %v", err)
	}

	// other redirect_uri at /token
	code, a = fresh()
	other := *rc
	other.oauth.RedirectURL = appURL("running-club") + "/other"
	if _, err := other.exchange(code, a); err == nil {
		t.Fatal("redirect_uri differs, but accepted")
	}

	resp := b.get(e.srv.URL + "/token")
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "POST" {
		t.Fatalf("GET /token: %d %q", resp.StatusCode, resp.Header.Get("Allow"))
	}
}

func TestSecretEncodings(t *testing.T) {
	e := setup(t)
	b := e.browser()
	tg := e.tg
	tg.as(alice, "Alice", "")
	p := e.rp("plus") // oauth2 form-encodes «a+b/c=d» in Basic auth
	p.login(b)

	// a library that sends it as is
	a := p.start()
	code := p.back(b.get(a.url), a)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {p.oauth.RedirectURL}, "code_verifier": {a.verifier}}
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("plus", secrets["plus"])
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("raw secret: %d %s", resp.StatusCode, body(resp))
	}
}

func TestAccessPerApp(t *testing.T) {
	e := setup(t)
	e.tg.as(bob, "Bob B", "bob")
	b := e.browser()
	stub, rc := e.rp("stub"), e.rp("running-club")
	if idt := stub.login(b); idt.Subject != bob {
		t.Fatal(idt.Subject)
	}
	for i := 0; i < 2; i++ {
		a := rc.start()
		resp := b.get(a.url)
		page := body(resp)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(page, "Running Club Wrapped") || !strings.Contains(page, "@bob") || resp.Header.Get("Location") != "" {
			t.Fatalf("denied: %d %.300s", resp.StatusCode, page)
		}
		if !strings.Contains(page, `href="/login?next=%2Fauthorize%3F`) {
			t.Fatalf("no other-account button: %s", page)
		}
	}
	e.app.Load().wg.Wait()
	msgs := e.bot.messages()
	if len(msgs) != 1 || msgs[0]["chat_id"] != alice || !strings.Contains(msgs[0]["text"].(string), "Running Club Wrapped") || !strings.Contains(msgs[0]["text"].(string), "@bob") {
		t.Fatalf("bot messages: %v", msgs)
	}
	// still fine for stub, and an hour later a new attempt is reported again
	stub.login(b)
	e.shift.Add(3601)
	rc.start()
	b.get(rc.start().url)
	e.app.Load().wg.Wait()
	if len(e.bot.messages()) != 2 {
		t.Fatalf("after an hour: %d messages", len(e.bot.messages()))
	}
	// prompt=none: an error back to the app instead of the page
	a := rc.start(oauth2.SetAuthURLParam("prompt", "none"))
	if loc, _ := b.get(a.url).Location(); loc == nil || loc.Query().Get("error") != "access_denied" {
		t.Fatalf("prompt=none denied: %v", loc)
	}
}

func TestRemovedWithLiveSession(t *testing.T) {
	e := setup(t)
	b := e.browser()
	rc := e.rp("running-club")
	rc.login(b)
	// next deploy: Alice is out of running-club (allowed for nothing there but carol)
	e.reconfigure(withAccess(t, accessJSON(carol)))
	a := rc.start()
	if resp := b.get(a.url); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("removed person: %d", resp.StatusCode)
	}
	if e.tg.authCount() != 1 {
		t.Fatal("the hub session should still say who she is")
	}
}

func TestKeyRotation(t *testing.T) {
	e := setup(t)
	b := e.browser()
	rc := e.rp("running-club")
	a := rc.start()
	oldCode := rc.back(b.get(a.url), a) // issued before, spent after: signed with the new key

	ctx := context.Background()
	tok, err := rc.oauth.Exchange(ctx, oldCode, oauth2.VerifierOption(a.verifier))
	if err != nil {
		t.Fatal(err)
	}
	oldToken := tok.Extra("id_token").(string)

	// rotate: B signs, A still listed
	e.reconfigure(func(c *Config) { c.SigningKey, c.SigningKeyOld = keyB, keyA })
	if _, err := rc.verifier.Verify(ctx, oldToken); err != nil {
		t.Fatalf("token from before the rotation: %v", err)
	}
	idt := rc.login(b) // rc's verifier cached A only: go-oidc refetches on the new kid
	if idt.Subject != alice {
		t.Fatal(idt.Subject)
	}
	var jwks jose.JSONWebKeySet
	_ = json.Unmarshal([]byte(body(b.get(e.srv.URL+"/jwks.json"))), &jwks)
	if len(jwks.Keys) != 2 {
		t.Fatalf("jwks during rotation: %d keys", len(jwks.Keys))
	}

	// rotation done: A gone, so its tokens fail for a fresh app
	e.reconfigure(func(c *Config) { c.SigningKeyOld = "" })
	if _, err := e.rp("running-club").verifier.Verify(ctx, oldToken); err == nil {
		t.Fatal("token signed with a retired key still verifies")
	}
}

func TestWrongAudience(t *testing.T) {
	e := setup(t)
	b := e.browser()
	rc := e.rp("running-club")
	a := rc.start()
	code := rc.back(b.get(a.url), a)
	tok, err := rc.oauth.Exchange(context.Background(), code, oauth2.VerifierOption(a.verifier))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.rp("stub").verifier.Verify(context.Background(), tok.Extra("id_token").(string)); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("running-club's token accepted by stub: %v", err)
	}
}

func TestTwoLoginsAtOnce(t *testing.T) {
	e := setup(t)
	b := e.browser()
	rc, stub := e.rp("running-club"), e.rp("stub")
	// both tabs reach Telegram before either comes back
	stopAtTG := *b.Client
	stopAtTG.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), e.tg.URL) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	a1, a2 := rc.start(), stub.start()
	var toTG []string
	for _, a := range []attempt{a1, a2} {
		resp, err := stopAtTG.Get(a.url)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		toTG = append(toTG, resp.Header.Get("Location"))
	}
	for i, r := range []*rp{rc, stub} {
		a := []attempt{a1, a2}[i]
		code := r.back(b.get(toTG[i]), a)
		if _, err := r.exchange(code, a); err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
	}
}

func TestTelegramFailures(t *testing.T) {
	e := setup(t)
	b := e.browser()
	rc := e.rp("running-club")
	e.tg.badNonce = true
	a := rc.start()
	resp := b.get(a.url)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body(resp), "Не получилось войти") {
		t.Fatalf("bad nonce: %d", resp.StatusCode)
	}
	if !strings.Contains(e.logs.String(), "nonce mismatch") {
		t.Fatal(e.logs.String())
	}
	e.tg.badNonce = false
	// a callback without its login cookie (another browser, or expired)
	resp = e.browser().get(e.srv.URL + "/callback?code=x&state=" + random())
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("no cookie: %d", resp.StatusCode)
	}
	// someone without a Telegram id
	e.tg.mu.Lock()
	e.tg.user = map[string]any{"sub": "abc"}
	e.tg.mu.Unlock()
	if resp := b.get(rc.start().url); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("no id: %d", resp.StatusCode)
	}
}

func TestLogout(t *testing.T) {
	e := setup(t)
	b := e.browser()
	rc := e.rp("running-club")
	rc.login(b)
	logout := e.srv.URL + "/logout?" + url.Values{"client_id": {"running-club"}, "post_logout_redirect_uri": {appURL("running-club") + "/"}, "state": {"s1"}}.Encode()

	resp := b.get(logout)
	page := body(resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Выйти на всех сайтах?") || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "form-action 'self' "+appURL("running-club")+";") {
		t.Fatalf("logout page: %d %s %s", resp.StatusCode, resp.Header.Get("Content-Security-Policy"), page)
	}
	form := url.Values{"client_id": {"running-club"}, "post_logout_redirect_uri": {appURL("running-club") + "/"}, "state": {"s1"}}
	for _, h := range [][]string{{"Sec-Fetch-Site", "same-site"}, {"Sec-Fetch-Site", "cross-site"}, {"Origin", "https://evil.example"}} {
		if resp := b.post(e.srv.URL+"/logout", form, h...); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("logout from %v: %d", h, resp.StatusCode)
		}
	}
	resp = b.post(e.srv.URL+"/logout", form, "Sec-Fetch-Site", "same-origin")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != appURL("running-club")+"/?state=s1" {
		t.Fatalf("logout: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// the next login needs Telegram again
	rc.login(b)
	if e.tg.authCount() != 2 {
		t.Fatalf("telegram logins: %d", e.tg.authCount())
	}
	// an unlisted return address is dropped, not followed
	resp = b.post(e.srv.URL+"/logout", url.Values{"client_id": {"running-club"}, "post_logout_redirect_uri": {"https://evil.example/"}}, "Origin", e.srv.URL)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Location") != "" || !strings.Contains(body(resp), "Ты вышел") {
		t.Fatalf("unlisted return: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// without a session, GET goes straight back
	if resp := b.get(logout); resp.Header.Get("Location") != appURL("running-club")+"/?state=s1" {
		t.Fatalf("logged out already: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestDiscoveryAndHeaders(t *testing.T) {
	e := setup(t)
	b := e.browser()
	var d map[string]any
	resp := b.get(e.srv.URL + "/.well-known/openid-configuration")
	if err := json.Unmarshal([]byte(body(resp)), &d); err != nil {
		t.Fatal(err)
	}
	if d["issuer"] != e.srv.URL || fmt.Sprint(d["code_challenge_methods_supported"]) != "[S256]" || fmt.Sprint(d["id_token_signing_alg_values_supported"]) != "[EdDSA]" || fmt.Sprint(d["token_endpoint_auth_methods_supported"]) != "[client_secret_basic]" {
		t.Fatalf("discovery: %v", d)
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("headers")
	}
	var jwks jose.JSONWebKeySet
	_ = json.Unmarshal([]byte(body(b.get(e.srv.URL+"/jwks.json"))), &jwks)
	if len(jwks.Keys) != 1 || jwks.Keys[0].Algorithm != "EdDSA" || jwks.Keys[0].KeyID != kidOf(mustSeed(keyA).Public().(ed25519.PublicKey)) {
		t.Fatalf("jwks: %+v", jwks)
	}
	if resp := b.get(e.srv.URL + "/healthz"); resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}
	if resp := b.get(e.srv.URL + "/nope"); resp.StatusCode != http.StatusNotFound {
		t.Fatal(resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodHead, e.srv.URL+"/authorize", nil)
	if resp, _ := b.Do(req); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD /authorize: %d", resp.StatusCode)
	}
	if resp := b.get(e.srv.URL + "/"); !strings.Contains(resp.Header.Get("Content-Security-Policy"), "style-src 'sha256-") {
		t.Fatal(resp.Header.Get("Content-Security-Policy"))
	}
}

func mustSeed(s string) ed25519.PrivateKey {
	k, err := parseSeed(s)
	if err != nil {
		panic(err)
	}
	return k
}

// Over https the cookies are __Host-, Secure, HttpOnly, Lax, and HSTS is on
func TestHTTPSCookies(t *testing.T) {
	e := setup(t)
	cfg := e.cfg
	cfg.PublicURL = "https://login.example"
	a := newApp(cfg)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://login.example/login", nil))
	c := w.Result().Cookies()
	if len(c) != 1 || !strings.HasPrefix(c[0].Name, "__Host-hub_oauth_") || !c[0].Secure || !c[0].HttpOnly || c[0].Path != "/" || c[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie: %+v", c)
	}
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("no HSTS")
	}
	if a.sessionName != "__Host-hub_session" {
		t.Fatal(a.sessionName)
	}
}

func TestFailsClosed(t *testing.T) {
	for name, mod := range map[string]func(*Config){
		"no telegram":   func(c *Config) { c.ClientID = "" },
		"short secret":  func(c *Config) { c.SessionSecret = "short" },
		"no key":        func(c *Config) { c.SigningKey = "" },
		"bad key":       func(c *Config) { c.SigningKey = "bm90IGEga2V5" },
		"same old key":  func(c *Config) { c.SigningKeyOld = c.SigningKey },
		"http issuer":   func(c *Config) { c.PublicURL = "http://login.example" },
		"issuer path":   func(c *Config) { c.PublicURL = "https://login.example/x" },
		"broken config": func(c *Config) { c.Access, c.AccessErr = nil, fmt.Errorf("bad") },
	} {
		cfg := Config{SessionSecret: strings.Repeat("s", 32), ClientID: "1", ClientSecret: "2", PublicURL: "https://login.example", SigningKey: keyA, Access: &Access{Apps: map[string]*client{}}, Log: log.New(io.Discard, "", 0)}
		mod(&cfg)
		a := newApp(cfg)
		for _, p := range []string{"/healthz", "/authorize", "/.well-known/openid-configuration", "/"} {
			w := httptest.NewRecorder()
			a.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://login.example"+p, nil))
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("%s %s: %d", name, p, w.Code)
			}
		}
	}
}
