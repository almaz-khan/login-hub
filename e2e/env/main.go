// The end-to-end environment: go run ./e2e/env
//
//   - the hub on http://localhost:4455 (WebAuthn needs a host name), with a fresh database;
//   - a fake Telegram on http://127.0.0.1:4454: its login page lets the test pick who logs in,
//     and it plays the bot API too;
//   - four stub apps, each its own origin, each a real OIDC client (go-oidc + oauth2, as a Go app
//     would be): tg-app (Telegram only), pk-app (passkey only), both-app (either), closed-app
//     (only Bob).
//
// Nothing here is used in production. Bot messages are printed as «bot: …» for the tests to read
// at /bot-messages on the fake Telegram.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"

	"hub/internal/hub"
	"hub/internal/store"
)

const (
	hubURL   = "http://localhost:4455"
	tgURL    = "http://127.0.0.1:4454"
	tgClient = "7000000001"
	tgSecret = "e2e-telegram-secret"
	botToken = "e2e:BOT"
)

// people the fake Telegram can log in as; Dave is a Telegram account the hub doesn't know
var accounts = []struct{ ID, Name, Username string }{
	{"111", "Alice Telegram", "alice"},
	{"222", "Bob Telegram", "bob"},
	{"444", "Dave Telegram", "dave"},
}

type stubApp struct {
	ID, Name string
	Port     int
	Login    []string
	Allow    []string
	secret   string
}

var apps = []*stubApp{
	{ID: "tg-app", Name: "Telegram App", Port: 4461, Login: []string{"telegram"}, Allow: []string{"Alice", "Bob"}},
	{ID: "pk-app", Name: "Passkey App", Port: 4462, Login: []string{"passkey"}, Allow: []string{"Alice", "Bob", "Carol"}},
	{ID: "both-app", Name: "Both App", Port: 4463, Login: []string{"telegram", "passkey"}, Allow: []string{"group:club"}},
	{ID: "closed-app", Name: "Closed App", Port: 4464, Login: []string{"telegram"}, Allow: []string{"Bob"}},
}

func (s *stubApp) origin() string { return fmt.Sprintf("http://127.0.0.1:%d", s.Port) }

func main() {
	dir, err := os.MkdirTemp("", "hub-e2e-")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	seedApps := map[string]any{}
	for _, a := range apps {
		var hash []byte
		a.secret, hash = store.NewClientSecret()
		seedApps[a.ID] = map[string]any{
			"name": a.Name, "redirect_uris": []string{a.origin() + "/auth/callback"},
			"post_logout_redirect_uris": []string{a.origin() + "/"}, "login": a.Login,
			"secret_sha256": hex.EncodeToString(hash), "allow": a.Allow,
		}
	}
	seed, _ := json.Marshal(map[string]any{
		"notify": "Alice",
		"people": map[string]any{
			"Alice": map[string]string{"name": "Alice", "telegram": "111"},
			"Bob":   map[string]string{"name": "Bob", "telegram": "222"},
			"Carol": map[string]string{"name": "Carol"},
		},
		"groups": map[string][]string{"club": {"Alice"}},
		"apps":   seedApps,
	})

	db, err := store.Open(filepath.Join(dir, "hub.db"), nil)
	if err != nil {
		log.Fatal(err)
	}
	tg := newFakeTelegram()
	server := hub.New(hub.Config{
		Store: db, Seed: seed, Admin: "Alice",
		ClientID: tgClient, ClientSecret: tgSecret, SessionSecret: random(),
		PublicURL: hubURL, SigningKey: base64.StdEncoding.EncodeToString(randomBytes(32)),
		BotToken: botToken, TGBase: tgURL, BotAPI: tgURL,
	})

	go serve("127.0.0.1:4454", tg)
	for _, a := range apps {
		go serve(fmt.Sprintf("127.0.0.1:%d", a.Port), newRP(a))
	}
	log.Printf("e2e: hub %s, telegram %s, apps 4461–4464", hubURL, tgURL)
	serve("localhost:4455", server)
}

func serve(addr string, h http.Handler) {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func random() string { return base64.RawURLEncoding.EncodeToString(randomBytes(32)) }

func page(w http.ResponseWriter, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintf(w, "<!doctype html><html lang=ru><meta charset=utf-8><title>%s</title><body>%s</body></html>", html.EscapeString(title), body)
}

// ------------------------------------------------------------ fake Telegram

type fakeTelegram struct {
	key   *rsa.PrivateKey
	mu    sync.Mutex
	codes map[string]map[string]string // code → who, nonce, challenge
	bot   []string
}

func newFakeTelegram() *fakeTelegram {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	return &fakeTelegram{key: key, codes: map[string]map[string]string{}}
}

func (f *fakeTelegram) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/jwks.json":
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "tg1", Algorithm: "RS256", Use: "sig"}}})
	case "/auth":
		// Telegram's own screen: here, one button per account
		var b strings.Builder
		b.WriteString("<h1>Fake Telegram</h1>")
		for _, a := range accounts {
			q := r.URL.Query()
			q.Set("who", a.ID)
			fmt.Fprintf(&b, `<p><a href="/pick?%s">Sign in as %s</a></p>`, html.EscapeString(q.Encode()), html.EscapeString(a.Name))
		}
		page(w, "Fake Telegram", b.String())
	case "/pick":
		q := r.URL.Query()
		code := random()
		f.mu.Lock()
		f.codes[code] = map[string]string{"who": q.Get("who"), "nonce": q.Get("nonce"), "challenge": q.Get("code_challenge")}
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	case "/token":
		f.token(w, r)
	case "/bot" + botToken + "/sendMessage":
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		f.mu.Lock()
		f.bot = append(f.bot, fmt.Sprint(m["text"]))
		f.mu.Unlock()
		log.Printf("bot: %v", m["text"])
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	case "/bot-messages":
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_ = json.NewEncoder(w).Encode(f.bot)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeTelegram) token(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	_ = r.ParseForm()
	f.mu.Lock()
	c := f.codes[r.PostForm.Get("code")]
	delete(f.codes, r.PostForm.Get("code"))
	f.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || user != tgClient || pass != tgSecret || c == nil || base64.RawURLEncoding.EncodeToString(sum[:]) != c["challenge"] {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	claims := map[string]any{"iss": tgURL, "aud": tgClient, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "nonce": c["nonce"], "sub": "tg-" + c["who"], "id": json.Number(c["who"])}
	for _, a := range accounts {
		if a.ID == c["who"] {
			claims["name"], claims["preferred_username"] = a.Name, a.Username
		}
	}
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "tg1"))
	body, _ := json.Marshal(claims)
	jws, _ := signer.Sign(body)
	token, _ := jws.CompactSerialize()
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "x", "token_type": "Bearer", "id_token": token})
}

// ---------------------------------------------------------------- stub apps

type rp struct {
	app    *stubApp
	secret []byte
	once   sync.Once
	oauth  oauth2.Config
	verify *oidc.IDTokenVerifier
}

func newRP(a *stubApp) *rp { return &rp{app: a, secret: randomBytes(32)} }

// setup: discovery from the hub, the first time it's needed (the hub may start after the apps)
func (p *rp) setup() error {
	var err error
	p.once.Do(func() {
		var prov *oidc.Provider
		prov, err = oidc.NewProvider(context.Background(), hubURL)
		if err != nil {
			p.once = sync.Once{}
			return
		}
		ep := prov.Endpoint()
		ep.AuthStyle = oauth2.AuthStyleInHeader
		p.oauth = oauth2.Config{ClientID: p.app.ID, ClientSecret: p.app.secret, Endpoint: ep, RedirectURL: p.app.origin() + "/auth/callback", Scopes: []string{oidc.ScopeOpenID, "profile"}}
		p.verify = prov.Verifier(&oidc.Config{ClientID: p.app.ID, SupportedSigningAlgs: []string{oidc.EdDSA}})
	})
	return err
}

func (p *rp) sign(v any) string {
	body, _ := json.Marshal(v)
	payload := base64.RawURLEncoding.EncodeToString(body)
	m := hmac.New(sha256.New, p.secret)
	m.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (p *rp) unsign(s string, v any) bool {
	payload, sig, ok := strings.Cut(s, ".")
	m := hmac.New(sha256.New, p.secret)
	m.Write([]byte(payload))
	if !ok || !hmac.Equal([]byte(sig), []byte(base64.RawURLEncoding.EncodeToString(m.Sum(nil)))) {
		return false
	}
	body, err := base64.RawURLEncoding.DecodeString(payload)
	return err == nil && json.Unmarshal(body, v) == nil
}

// cookies are per host, not per port: all stub apps share 127.0.0.1, so their cookie names differ
type rpSession struct {
	Sub, Name string
	AMR       []string
}

func (p *rp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := p.setup(); err != nil {
		http.Error(w, "hub not up: "+err.Error(), http.StatusBadGateway)
		return
	}
	switch r.URL.Path {
	case "/":
		var s rpSession
		if c, err := r.Cookie("rp_session_" + p.app.ID); err == nil && p.unsign(c.Value, &s) {
			page(w, p.app.Name, fmt.Sprintf(`<h1>%s</h1><p id="who" data-sub="%s" data-amr="%s">Signed in: %s</p><form method="post" action="/logout"><button id="logout">Sign out</button></form>`,
				html.EscapeString(p.app.Name), html.EscapeString(s.Sub), html.EscapeString(strings.Join(s.AMR, ",")), html.EscapeString(s.Name)))
			return
		}
		page(w, p.app.Name, fmt.Sprintf(`<h1>%s</h1><p id="anon">Not signed in</p><a id="login" href="/login">Sign in</a>`, html.EscapeString(p.app.Name)))
	case "/login":
		st := map[string]string{"state": random(), "nonce": random(), "verifier": oauth2.GenerateVerifier()}
		http.SetCookie(w, &http.Cookie{Name: "rp_login_" + p.app.ID, Value: p.sign(st), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
		http.Redirect(w, r, p.oauth.AuthCodeURL(st["state"], oidc.Nonce(st["nonce"]), oauth2.S256ChallengeOption(st["verifier"])), http.StatusFound)
	case "/auth/callback":
		p.callback(w, r)
	case "/logout":
		if r.Method != http.MethodPost {
			http.Error(w, "POST", http.StatusMethodNotAllowed)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "rp_session_" + p.app.ID, Path: "/", MaxAge: -1})
		q := url.Values{"client_id": {p.app.ID}, "post_logout_redirect_uri": {p.app.origin() + "/"}}
		http.Redirect(w, r, hubURL+"/logout?"+q.Encode(), http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

func (p *rp) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	fail := func(msg string) {
		page(w, p.app.Name, `<p id="error">`+html.EscapeString(msg)+`</p>`)
	}
	var st map[string]string
	c, err := r.Cookie("rp_login_" + p.app.ID)
	if err != nil || !p.unsign(c.Value, &st) || st["state"] != q.Get("state") {
		fail("state")
		return
	}
	if q.Get("error") != "" {
		fail(q.Get("error"))
		return
	}
	if q.Get("iss") != hubURL {
		fail("iss " + q.Get("iss"))
		return
	}
	tok, err := p.oauth.Exchange(r.Context(), q.Get("code"), oauth2.VerifierOption(st["verifier"]))
	if err != nil {
		fail("token: " + err.Error())
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := p.verify.Verify(r.Context(), raw)
	if err != nil || idt.Nonce != st["nonce"] {
		fail(fmt.Sprintf("id token: %v", err))
		return
	}
	var claims struct {
		Name string   `json:"name"`
		AMR  []string `json:"amr"`
	}
	_ = idt.Claims(&claims)
	http.SetCookie(w, &http.Cookie{Name: "rp_login_" + p.app.ID, Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "rp_session_" + p.app.ID, Value: p.sign(rpSession{Sub: idt.Subject, Name: claims.Name, AMR: claims.AMR}), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusFound)
}
