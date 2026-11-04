package main

// The hub's own cookies, HMAC-signed: the session (who someone is, never what they may open) and
// one short-lived cookie per Telegram login in progress, named after its state, so two tabs
// logging in at once don't overwrite each other.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	sessionTTL = 180 * 24 * time.Hour
	oauthTTL   = 10 * time.Minute
)

// sessionData: the Telegram account, as Telegram last confirmed it, and when (auth_time)
type sessionData struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Username string `json:"username,omitempty"`
	At       int64  `json:"at"`
}

type oauthData struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce"`
	Next     string `json:"next"`
}

var b64 = base64.RawURLEncoding

func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b64.EncodeToString(b)
}

// sign: base64url(JSON {aud, exp, data}) "." base64url(HMAC-SHA256); aud keeps the cookie kinds apart
func (a *app) sign(aud string, data any, ttl time.Duration) string {
	body, _ := json.Marshal(struct {
		Aud  string `json:"aud"`
		Exp  int64  `json:"exp"`
		Data any    `json:"data"`
	}{aud, a.now().Add(ttl).Unix(), data})
	p := b64.EncodeToString(body)
	return p + "." + a.mac(p)
}

func (a *app) mac(p string) string {
	m := hmac.New(sha256.New, a.secret)
	m.Write([]byte(p))
	return b64.EncodeToString(m.Sum(nil))
}

func (a *app) unsign(token, aud string, data any) bool {
	p, sig, ok := strings.Cut(token, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(a.mac(p))) {
		return false
	}
	body, err := b64.DecodeString(p)
	if err != nil {
		return false
	}
	var env struct {
		Aud  string          `json:"aud"`
		Exp  int64           `json:"exp"`
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(body, &env) != nil || env.Aud != aud || a.now().Unix() > env.Exp {
		return false
	}
	return json.Unmarshal(env.Data, data) == nil
}

func (a *app) session(r *http.Request) *sessionData {
	c, err := r.Cookie(a.sessionName)
	var s sessionData
	if err != nil || !a.unsign(c.Value, "session", &s) || !digits.MatchString(s.ID) {
		return nil
	}
	return &s
}

var (
	authorizeNext = regexp.MustCompile(`^/authorize\?[^#\\]*$`)
	stateChars    = regexp.MustCompile(`^[\w-]+$`) // base64url, as random() makes them
)

// safeNext: after a Telegram login the hub only ever goes on to /authorize (with the app's request)
// or its own home page; anything else becomes «/»
func safeNext(next string) string {
	if authorizeNext.MatchString(next) {
		return next
	}
	return "/"
}

// oauthName: the login cookie for this state, or "" for a state that isn't one of ours
func (a *app) oauthName(state string) string {
	if len(state) < 16 || !stateChars.MatchString(state) {
		return ""
	}
	return a.oauthPrefix + state[:16]
}
