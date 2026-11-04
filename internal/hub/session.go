package hub

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

// sessionData: what someone has proven in this browser, one proof per method. Proofs never say
// what anyone may open; who the proofs belong to is looked up on every request (see resolve).
type sessionData struct {
	TG *tgProof `json:"tg,omitempty"`
	PK *pkProof `json:"pk,omitempty"`
}

// tgProof: a Telegram login, as Telegram confirmed it
type tgProof struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Username string `json:"username,omitempty"`
	At       int64  `json:"at"`
}

// pkProof: a passkey login (phase 4)
type pkProof struct {
	Person string `json:"person"`
	Cred   string `json:"cred"`
	At     int64  `json:"at"`
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
func (a *Server) sign(aud string, data any, ttl time.Duration) string {
	body, _ := json.Marshal(struct {
		Aud  string `json:"aud"`
		Exp  int64  `json:"exp"`
		Data any    `json:"data"`
	}{aud, a.now().Add(ttl).Unix(), data})
	p := b64.EncodeToString(body)
	return p + "." + a.mac(p)
}

func (a *Server) mac(p string) string {
	m := hmac.New(sha256.New, a.secret)
	m.Write([]byte(p))
	return b64.EncodeToString(m.Sum(nil))
}

func (a *Server) unsign(token, aud string, data any) bool {
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

func (a *Server) session(r *http.Request) *sessionData {
	c, err := r.Cookie(a.sessionName)
	var s sessionData
	if err != nil || !a.unsign(c.Value, "session", &s) {
		return &sessionData{}
	}
	if s.TG != nil && !digits.MatchString(s.TG.ID) {
		s.TG = nil
	}
	return &s
}

func (a *Server) saveSession(w http.ResponseWriter, s *sessionData) {
	a.setCookie(w, a.sessionName, a.sign("session", s, sessionTTL), int(sessionTTL.Seconds()))
}

var (
	authorizeNext = regexp.MustCompile(`^/authorize\?[^#\\]*$`)
	stateChars    = regexp.MustCompile(`^[\w-]+$`) // base64url, as random() makes them
)

// safeNext: after a login the hub only ever goes on to /authorize (with the app's request), the
// admin UI or its own home page; anything else becomes «/»
func safeNext(next string) string {
	if authorizeNext.MatchString(next) || next == "/admin" {
		return next
	}
	return "/"
}

// oauthName: the login cookie for this state, or "" for a state that isn't one of ours
func (a *Server) oauthName(state string) string {
	if len(state) < 16 || !stateChars.MatchString(state) {
		return ""
	}
	return a.oauthPrefix + state[:16]
}
