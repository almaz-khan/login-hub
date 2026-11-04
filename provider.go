package main

// The OpenID Connect side: discovery, JWKS, /authorize and /token. Only what the apps need:
// the code flow, PKCE S256 (required), client_secret_basic, EdDSA ID tokens. Codes live in memory
// for 60 seconds and work once; the hub runs as one instance, so a restart only cancels logins
// that are halfway through, and those simply start again.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	codeTTL    = 60 * time.Second
	idTokenTTL = 5 * time.Minute
)

// keySet: the key that signs, plus the JWKS document (that key and, during a rotation, the old one)
type keySet struct {
	kid    string
	signer jose.Signer
	jwks   []byte
}

// parseSeed: a 32-byte Ed25519 seed in standard or URL-safe base64, padded or not
func parseKeySeed(s string) (ed25519.PrivateKey, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	if s == "" {
		return nil, errors.New("not set")
	}
	seed, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		seed, err = base64.RawURLEncoding.DecodeString(s)
	}
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("not a base64 32-byte seed; make one with `hub keygen`")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// kidOf: a hash of the public key, so the same key always has the same kid
func kidOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return b64.EncodeToString(sum[:12])
}

func newKeySet(current, old string) (*keySet, error) {
	key, err := parseKeySeed(current)
	if err != nil {
		return nil, err
	}
	pub := key.Public().(ed25519.PublicKey)
	ks := &keySet{kid: kidOf(pub)}
	ks.signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", ks.kid))
	if err != nil {
		return nil, err
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: ks.kid, Algorithm: string(jose.EdDSA), Use: "sig"}}}
	if old != "" {
		oldKey, err := parseKeySeed(old)
		if err != nil {
			return nil, fmt.Errorf("HUB_SIGNING_KEY_OLD: %w", err)
		}
		oldPub := oldKey.Public().(ed25519.PublicKey)
		if oldPub.Equal(pub) {
			return nil, errors.New("HUB_SIGNING_KEY_OLD is the same key")
		}
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: oldPub, KeyID: kidOf(oldPub), Algorithm: string(jose.EdDSA), Use: "sig"})
	}
	ks.jwks, err = json.Marshal(set)
	return ks, err
}

func (k *keySet) sign(claims map[string]any) (string, error) {
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	jws, err := k.signer.Sign(body)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

func (a *app) discoveryDoc() []byte {
	doc, _ := json.Marshal(map[string]any{
		"issuer":                                         a.issuer,
		"authorization_endpoint":                         a.issuer + "/authorize",
		"token_endpoint":                                 a.issuer + "/token",
		"jwks_uri":                                       a.issuer + "/jwks.json",
		"end_session_endpoint":                           a.issuer + "/logout",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{string(jose.EdDSA)},
		"scopes_supported":                               []string{"openid", "profile"},
		"claims_supported":                               []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "name", "preferred_username", "telegram_id"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic"},
		"code_challenge_methods_supported":               []string{"S256"},
		"prompt_values_supported":                        []string{"none"},
		"authorization_response_iss_parameter_supported": true,
	})
	return doc
}

func serveJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(body)
}

func (a *app) serveDiscovery(w http.ResponseWriter, _ *http.Request) { serveJSON(w, a.discovery) }
func (a *app) serveJWKS(w http.ResponseWriter, _ *http.Request)      { serveJSON(w, a.keys.jwks) }

// grant: what a code stands for, until /token spends it
type grant struct {
	client    string
	redirect  string
	nonce     string
	challenge string
	who       sessionData // how they logged in (username, auth_time)
	person    Person
	exp       time.Time
}

type codeStore struct {
	mu sync.Mutex
	m  map[string]grant
}

func (s *codeStore) put(code string, g grant, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, old := range s.m {
		if now.After(old.exp) {
			delete(s.m, k)
		}
	}
	s.m[code] = g
}

// take: the grant for code, which is gone from the store from now on whatever happens next
func (s *codeStore) take(code string) (grant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.m[code]
	delete(s.m, code)
	return g, ok
}

var pkceValue = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`) // RFC 7636: verifier and S256 challenge

func (a *app) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for k, v := range q {
		if len(v) > 1 {
			a.log.Printf("authorize refused: %s given twice", k)
			page(w, http.StatusBadRequest, pageBadLink)
			return
		}
	}
	// Until client and redirect URL are known to match, nothing redirects: otherwise anyone could
	// have the hub send codes to their own site.
	c, err := a.store.App(q.Get("client_id"))
	if err != nil {
		a.broken(w, err)
		return
	}
	if c == nil {
		a.log.Printf("authorize refused: unknown client %q", q.Get("client_id"))
		page(w, http.StatusBadRequest, pageBadLink)
		return
	}
	back := q.Get("redirect_uri")
	if !c.redirects[back] {
		a.log.Printf("authorize refused: %s: redirect_uri %q is not listed", c.ID, back)
		page(w, http.StatusBadRequest, pageBadLink)
		return
	}
	state := q.Get("state")
	fail := func(code, desc string) {
		a.log.Printf("authorize: %s: %s (%s)", c.ID, code, desc)
		redirect(w, a.withQuery(back, "error", code, "error_description", desc, "state", state))
	}
	prompt := strings.Fields(q.Get("prompt"))
	switch {
	case q.Get("response_type") != "code":
		fail("unsupported_response_type", "only response_type=code")
		return
	case !contains(strings.Fields(q.Get("scope")), "openid"):
		fail("invalid_scope", "scope must include openid")
		return
	case q.Get("code_challenge_method") != "S256" || !pkceValue.MatchString(q.Get("code_challenge")):
		fail("invalid_request", "PKCE with S256 is required")
		return
	case state == "":
		fail("invalid_request", "state is required")
		return
	case q.Get("nonce") == "":
		fail("invalid_request", "nonce is required")
		return
	case q.Get("response_mode") != "" && q.Get("response_mode") != "query":
		fail("invalid_request", "only response_mode=query")
		return
	case q.Has("request") || q.Has("request_uri"):
		fail("request_not_supported", "request objects are not supported")
		return
	}

	who := a.session(r)
	if who == nil {
		if contains(prompt, "none") {
			fail("login_required", "no hub session")
			return
		}
		redirect(w, "/login?next="+url.QueryEscape("/authorize?"+r.URL.RawQuery))
		return
	}
	// who they are and what they may open are read from the database on every /authorize,
	// never stored in the session: a removed person or a changed allow list applies at once
	person, err := a.store.PersonByTelegram(who.ID)
	if err != nil {
		a.broken(w, err)
		return
	}
	allowed := false
	if person != nil {
		if allowed, err = a.store.Allowed(c.ID, person.Key); err != nil {
			a.broken(w, err)
			return
		}
	}
	if !allowed {
		label := "unknown Telegram account"
		if person != nil {
			label = person.Key
		}
		a.log.Printf("access denied: %s, telegram %s (%s @%s) → %s", label, who.ID, who.Name, who.Username, c.ID)
		a.notifyDenied(*who, person, c)
		if contains(prompt, "none") {
			fail("access_denied", "not allowed for this app")
			return
		}
		page(w, http.StatusForbidden, pageDenied(c.Name, *who, "/authorize?"+r.URL.RawQuery))
		return
	}
	code := random()
	a.codes.put(code, grant{
		client: c.ID, redirect: back, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"),
		who: *who, person: *person, exp: a.now().Add(codeTTL),
	}, a.now())
	if err := a.store.Seen(person.Key); err != nil {
		a.log.Printf("last seen: %v", err)
	}
	a.log.Printf("authorize: %s → %s", person.Key, c.ID)
	redirect(w, a.withQuery(back, "code", code, "state", state))
}

// withQuery: back with these parameters added, plus iss (RFC 9207), keeping back's own query
func (a *app) withQuery(back string, kv ...string) string {
	u, _ := url.Parse(back)
	q := u.Query()
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			q.Set(kv[i], kv[i+1])
		}
	}
	q.Set("iss", a.issuer)
	u.RawQuery = q.Encode()
	return u.String()
}

func (a *app) token(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	// the client is checked first, so nobody without a secret can spend someone's code
	c := a.clientAuth(r)
	if c == nil {
		h.Set("WWW-Authenticate", `Basic realm="hub"`)
		tokenError(w, http.StatusUnauthorized, "invalid_client", "")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	f := r.PostForm
	if f.Get("grant_type") != "authorization_code" {
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "")
		return
	}
	if id := f.Get("client_id"); id != "" && id != c.ID {
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client_id differs from the authenticated client")
		return
	}
	g, ok := a.codes.take(f.Get("code"))
	var why string
	switch {
	case !ok:
		why = "unknown, used or cancelled code"
	case a.now().After(g.exp):
		why = "expired code"
	case g.client != c.ID:
		why = "code belongs to " + g.client
	case f.Get("redirect_uri") != g.redirect:
		why = "redirect_uri differs from /authorize"
	case !pkceOK(f.Get("code_verifier"), g.challenge):
		why = "PKCE verifier does not match"
	}
	if why != "" {
		a.log.Printf("token refused: %s: %s", c.ID, why)
		tokenError(w, http.StatusBadRequest, "invalid_grant", why)
		return
	}
	now := a.now()
	claims := map[string]any{
		"iss":       a.issuer,
		"sub":       g.person.Key,
		"aud":       c.ID,
		"iat":       now.Unix(),
		"exp":       now.Add(idTokenTTL).Unix(),
		"auth_time": g.who.At,
		"nonce":     g.nonce,
		"name":      g.person.Name,
	}
	if g.person.TelegramID != "" {
		claims["telegram_id"] = g.person.TelegramID
	}
	if g.who.Username != "" {
		claims["preferred_username"] = g.who.Username
	}
	idToken, err := a.keys.sign(claims)
	if err != nil {
		a.log.Printf("token: signing failed: %v", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	h.Set("Content-Type", "application/json")
	// an access_token because standard client libraries require one; nothing accepts it
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": random(),
		"token_type":   "Bearer",
		"expires_in":   int(idTokenTTL.Seconds()),
		"id_token":     idToken,
	})
}

// clientAuth: client_secret_basic. RFC 6749 says id and secret are form-encoded before Basic
// (Go's oauth2 does that, many libraries don't), so both spellings are tried.
func (a *app) clientAuth(r *http.Request) *client {
	user, pass, ok := r.BasicAuth()
	if !ok || pass == "" {
		return nil
	}
	c, err := a.store.App(user)
	if c == nil && err == nil {
		if u, uerr := url.QueryUnescape(user); uerr == nil && u != user {
			c, err = a.store.App(u)
		}
	}
	if err != nil {
		a.log.Printf("token: database: %v", err)
		return nil
	}
	if c == nil {
		return nil
	}
	if secretOK(pass, c.secretHash) {
		return c
	}
	if p, err := url.QueryUnescape(pass); err == nil && p != pass && secretOK(p, c.secretHash) {
		return c
	}
	a.log.Printf("token refused: %s: wrong client secret", c.ID)
	return nil
}

func secretOK(secret string, hash []byte) bool {
	sum := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(sum[:], hash) == 1
}

func pkceOK(verifier, challenge string) bool {
	if !pkceValue.MatchString(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(b64.EncodeToString(sum[:])), []byte(challenge)) == 1
}

func tokenError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	_ = json.NewEncoder(w).Encode(body)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// broken: the database failed; nothing is let through
func (a *app) broken(w http.ResponseWriter, err error) {
	a.log.Printf("error: database: %v", err)
	page(w, http.StatusInternalServerError, pageFailed("/"))
}
