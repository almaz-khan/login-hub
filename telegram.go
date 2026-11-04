package main

// The Telegram login, moved from Running Club: /login → oauth.telegram.org (code flow, PKCE S256,
// state, nonce) → /callback, which exchanges the code, verifies the ID token against Telegram's
// JWKS (signature, issuer, audience, expiry, nonce) and sets the hub session. Nobody is refused
// here: the session only says who someone is, and /authorize decides what they may open.

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func (a *app) telegramRedirect() string { return a.issuer + "/callback" }

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	o := oauthData{State: random(), Verifier: random(), Nonce: random(), Next: safeNext(r.URL.Query().Get("next"))}
	a.setCookie(w, a.oauthName(o.State), a.sign("oauth", o, oauthTTL), int(oauthTTL.Seconds()))
	sum := sha256.Sum256([]byte(o.Verifier))
	q := url.Values{
		"client_id":             {a.cfg.ClientID},
		"redirect_uri":          {a.telegramRedirect()},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {o.State},
		"nonce":                 {o.Nonce},
		"code_challenge":        {b64.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	redirect(w, a.tg+"/auth?"+q.Encode())
}

func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var o oauthData
	ok := false
	if name := a.oauthName(q.Get("state")); name != "" {
		if c, err := r.Cookie(name); err == nil {
			ok = a.unsign(c.Value, "oauth", &o)
		}
		a.setCookie(w, name, "", -1)
	}
	code := q.Get("code")
	switch {
	case q.Get("error") != "":
		a.log.Printf("telegram login failed: telegram said %q", q.Get("error"))
	case !ok:
		a.log.Printf("telegram login failed: no or expired login cookie")
	case code == "":
		a.log.Printf("telegram login failed: no code")
	case subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(o.State)) != 1:
		a.log.Printf("telegram login failed: state mismatch")
	default:
		a.finish(w, r, code, o)
		return
	}
	page(w, http.StatusBadRequest, pageFailed(o.Next))
}

func (a *app) finish(w http.ResponseWriter, r *http.Request, code string, o oauthData) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {a.telegramRedirect()},
		"client_id":     {a.cfg.ClientID},
		"code_verifier": {o.Verifier},
	}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, a.tg+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(a.cfg.ClientID, a.cfg.ClientSecret)
	resp, err := a.client.Do(req)
	if err != nil {
		a.log.Printf("telegram login failed: token endpoint: %v", err)
		page(w, http.StatusBadGateway, pageFailed(o.Next))
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &tr) != nil || tr.IDToken == "" {
		a.log.Printf("telegram login failed: token endpoint %d %.200s", resp.StatusCode, body)
		page(w, http.StatusBadGateway, pageFailed(o.Next))
		return
	}
	tok, err := a.verifier.Verify(r.Context(), tr.IDToken)
	if err != nil {
		a.log.Printf("telegram login failed: ID token rejected: %v", err)
		page(w, http.StatusBadGateway, pageFailed(o.Next))
		return
	}
	// Telegram's discovery document doesn't list «nonce», but its ID tokens carry it: required
	if subtle.ConstantTimeCompare([]byte(tok.Nonce), []byte(o.Nonce)) != 1 {
		a.log.Printf("telegram login failed: nonce mismatch")
		page(w, http.StatusBadRequest, pageFailed(o.Next))
		return
	}
	var claims map[string]json.RawMessage
	_ = tok.Claims(&claims)
	id := telegramID(claims["id"], tok.Subject)
	if id == "" {
		a.log.Printf("telegram login failed: no numeric id in the ID token")
		page(w, http.StatusBadGateway, pageFailed(o.Next))
		return
	}
	s := sessionData{ID: id, Name: str(claims["name"]), Username: str(claims["preferred_username"]), At: a.now().Unix()}
	a.log.Printf("telegram login: %s (%s @%s)", id, s.Name, s.Username)
	a.setCookie(w, a.sessionName, a.sign("session", s, sessionTTL), int(sessionTTL.Seconds()))
	redirect(w, o.Next)
}

// telegramID: the numeric id from Telegram's «id» claim (number or string); «sub» only if it is that number
func telegramID(raw json.RawMessage, sub string) string {
	if s := strings.Trim(string(bytes.TrimSpace(raw)), `"`); digits.MatchString(s) {
		return s
	}
	if digits.MatchString(sub) {
		return sub
	}
	return ""
}

func str(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}
