package main

// The passkey login, with p2pvc's rules: discoverable credentials, user verification required,
// and who logs in is decided by the credential id and its signature alone. The user handle the
// authenticator returns isn't signed and some password managers (NordPass) alter it, so it is
// only compared and logged. The RP ID is the hub's host: one passkey works for every app.
//
//	GET  /login/passkey?next=…    the page; its script runs navigator.credentials.get
//	POST /login/passkey/options   a challenge (single use, 5 minutes)
//	POST /login/passkey/verify    the signed answer → a passkey proof in the hub session

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const challengeTTL = 5 * time.Minute

func newWebAuthn(issuer string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}
	return webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "Вход",
		RPOrigins:     []string{issuer},
	})
}

// waUser: a person as go-webauthn sees them
type waUser struct {
	handle []byte
	name   string
	creds  []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return u.handle }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.name }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (a *app) waUser(p *Person) (*waUser, error) {
	handle, err := a.store.WebAuthnHandle(p.Key)
	if err != nil {
		return nil, err
	}
	rows, err := a.store.Passkeys(p.Key)
	if err != nil {
		return nil, err
	}
	u := &waUser{handle: handle, name: p.Name}
	for _, raw := range rows {
		var c webauthn.Credential
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		u.creds = append(u.creds, c)
	}
	return u, nil
}

func (a *app) passkeyPage(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	pageScript(w, http.StatusOK, pagePasskey(next))
}

// sameOrigin: a request the hub's own page made (Sec-Fetch-Site, or Origin from older browsers),
// with a JSON body, so no form on another site can drive it
func (a *app) sameOrigin(r *http.Request) bool {
	site, origin := r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Origin")
	return (site == "same-origin" || site == "" && origin == a.issuer) && r.Header.Get("Content-Type") == "application/json"
}

func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	jsonOut(w, status, map[string]string{"error": msg})
}

func (a *app) passkeyOptions(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		jsonError(w, http.StatusForbidden, "Только со страницы входа")
		return
	}
	// no allowCredentials: passkeys are discoverable, and listing ids would hand them to anyone
	options, session, err := a.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		a.log.Printf("passkey options: %v", err)
		jsonError(w, http.StatusInternalServerError, "Не получилось начать вход")
		return
	}
	data, _ := json.Marshal(session)
	id := random()
	if err := a.store.PutChallenge(id, "login", data, "", challengeTTL); err != nil {
		a.log.Printf("passkey options: %v", err)
		jsonError(w, http.StatusServiceUnavailable, "Слишком много входов сразу, попробуй через минуту")
		return
	}
	jsonOut(w, http.StatusOK, map[string]any{"challenge": id, "options": options})
}

func (a *app) passkeyVerify(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		jsonError(w, http.StatusForbidden, "Только со страницы входа")
		return
	}
	var in struct {
		Challenge  string          `json:"challenge"`
		Next       string          `json:"next"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "Не получилось прочитать ответ passkey")
		return
	}
	data, _, ok, err := a.store.TakeChallenge(in.Challenge, "login")
	if err != nil {
		a.log.Printf("passkey login: %v", err)
		jsonError(w, http.StatusInternalServerError, "Не получилось войти")
		return
	}
	if !ok {
		jsonError(w, http.StatusBadRequest, "Вход устарел. Попробуй ещё раз")
		return
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		jsonError(w, http.StatusInternalServerError, "Не получилось войти")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(in.Credential)
	if err != nil {
		a.log.Printf("passkey login failed: parse: %v", err)
		jsonError(w, http.StatusBadRequest, "Не получилось прочитать ответ passkey")
		return
	}

	var owner *Person
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		key, err := a.store.PasskeyOwner(rawID)
		if err != nil || key == "" {
			return nil, errors.New("unknown credential")
		}
		if owner, err = a.store.Person(key); err != nil || owner == nil {
			return nil, errors.New("unknown person")
		}
		u, err := a.waUser(owner)
		if err != nil {
			return nil, err
		}
		if string(userHandle) != string(u.handle) {
			a.log.Printf("passkey: user handle differs from the stored one (%d bytes, %d expected): ignored", len(userHandle), len(u.handle))
		}
		u.handle = userHandle // go-webauthn insists they match; the signature decides
		return u, nil
	}
	_, cred, err := a.wa.ValidatePasskeyLogin(handler, session, parsed)
	if err != nil {
		if owner == nil {
			a.log.Printf("passkey login failed: unknown credential %s", b64.EncodeToString(parsed.RawID)[:min(8, len(b64.EncodeToString(parsed.RawID)))])
			jsonError(w, http.StatusForbidden, "Этот passkey здесь не знают. Возможно, его удалили")
			return
		}
		a.log.Printf("passkey login failed: %s: %v", owner.Key, describe(err))
		jsonError(w, http.StatusForbidden, "Passkey не подтвердился")
		return
	}
	if cred.Authenticator.CloneWarning {
		a.log.Printf("passkey: %s: the sign counter went backwards (a cloned authenticator?)", owner.Key)
	}
	updated, _ := json.Marshal(cred)
	if err := a.store.PasskeyUsed(cred.ID, updated); err != nil {
		a.log.Printf("passkey: %v", err)
	}
	s, person, err := a.addProof(a.session(r), nil, &pkProof{Person: owner.Key, Cred: b64.EncodeToString(cred.ID), At: a.now().Unix()})
	if err != nil || person == nil {
		a.log.Printf("passkey login failed: %v", err)
		jsonError(w, http.StatusInternalServerError, "Не получилось войти")
		return
	}
	a.log.Printf("passkey login: %s", person.Key)
	a.saveSession(w, s)
	jsonOut(w, http.StatusOK, map[string]string{"next": safeNext(in.Next)})
}

func describe(err error) string {
	var pe *protocol.Error
	if errors.As(err, &pe) {
		return pe.Type + ": " + pe.Details + " " + pe.DevInfo
	}
	return err.Error()
}
