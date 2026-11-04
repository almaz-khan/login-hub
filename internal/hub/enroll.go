package hub

// Adding passkeys. Two ways in:
//
//   - a link the admin made for a person (/enroll?t=…): single use, 24 hours, only its hash kept;
//   - someone already logged in (any method that resolves to them) adding this device (/enroll).
//
// The passkey is saved at once and proves the person in this browser too. The bot tells the
// notify person. Resident key and user verification are required, as for the login.
//
//	GET  /enroll[?t=…]        the page; the same script as the login, its «create» half
//	POST /enroll/options      registration options for that person (single-use challenge)
//	POST /enroll/verify       the new credential → saved

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"hub/internal/store"
)

const (
	enrollTTL     = 24 * time.Hour
	maxLabelRunes = 60
)

// enrollSubject: whom a passkey made now would belong to: the link's person, or the logged-in one
func (a *Server) enrollSubject(r *http.Request, token string) (*store.Person, error) {
	if token != "" {
		key, err := a.store.Enrollment(token)
		if err != nil || key == "" {
			return nil, err
		}
		return a.store.Person(key)
	}
	id, err := a.resolve(a.session(r))
	return id.person, err
}

func (a *Server) enrollPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("t")
	p, err := a.enrollSubject(r, token)
	switch {
	case err != nil:
		a.broken(w, err)
	case p == nil && token != "":
		page(w, http.StatusNotFound, pageLinkUsed)
	case p == nil:
		page(w, http.StatusForbidden, pageLoginFirst)
	default:
		pageScript(w, http.StatusOK, pageEnroll(p, token))
	}
}

type enrollChallenge struct {
	Session  webauthn.SessionData `json:"session"`
	LinkHash []byte               `json:"link,omitempty"`
}

func (a *Server) enrollOptions(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		jsonError(w, http.StatusForbidden, "Только со страницы входа")
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&in)
	p, err := a.enrollSubject(r, in.Token)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Не получилось начать")
		return
	}
	if p == nil {
		jsonError(w, http.StatusForbidden, "Ссылка уже использована или устарела")
		return
	}
	u, err := a.waUser(p)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Не получилось начать")
		return
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(u.creds))
	for _, c := range u.creds {
		exclude = append(exclude, c.Descriptor())
	}
	options, session, err := a.wa.BeginRegistration(u,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExclusions(exclude),
	)
	if err != nil {
		a.log.Printf("enroll options: %v", err)
		jsonError(w, http.StatusInternalServerError, "Не получилось начать")
		return
	}
	ch := enrollChallenge{Session: *session}
	if in.Token != "" {
		ch.LinkHash = store.TokenHash(in.Token)
	}
	data, _ := json.Marshal(ch)
	id := random()
	if err := a.store.PutChallenge(id, "register", data, p.Key, challengeTTL); err != nil {
		jsonError(w, http.StatusServiceUnavailable, "Слишком много запросов сразу, попробуй через минуту")
		return
	}
	jsonOut(w, http.StatusOK, map[string]any{"challenge": id, "options": options})
}

func (a *Server) enrollVerify(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		jsonError(w, http.StatusForbidden, "Только со страницы входа")
		return
	}
	var in struct {
		Challenge  string          `json:"challenge"`
		Label      string          `json:"label"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "Не получилось прочитать ответ passkey")
		return
	}
	data, key, ok, err := a.store.TakeChallenge(in.Challenge, "register")
	if err != nil || !ok {
		jsonError(w, http.StatusBadRequest, "Запрос устарел. Попробуй ещё раз")
		return
	}
	var ch enrollChallenge
	if err := json.Unmarshal(data, &ch); err != nil {
		jsonError(w, http.StatusInternalServerError, "Не получилось сохранить")
		return
	}
	p, err := a.store.Person(key)
	if err != nil || p == nil {
		jsonError(w, http.StatusForbidden, "Такого человека больше нет")
		return
	}
	// without a link, it must still be that person logged in here
	if ch.LinkHash == nil {
		id, err := a.resolve(a.session(r))
		if err != nil || id.person == nil || id.person.Key != p.Key {
			jsonError(w, http.StatusForbidden, "Войди снова и попробуй ещё раз")
			return
		}
	}
	u, err := a.waUser(p)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Не получилось сохранить")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(in.Credential)
	if err != nil {
		a.log.Printf("enroll failed: %s: parse: %v", p.Key, err)
		jsonError(w, http.StatusBadRequest, "Не получилось прочитать ответ passkey")
		return
	}
	cred, err := a.wa.CreateCredential(u, ch.Session, parsed)
	if err != nil {
		a.log.Printf("enroll failed: %s: %s", p.Key, describe(err))
		jsonError(w, http.StatusForbidden, "Passkey не подтвердился")
		return
	}
	label := cleanLabel(in.Label)
	stored, _ := json.Marshal(cred)
	if ch.LinkHash != nil {
		err = a.store.AddPasskeyWithLink(ch.LinkHash, p.Key, cred.ID, stored, label)
	} else {
		err = a.store.AddPasskey(p.Key, cred.ID, stored, label, p.Key)
	}
	switch {
	case errors.Is(err, store.ErrLinkUsed):
		jsonError(w, http.StatusForbidden, "Ссылка уже использована или устарела")
		return
	case err != nil && strings.Contains(err.Error(), "UNIQUE"):
		jsonError(w, http.StatusConflict, "Этот passkey уже добавлен")
		return
	case err != nil:
		a.log.Printf("enroll failed: %s: %v", p.Key, err)
		jsonError(w, http.StatusInternalServerError, "Не получилось сохранить")
		return
	}
	how := "сам, войдя"
	if ch.LinkHash != nil {
		how = "по ссылке"
	}
	a.log.Printf("passkey added: %s («%s», %s)", p.Key, label, how)
	a.tell("🔑 Новый passkey: " + p.Key + " («" + label + "», " + how + ")")
	s, _, err := a.addProof(a.session(r), nil, &pkProof{Person: p.Key, Cred: b64.EncodeToString(cred.ID), At: a.now().Unix()})
	if err == nil {
		a.saveSession(w, s)
	}
	jsonOut(w, http.StatusOK, map[string]bool{"done": true})
}

// cleanLabel: the device name, trimmed to something a list can show
func cleanLabel(s string) string {
	s = strings.Join(strings.Fields(strings.ToValidUTF8(s, "")), " ")
	if utf8.RuneCountInString(s) > maxLabelRunes {
		s = string([]rune(s)[:maxLabelRunes])
	}
	return or(s, "Passkey")
}
