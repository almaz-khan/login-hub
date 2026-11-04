package hub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

// register: the enrollment page's script, with a software authenticator; the verify response
func (e *env) register(b *browser, soft *softAuthenticator, token, label string) *http.Response {
	e.t.Helper()
	resp := b.postJSON(e.url+"/enroll/options", map[string]string{"token": token})
	if resp.StatusCode != http.StatusOK {
		return resp
	}
	var o struct {
		Challenge string                       `json:"challenge"`
		Options   *protocol.CredentialCreation `json:"options"`
	}
	if err := json.Unmarshal([]byte(body(resp)), &o); err != nil {
		e.t.Fatal(err)
	}
	// JSON gives user.id back as a string; the authenticator wants its bytes
	id, _ := b64.DecodeString(o.Options.Response.User.ID.(string))
	o.Options.Response.User.ID = protocol.URLEncodedBase64(id)
	return b.postJSON(e.url+"/enroll/verify", map[string]any{"challenge": o.Challenge, "label": label, "credential": json.RawMessage(soft.register(o.Options))})
}

var linkRe = regexp.MustCompile(`/enroll\?t=([\w-]+)`)

// adminLink: the admin (logged in in b) makes a passkey link for person through the API
func (e *env) adminLink(b *browser, person string) string {
	e.t.Helper()
	status, out := e.call(b, http.MethodPost, "/admin/api/people/"+person+"/enroll", nil)
	m := linkRe.FindStringSubmatch(fmt.Sprint(out["link"]))
	if status != http.StatusOK || m == nil {
		e.t.Fatalf("admin link: %d %v", status, out)
	}
	return m[1]
}

func ok(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%d %s", resp.StatusCode, body(resp))
	}
}

func TestEnrollByLink(t *testing.T) {
	e := setup(t)
	admin := e.adminBrowser()
	token := e.adminLink(admin, "Bob")

	// Bob, on his own phone, not logged in anywhere
	phone := e.browser()
	resp := phone.get(e.url + "/enroll?t=" + token)
	if page := body(resp); resp.StatusCode != http.StatusOK || !strings.Contains(page, "Для <b>Боб</b>") || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src 'sha256-") {
		t.Fatalf("enroll page: %d %s", resp.StatusCode, page)
	}
	soft := newSoftAuthenticator(e.url, "localhost")
	ok(t, e.register(phone, soft, token, "  Bob's   iPhone\n"))

	var label string
	_ = e.cfg.Store.DB().QueryRow(`SELECT label FROM passkeys WHERE person = 'Bob'`).Scan(&label)
	if label != "Bob's iPhone" {
		t.Fatalf("label %q", label)
	}
	e.app.Load().wg.Wait()
	if m := e.bot.messages(); len(m) != 1 || !strings.Contains(m[0]["text"].(string), "Новый passkey: Bob") || m[0]["chat_id"] != alice {
		t.Fatalf("bot: %v", m)
	}
	// the new passkey already logs him in on that phone, and works for logins later
	if page := body(phone.get(e.url + "/")); !strings.Contains(page, "<b>Боб</b>, через passkey") {
		t.Fatal(page)
	}
	nextOf(t, e.passkey(e.browser(), soft, "/"))

	// the link worked once
	if resp := phone.get(e.url + "/enroll?t=" + token); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("used link page: %d", resp.StatusCode)
	}
	if resp := e.register(e.browser(), newSoftAuthenticator(e.url, "localhost"), token, "x"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("used link: %d", resp.StatusCode)
	}
}

func TestEnrollLinkRaces(t *testing.T) {
	e := setup(t)
	admin := e.adminBrowser()
	token := e.adminLink(admin, "Bob")
	// two devices start with the same link; only the first to finish gets a passkey
	a, b := e.browser(), e.browser()
	optA := a.postJSON(e.url+"/enroll/options", map[string]string{"token": token})
	ok(t, optA)
	ok(t, e.register(b, newSoftAuthenticator(e.url, "localhost"), token, "first"))
	var o struct {
		Challenge string                       `json:"challenge"`
		Options   *protocol.CredentialCreation `json:"options"`
	}
	_ = json.Unmarshal([]byte(body(optA)), &o)
	id, _ := b64.DecodeString(o.Options.Response.User.ID.(string))
	o.Options.Response.User.ID = protocol.URLEncodedBase64(id)
	late := a.postJSON(e.url+"/enroll/verify", map[string]any{"challenge": o.Challenge, "label": "second", "credential": json.RawMessage(newSoftAuthenticator(e.url, "localhost").register(o.Options))})
	if late.StatusCode != http.StatusForbidden || !strings.Contains(body(late), "использована") {
		t.Fatalf("second device: %d", late.StatusCode)
	}
	var n int
	_ = e.cfg.Store.DB().QueryRow(`SELECT count(*) FROM passkeys WHERE person = 'Bob'`).Scan(&n)
	if n != 1 {
		t.Fatalf("%d passkeys", n)
	}
	// and a link lasts 24 hours
	token = e.adminLink(admin, "Carol")
	e.shift.Add(int64((enrollTTL + time.Minute) / time.Second))
	if resp := e.browser().get(e.url + "/enroll?t=" + token); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expired link: %d", resp.StatusCode)
	}
}

func TestEnrollSelf(t *testing.T) {
	e := setup(t)
	b := e.browser()
	if resp := b.get(e.url + "/enroll"); resp.StatusCode != http.StatusForbidden || !strings.Contains(body(resp), "Сначала войди") {
		t.Fatalf("not logged in: %d", resp.StatusCode)
	}
	if resp := e.register(b, newSoftAuthenticator(e.url, "localhost"), "", "x"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("options without login: %d", resp.StatusCode)
	}
	e.rp("running-club").login(b) // Alice by Telegram
	if page := body(b.get(e.url + "/")); !strings.Contains(page, `href="/enroll"`) {
		t.Fatal(page)
	}
	soft := newSoftAuthenticator(e.url, "localhost")
	ok(t, e.register(b, soft, "", "Mac"))
	// now the passkey-only app opens silently, with both proofs
	idt := e.rp("pk").login(b)
	var c struct {
		AMR []string `json:"amr"`
	}
	_ = idt.Claims(&c)
	if idt.Subject != "Alice" || strings.Join(c.AMR, ",") != "telegram,passkey" {
		t.Fatalf("%s %v", idt.Subject, c.AMR)
	}
	// the same authenticator again: refused, not duplicated
	if resp := e.register(b, soft, "", "Mac again"); resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate: %d", resp.StatusCode)
	}
}

func TestEnrollRefusals(t *testing.T) {
	e := setup(t)
	b := e.browser()
	e.rp("running-club").login(b)
	soft := newSoftAuthenticator(e.url, "localhost")
	soft.origin = "https://evil.example"
	if resp := e.register(b, soft, "", "x"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong origin: %d", resp.StatusCode)
	}
	if resp := b.postJSON(e.url+"/enroll/options", map[string]string{}, "Sec-Fetch-Site", "cross-site"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site: %d", resp.StatusCode)
	}
	if resp := e.register(b, newSoftAuthenticator(e.url, "localhost"), "not-a-token", "x"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("made-up token: %d", resp.StatusCode)
	}
}
