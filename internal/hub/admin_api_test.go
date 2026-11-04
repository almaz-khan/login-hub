package hub

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"hub/internal/store"
)

// call: the admin UI's fetch: same-origin, JSON; the status and the decoded answer
func (e *env) call(b *browser, method, path string, in any, headers ...string) (int, map[string]any) {
	e.t.Helper()
	var body io.Reader
	if in != nil {
		raw, _ := json.Marshal(in)
		body = strings.NewReader(string(raw))
	}
	req, _ := http.NewRequest(method, e.url+path, body)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := b.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		out = map[string]any{"raw": string(raw)}
	}
	return resp.StatusCode, out
}

func (e *env) mustCall(b *browser, method, path string, in any) map[string]any {
	e.t.Helper()
	status, out := e.call(b, method, path, in)
	if status != http.StatusOK {
		e.t.Fatalf("%s %s: %d %v", method, path, status, out)
	}
	return out
}

func (e *env) state(b *browser) store.State {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.url+"/admin/api/state", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := b.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var st store.State
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil || resp.StatusCode != http.StatusOK {
		e.t.Fatalf("state: %d %v", resp.StatusCode, err)
	}
	return st
}

func (e *env) adminBrowser() *browser {
	e.t.Helper()
	b := e.browser()
	e.tg.as(alice, "Alice", "alice")
	e.rp("running-club").login(b)
	return b
}

func TestAdminAPIGuards(t *testing.T) {
	e := setup(t)
	anon := e.browser()
	if status, _ := e.call(anon, http.MethodGet, "/admin/api/state", nil); status != http.StatusForbidden {
		t.Fatalf("anonymous: %d", status)
	}
	e.tg.as(bob, "Bob", "bob")
	bob := e.browser()
	e.rp("stub").login(bob)
	if status, _ := e.call(bob, http.MethodGet, "/admin/api/state", nil); status != http.StatusForbidden {
		t.Fatalf("not admin: %d", status)
	}
	admin := e.adminBrowser()
	for name, h := range map[string][]string{
		"same-site":  {"Sec-Fetch-Site", "same-site"},
		"cross-site": {"Sec-Fetch-Site", "cross-site"},
		"form":       {"Content-Type", "application/x-www-form-urlencoded"},
	} {
		if status, _ := e.call(admin, http.MethodPost, "/admin/api/groups", map[string]string{"name": "x"}, h...); status != http.StatusForbidden {
			t.Errorf("%s: %d", name, status)
		}
	}
	if status, _ := e.call(admin, http.MethodPost, "/admin/api/groups", map[string]any{"name": "x", "extra": 1}); status != http.StatusBadRequest {
		t.Errorf("unknown field: %d", status)
	}
	if status, _ := e.call(admin, http.MethodGet, "/admin/api/nope", nil); status != http.StatusNotFound {
		t.Errorf("unknown path: %d", status)
	}
	if status, out := e.call(admin, http.MethodPatch, "/admin/api/people/Bob", map[string]string{}); status != http.StatusNotFound || out["error"] == "" {
		t.Errorf("wrong method: %d %v", status, out) // the JSON catch-all, not a 405
	}
	st := e.state(admin)
	if st.Me != "Alice" || st.Notify != "Alice" || len(st.People) != 3 || len(st.Apps) != 5 || len(st.Groups) != 1 {
		t.Fatalf("state: %+v", st)
	}
}

func TestAdminPeopleAndGroups(t *testing.T) {
	e := setup(t)
	admin := e.adminBrowser()

	e.mustCall(admin, http.MethodPost, "/admin/api/people", map[string]string{"key": "Dave", "name": " Дэйв ", "telegram_id": dave})
	for name, in := range map[string]map[string]string{
		"bad key":       {"key": "Dave Smith", "name": "x"},
		"no name":       {"key": "Eve", "name": " "},
		"bad telegram":  {"key": "Eve", "name": "Eve", "telegram_id": "@eve"},
		"same telegram": {"key": "Eve", "name": "Eve", "telegram_id": dave},
		"same key":      {"key": "Dave", "name": "Dave"},
	} {
		if status, out := e.call(admin, http.MethodPost, "/admin/api/people", in); status != http.StatusBadRequest || out["error"] == "" {
			t.Errorf("%s: %d %v", name, status, out)
		}
	}

	// a new group with Dave, given an app: he gets in without anything else
	e.mustCall(admin, http.MethodPost, "/admin/api/groups", map[string]string{"name": "friends"})
	e.mustCall(admin, http.MethodPut, "/admin/api/groups/friends/members", map[string][]string{"members": {"Dave", "Dave", "Bob"}})
	if status, _ := e.call(admin, http.MethodPut, "/admin/api/groups/friends/members", map[string][]string{"members": {"Nobody"}}); status != http.StatusBadRequest {
		t.Errorf("unknown member: %d", status)
	}
	e.mustCall(admin, http.MethodPut, "/admin/api/apps/stub", map[string]any{
		"name": "Stub", "redirect_uris": []string{appURL("stub") + "/auth/callback"}, "post_logout_redirect_uris": []string{appURL("stub") + "/"},
		"login": []string{"telegram"}, "allow": []string{"group:friends"},
	})
	e.tg.as(dave, "Dave", "dave")
	if idt := e.rp("stub").login(e.browser()); idt.Subject != "Dave" {
		t.Fatal(idt.Subject)
	}
	st := e.state(admin)
	var dv store.StatePerson
	for _, p := range st.People {
		if p.Key == "Dave" {
			dv = p
		}
	}
	if dv.Name != "Дэйв" || strings.Join(dv.Groups, ",") != "friends" || strings.Join(dv.Apps, ",") != "stub" || dv.LastSeen == 0 {
		t.Fatalf("Dave: %+v", dv)
	}

	// edits
	e.mustCall(admin, http.MethodPut, "/admin/api/people/Dave", map[string]string{"name": "Дэйв Д", "telegram_id": ""})
	if status, _ := e.call(admin, http.MethodPut, "/admin/api/people/Nobody", map[string]string{"name": "x"}); status != http.StatusBadRequest {
		t.Errorf("edit nobody: %d", status)
	}
	// the admin can't lock themselves out
	if status, out := e.call(admin, http.MethodPut, "/admin/api/people/Alice", map[string]string{"name": "Алиса", "telegram_id": ""}); status != http.StatusBadRequest || !strings.Contains(out["error"].(string), "админ не сможет войти") {
		t.Errorf("admin without a way in: %d %v", status, out)
	}
	if status, _ := e.call(admin, http.MethodDelete, "/admin/api/people/Alice", nil); status != http.StatusBadRequest {
		t.Errorf("delete admin: %d", status)
	}
	// notify must be someone the bot can write to
	if status, _ := e.call(admin, http.MethodPut, "/admin/api/settings", map[string]string{"notify": "Dave"}); status != http.StatusBadRequest {
		t.Errorf("notify without telegram: %d", status)
	}
	e.mustCall(admin, http.MethodPut, "/admin/api/settings", map[string]string{"notify": "Bob"})
	// deleting Bob clears notify and his group place
	e.mustCall(admin, http.MethodDelete, "/admin/api/people/Bob", nil)
	e.mustCall(admin, http.MethodDelete, "/admin/api/groups/friends", nil)
	st = e.state(admin)
	if st.Notify != "" || len(st.Groups) != 1 || len(st.People) != 3 {
		t.Fatalf("after deletes: notify %q, %d groups, %d people", st.Notify, len(st.Groups), len(st.People))
	}

	audit := e.mustCall(admin, http.MethodGet, "/admin/api/audit", nil)
	_ = audit
	entries, _ := e.cfg.Store.Audit(0, 100)
	if len(entries) < 8 || entries[0].Action != "group delete" || entries[0].Actor != "Alice" {
		t.Fatalf("audit: %+v", entries[:min(3, len(entries))])
	}
	older, _ := e.cfg.Store.Audit(entries[2].ID, 1)
	if len(older) != 1 || older[0].ID != entries[3].ID {
		t.Fatal("audit paging")
	}
}

func TestAdminApps(t *testing.T) {
	e := setup(t)
	admin := e.adminBrowser()
	app := map[string]any{
		"id": "new-app", "name": "Новый сайт", "redirect_uris": []string{"http://[::1]:7/auth/callback"},
		"post_logout_redirect_uris": []string{}, "login": []string{"telegram", "passkey"}, "allow": []string{"Alice"},
	}
	out := e.mustCall(admin, http.MethodPost, "/admin/api/apps", app)
	secret, _ := out["secret"].(string)
	if len(secret) != 64 {
		t.Fatalf("secret %q", secret)
	}
	// it works as an OIDC client right away, with that secret
	secrets["new-app"] = secret
	defer delete(secrets, "new-app")
	r := e.rp("new-app")
	r.oauth.RedirectURL = "http://[::1]:7/auth/callback"
	if idt := r.login(admin); idt.Subject != "Alice" {
		t.Fatal(idt.Subject)
	}
	// a new secret: the old one stops working
	out = e.mustCall(admin, http.MethodPost, "/admin/api/apps/new-app/secret", nil)
	a := r.start()
	code := r.back(admin.get(a.url), a)
	if _, err := r.exchange(code, a); err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("old secret: %v", err)
	}
	r.oauth.ClientSecret = out["secret"].(string)
	a = r.start()
	if _, err := r.exchange(r.back(admin.get(a.url), a), a); err != nil {
		t.Fatalf("new secret: %v", err)
	}

	for name, mod := range map[string]func(map[string]any){
		"http":        func(m map[string]any) { m["redirect_uris"] = []string{"http://app.example/cb"} },
		"no login":    func(m map[string]any) { m["login"] = []string{} },
		"bad method":  func(m map[string]any) { m["login"] = []string{"sms"} },
		"bad allow":   func(m map[string]any) { m["allow"] = []string{"group:nope"} },
		"bad id":      func(m map[string]any) { m["id"] = "New App" },
		"same id":     func(m map[string]any) {},
		"no redirect": func(m map[string]any) { m["redirect_uris"] = []string{} },
	} {
		in := map[string]any{}
		for k, v := range app {
			in[k] = v
		}
		mod(in)
		if status, out := e.call(admin, http.MethodPost, "/admin/api/apps", in); status != http.StatusBadRequest || out["error"] == "" {
			t.Errorf("%s: %d %v", name, status, out)
		}
	}
	// the database never stores the secret itself
	var n int
	_ = e.cfg.Store.DB().QueryRow(`SELECT count(*) FROM audit WHERE detail LIKE ?`, "%"+secret[:16]+"%").Scan(&n)
	if n != 0 {
		t.Fatal("secret in the audit log")
	}
	e.mustCall(admin, http.MethodDelete, "/admin/api/apps/new-app", nil)
	if c, _ := e.cfg.Store.App("new-app"); c != nil {
		t.Fatal("still there")
	}
}

func TestAdminPasskeys(t *testing.T) {
	e := setup(t)
	admin := e.adminBrowser()
	soft := e.enroll("Bob")
	st := e.state(admin)
	var id string
	for _, p := range st.People {
		if p.Key == "Bob" && len(p.Passkeys) == 1 {
			id = p.Passkeys[0].ID
		}
	}
	if id == "" {
		t.Fatalf("Bob's passkey not listed: %+v", st.People)
	}
	e.mustCall(admin, http.MethodDelete, "/admin/api/passkeys/"+id, nil)
	if resp := e.passkey(e.browser(), soft, "/"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("deleted passkey still logs in: %d", resp.StatusCode)
	}
	// the admin's last way in can't go: Alice, logged in with her only passkey, no Telegram id
	nextOf(t, e.passkey(admin, e.enroll("Alice"), "/"))
	e.exec(`UPDATE people SET telegram_id = NULL WHERE key = 'Alice'`)
	var aliceKey []byte
	_ = e.cfg.Store.DB().QueryRow(`SELECT id FROM passkeys WHERE person = 'Alice'`).Scan(&aliceKey)
	if status, _ := e.call(admin, http.MethodDelete, "/admin/api/passkeys/"+b64.EncodeToString(aliceKey), nil); status != http.StatusBadRequest {
		t.Fatalf("admin's last passkey: %d", status)
	}
}

func TestAdminUIServing(t *testing.T) {
	e := setup(t)
	if resp := e.browser().get(e.url + "/admin"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("anonymous: %d", resp.StatusCode)
	}
	admin := e.adminBrowser()
	resp := admin.get(e.url + "/admin")
	if e.app.Load().ui.index == nil {
		// a hub built without the UI says so
		if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body(resp), "Админка не собрана") {
			t.Fatalf("not built: %d", resp.StatusCode)
		}
		return
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if resp.StatusCode != http.StatusOK || !strings.Contains(csp, "script-src 'self' 'sha256-") || strings.Contains(csp, "unsafe") {
		t.Fatalf("ui: %d %s", resp.StatusCode, csp)
	}
	// deep links get the app too, and assets are served
	if resp := admin.get(e.url + "/admin/people"); resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("deep link: %d", resp.StatusCode)
	}
}
