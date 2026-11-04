package main

// Logout everywhere. An app clears its own cookie and sends people to GET /logout?client_id=…
// &post_logout_redirect_uri=…; the hub asks «Выйти на всех сайтах?», and the button posts back.
// The return address is used only if it is listed for that app, exactly.

import (
	"net/http"
	"net/url"
)

type logoutTarget struct {
	app   *client // nil if the request named no known app
	back  string  // "" unless listed for app
	state string
}

func (a *app) logoutTarget(v url.Values) logoutTarget {
	c, err := a.store.App(v.Get("client_id"))
	if err != nil {
		a.log.Printf("logout: database: %v", err)
	}
	t := logoutTarget{app: c}
	if t.app != nil && t.app.logouts[v.Get("post_logout_redirect_uri")] {
		t.back, t.state = v.Get("post_logout_redirect_uri"), v.Get("state")
	} else if v.Get("post_logout_redirect_uri") != "" {
		a.log.Printf("logout: return address %q is not listed for %q", v.Get("post_logout_redirect_uri"), v.Get("client_id"))
	}
	return t
}

func (t logoutTarget) url() string {
	if t.state == "" {
		return t.back
	}
	u, _ := url.Parse(t.back)
	q := u.Query()
	q.Set("state", t.state)
	u.RawQuery = q.Encode()
	return u.String()
}

func (a *app) logoutPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "Cookie")
	t := a.logoutTarget(r.URL.Query())
	id, err := a.resolve(a.session(r))
	if err != nil {
		a.broken(w, err)
		return
	}
	if !id.proven() { // nothing to ask about
		if t.back != "" {
			redirect(w, t.url())
			return
		}
		page(w, http.StatusOK, pageLoggedOut(t))
		return
	}
	pageCSP(w, http.StatusOK, pageLogout(id, t), formActionFor(t.back))
}

// logout: a POST from the hub's own page only (not merely the same site: every app on
// *.almaz.dev is «same-site»), so a link or form elsewhere can't log anyone out
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	origin, site := r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site")
	// Sec-Fetch-Site is set by the browser and can't be faked by a page; browsers without it send Origin
	same := site == "same-origin" || site == "" && origin == a.issuer
	if !same {
		a.log.Printf("logout refused: origin %q, fetch site %q", origin, site)
		text(w, http.StatusForbidden, "Выйти можно только со страницы входа")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	_ = r.ParseForm()
	t := a.logoutTarget(r.PostForm)
	if id, err := a.resolve(a.session(r)); err == nil && id.proven() {
		a.log.Printf("logout: %s", id.label())
	}
	a.setCookie(w, a.sessionName, "", -1)
	if t.back != "" {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Location", t.url())
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	page(w, http.StatusOK, pageLoggedOut(t))
}

// formActionFor: browsers check form-action on the redirect after a POST too, so the logout page
// allows the one address the hub will send people back to
func formActionFor(back string) string {
	u, err := url.Parse(back)
	if back == "" || err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
