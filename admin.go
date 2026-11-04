package main

// Admin endpoints. For now only the backup; the admin UI and its API come in the last phase.
// An admin is the person whose key is HUB_ADMIN, logged in to the hub; scripts/backup.sh uses
// HUB_BACKUP_TOKEN instead.

import (
	"crypto/subtle"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// admin: the logged-in person if they are the admin, else nil
func (a *app) admin(r *http.Request) *Person {
	if a.cfg.Admin == "" {
		return nil
	}
	id, err := a.resolve(a.session(r))
	if err != nil || id.person == nil || id.person.Key != a.cfg.Admin {
		return nil
	}
	return id.person
}

func (a *app) backupToken(r *http.Request) bool {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && len(a.cfg.BackupToken) >= 32 && subtle.ConstantTimeCompare([]byte(token), []byte(a.cfg.BackupToken)) == 1
}

// backup: a consistent snapshot of the database (VACUUM INTO), streamed and then deleted
func (a *app) backup(w http.ResponseWriter, r *http.Request) {
	who := "backup token"
	if !a.backupToken(r) {
		// a download started by another site's link or form is refused, even for the admin
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			text(w, http.StatusForbidden, "Только со страницы хаба")
			return
		}
		p := a.admin(r)
		if p == nil {
			a.log.Printf("backup refused")
			text(w, http.StatusForbidden, "Только для админа")
			return
		}
		who = p.Key
	}
	tmp := filepath.Join(filepath.Dir(a.store.path), ".backup-"+random()[:16]+".db")
	defer func() { _ = os.Remove(tmp) }()
	if err := a.store.Backup(tmp); err != nil {
		a.broken(w, err)
		return
	}
	f, err := os.Open(tmp)
	if err != nil {
		a.broken(w, err)
		return
	}
	defer func() { _ = f.Close() }()
	h := w.Header()
	h.Set("Content-Type", "application/vnd.sqlite3")
	h.Set("Content-Disposition", `attachment; filename="hub-`+a.now().UTC().Format("20060102T150405Z")+`.db"`)
	h.Set("Cache-Control", "no-store")
	if _, err := io.Copy(w, f); err != nil {
		a.log.Printf("backup: %v", err)
		return
	}
	a.log.Printf("backup: downloaded by %s", who)
}

// sameOriginForm: a form posted from the hub's own page
func (a *app) sameOriginForm(r *http.Request) bool {
	site, origin := r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Origin")
	return site == "same-origin" || site == "" && origin == a.issuer
}

// adminOnly: the admin for this request, or nil after answering it
func (a *app) adminOnly(w http.ResponseWriter, r *http.Request) *Person {
	if r.Method == http.MethodPost && !a.sameOriginForm(r) {
		a.log.Printf("admin: refused a post from origin %q, fetch site %q", r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site"))
		text(w, http.StatusForbidden, "Только со страницы хаба")
		return nil
	}
	p := a.admin(r)
	if p == nil {
		page(w, http.StatusForbidden, pageAdminOnly)
	}
	return p
}

// adminPage: people and their passkeys, until the admin UI
func (a *app) adminPage(w http.ResponseWriter, r *http.Request) {
	if a.adminOnly(w, r) == nil {
		return
	}
	people, err := a.store.People()
	if err != nil {
		a.broken(w, err)
		return
	}
	page(w, http.StatusOK, pageAdmin(people))
}

// adminEnroll: a passkey link for a person
func (a *app) adminEnroll(w http.ResponseWriter, r *http.Request) {
	admin := a.adminOnly(w, r)
	if admin == nil {
		return
	}
	p, err := a.store.Person(r.PostFormValue("person"))
	if err != nil || p == nil {
		text(w, http.StatusBadRequest, "Нет такого человека")
		return
	}
	token, err := a.store.CreateEnrollment(p.Key, admin.Key, enrollTTL)
	if err != nil {
		a.broken(w, err)
		return
	}
	a.log.Printf("admin: %s made a passkey link for %s", admin.Key, p.Key)
	page(w, http.StatusOK, pageEnrollLink(p, a.issuer+"/enroll?t="+token))
}

func (a *app) adminDeletePasskey(w http.ResponseWriter, r *http.Request) {
	admin := a.adminOnly(w, r)
	if admin == nil {
		return
	}
	id, err := b64.DecodeString(r.PostFormValue("id"))
	if err != nil {
		text(w, http.StatusBadRequest, "Нет такого passkey")
		return
	}
	ok, err := a.store.DeletePasskey(id, admin.Key)
	if err != nil {
		a.broken(w, err)
		return
	}
	if ok {
		a.log.Printf("admin: %s deleted a passkey", admin.Key)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", "/admin")
	w.WriteHeader(http.StatusSeeOther)
}
