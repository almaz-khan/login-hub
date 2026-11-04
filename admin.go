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
	who := a.session(r)
	if who == nil {
		return nil
	}
	p, err := a.store.PersonByTelegram(who.ID)
	if err != nil || p == nil || p.Key != a.cfg.Admin {
		return nil
	}
	return p
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
