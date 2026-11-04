package hub

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

	"hub/internal/store"
)

// admin: the logged-in person if they are the admin, with a passkey, else nil. Telegram alone
// never makes anyone admin: a Telegram account is only as safe as its SMS and sessions.
func (a *Server) admin(r *http.Request) *store.Person {
	if a.cfg.Admin == "" {
		return nil
	}
	id, err := a.resolve(a.session(r))
	if err != nil || id.person == nil || id.person.Key != a.cfg.Admin || id.pk == nil {
		return nil
	}
	return id.person
}

func (a *Server) backupToken(r *http.Request) bool {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && len(a.cfg.BackupToken) >= 32 && subtle.ConstantTimeCompare([]byte(token), []byte(a.cfg.BackupToken)) == 1
}

// backup: a consistent snapshot of the database (VACUUM INTO), streamed and then deleted
func (a *Server) backup(w http.ResponseWriter, r *http.Request) {
	who := "backup token"
	if !a.backupToken(r) {
		// a download started by another site's link or form is refused, even for the admin
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			text(w, http.StatusForbidden, "Only from the hub's own pages")
			return
		}
		p := a.admin(r)
		if p == nil {
			a.log.Printf("backup refused")
			text(w, http.StatusForbidden, "Admin only")
			return
		}
		who = p.Key
	}
	tmp := filepath.Join(filepath.Dir(a.store.Path()), ".backup-"+random()[:16]+".db")
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
