package hub

// The admin UI: a SvelteKit app (admin/, adapter-static, base /admin) built into admin/build and
// embedded in the binary (package admin). Only the admin gets any of it, assets included. Its CSP
// header is made here from the build itself: script-src 'self' plus the hashes of the inline
// scripts SvelteKit writes into 200.html, and style-src 'self' plus 'unsafe-hashes' for exactly
// the style attributes the bundle sets (SvelteKit's visually hidden route announcer; the UI's own
// code sets none). connect-src 'self'; nothing else.

import (
	"io/fs"
	"mime"
	"net/http"
	"path"
	"regexp"
	"strings"

	"hub/admin"
)

type adminUI struct {
	files fs.FS
	index []byte // 200.html, the SPA fallback; nil when the UI isn't built
	csp   string
}

var (
	inlineScript = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	styleAttr    = regexp.MustCompile(`style="([^"]+)"`)
)

func loadAdminUI() *adminUI {
	sub := admin.FS()
	ui := &adminUI{files: sub}
	index, err := fs.ReadFile(sub, "200.html")
	if err != nil {
		return ui
	}
	ui.index = index
	scripts := []string{"'self'"}
	for _, m := range inlineScript.FindAllSubmatch(index, -1) {
		scripts = append(scripts, "'"+hash(string(m[1]))+"'")
	}
	styles := []string{"'self'"}
	seen := map[string]bool{}
	_ = fs.WalkDir(sub, "_app", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(name, ".js") {
			return nil
		}
		js, _ := fs.ReadFile(sub, name)
		for _, m := range styleAttr.FindAllSubmatch(js, -1) {
			if h := "'" + hash(string(m[1])) + "'"; !seen[h] {
				seen[h] = true
				styles = append(styles, h)
			}
		}
		return nil
	})
	if len(styles) > 1 {
		styles = append(styles[:1], append([]string{"'unsafe-hashes'"}, styles[1:]...)...)
	}
	ui.csp = "default-src 'none'; script-src " + strings.Join(scripts, " ") + "; style-src " + strings.Join(styles, " ") +
		"; connect-src 'self'; img-src 'self' data:; font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	return ui
}

func (a *Server) adminUI(w http.ResponseWriter, r *http.Request) {
	if a.admin(r) == nil {
		page(w, http.StatusForbidden, pageAdminOnly)
		return
	}
	ui := a.ui
	if ui.index == nil {
		page(w, http.StatusServiceUnavailable, pageUINotBuilt)
		return
	}
	h := w.Header()
	h.Add("Vary", "Cookie")
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/admin")
	name = strings.TrimPrefix(name, "/")
	if name != "" && name != "200.html" {
		if body, err := fs.ReadFile(ui.files, name); err == nil {
			ct := mime.TypeByExtension(path.Ext(name))
			if ct == "" {
				ct = "application/octet-stream"
			}
			h.Set("Content-Type", ct)
			if strings.HasPrefix(name, "_app/immutable/") {
				h.Set("Cache-Control", "private, max-age=31536000, immutable")
			} else {
				h.Set("Cache-Control", "no-store")
			}
			_, _ = w.Write(body)
			return
		}
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", ui.csp)
	_, _ = w.Write(ui.index)
}
