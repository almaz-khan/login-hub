package main

// The admin UI: a SvelteKit app (admin/, adapter-static, base /admin) built into admin/build and
// embedded in the binary. Only the admin gets any of it, assets included. Its CSP header is made
// here from the inline scripts SvelteKit writes into 200.html, so the page runs exactly those and
// its own files: script-src 'self' plus their hashes, style-src 'self', connect-src 'self'.

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"regexp"
	"strings"
)

//go:embed all:admin/build
var adminBuild embed.FS

type adminUI struct {
	files fs.FS
	index []byte // 200.html, the SPA fallback; nil when the UI isn't built
	csp   string
}

var inlineScript = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

func loadAdminUI() *adminUI {
	sub, _ := fs.Sub(adminBuild, "admin/build")
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
	ui.csp = "default-src 'none'; script-src " + strings.Join(scripts, " ") +
		"; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	return ui
}

func (a *app) adminUI(w http.ResponseWriter, r *http.Request) {
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
