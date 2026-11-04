// The login hub: «Войти через Telegram» once, for every app, as a small OpenID Connect provider.
//
// Apps send people to /authorize; the hub logs them in with Telegram if it has no session for them
// (/login → oauth.telegram.org → /callback), checks access.json for that app on every /authorize,
// and sends them back with a one-time code that the app exchanges at /token for an ID token signed
// with the hub's Ed25519 key. The hub keeps nothing but its session cookie and codes in memory.
// Missing or broken configuration fails closed: nothing is served and /healthz says 503.
package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-webauthn/webauthn/webauthn"

	"hub/internal/store"
)

type Config struct {
	Store         *store.Store
	StoreErr      error  // why Store is nil
	Seed          []byte // HUB_SEED: imported once into an empty database
	Admin         string // HUB_ADMIN: the person key that is always admin
	BackupToken   string // HUB_BACKUP_TOKEN: for scripts/backup.sh
	ClientID      string // Telegram (the bot's OpenID Connect client)
	ClientSecret  string
	Audience      string // Telegram's ID token aud; defaults to ClientID
	SessionSecret string // 32+ characters; changing it logs everyone out of the hub
	PublicURL     string // the issuer: https://…, no trailing slash
	SigningKey    string // base64 Ed25519 seed for ID tokens
	SigningKeyOld string // during a rotation: still listed in JWKS
	BotToken      string // optional: message the notify person about refused logins
	TGBase        string // https://oauth.telegram.org; tests point it at a fake
	BotAPI        string // https://api.telegram.org; tests point it at a fake
	Log           *log.Logger
	Client        *http.Client
	Now           func() time.Time // tests move the clock
}

var (
	publicURL = regexp.MustCompile(`^https?://[^/?#]+$`)
	digits    = regexp.MustCompile(`^\d+$`)
)

type Server struct {
	cfg         Config
	store       *store.Store
	missing     []string
	secure      bool
	issuer      string
	sessionName string // __Host-hub_session over https, hub_session over plain http (a local run)
	oauthPrefix string
	secret      []byte
	tg          string
	verifier    *oidc.IDTokenVerifier
	keys        *keySet
	wa          *webauthn.WebAuthn
	telegram    bool // Telegram login configured
	apiMux      http.Handler
	ui          *adminUI
	codes       codeStore
	discovery   []byte
	log         *log.Logger
	client      *http.Client
	now         func() time.Time

	botAPI   string
	notifyMu sync.Mutex
	notified map[string]time.Time // who was reported for which app, for one message an hour
	wg       sync.WaitGroup       // messages in flight
}

func New(cfg Config) *Server {
	a := &Server{cfg: cfg, store: cfg.Store, log: cfg.Log, client: cfg.Client, now: cfg.Now, notified: map[string]time.Time{}}
	if a.log == nil {
		a.log = log.Default()
	}
	if a.client == nil {
		a.client = &http.Client{Timeout: 15 * time.Second}
	}
	if a.now == nil {
		a.now = time.Now
	}
	a.codes.m = map[string]grant{}
	a.tg = strings.TrimSuffix(or(cfg.TGBase, "https://oauth.telegram.org"), "/")
	a.botAPI = strings.TrimSuffix(or(cfg.BotAPI, "https://api.telegram.org"), "/")
	a.issuer = strings.TrimSuffix(cfg.PublicURL, "/")
	a.secure = strings.HasPrefix(a.issuer, "https:")
	a.sessionName, a.oauthPrefix = "hub_session", "hub_oauth_"
	if a.secure {
		// __Host-: Secure, Path=/, no Domain, so no other *.almaz.dev site can set or shadow them
		a.sessionName, a.oauthPrefix = "__Host-hub_session", "__Host-hub_oauth_"
	}
	a.secret = []byte(cfg.SessionSecret)

	keys, keyErr := newKeySet(cfg.SigningKey, cfg.SigningKeyOld)
	a.keys = keys
	for _, m := range []struct {
		bad  bool
		name string
	}{
		// Telegram is optional (passkeys work without it), but not half-configured
		{(cfg.ClientID == "") != (cfg.ClientSecret == ""), "TG_CLIENT_ID and TG_CLIENT_SECRET (both, or neither for no Telegram login)"},
		{len(cfg.SessionSecret) < 32, "SESSION_SECRET (32+ characters)"},
		{!publicURL.MatchString(a.issuer) || store.CheckAppURL(a.issuer) != nil, "PUBLIC_URL (https://host)"},
		{keyErr != nil, fmt.Sprintf("HUB_SIGNING_KEY (%v)", keyErr)},
		{cfg.Store == nil, fmt.Sprintf("database (%v)", cfg.StoreErr)},
	} {
		if m.bad {
			a.missing = append(a.missing, m.name)
		}
	}
	if cfg.Store != nil {
		if err := a.seed(); err != nil {
			a.missing = append(a.missing, err.Error())
		}
	}
	if len(a.missing) > 0 {
		a.log.Printf("hub not configured, serving nothing: %s", strings.Join(a.missing, "; "))
		return a
	}

	notify, err := a.store.Notify()
	switch {
	case err != nil:
		a.log.Printf("refused logins: in this log only (%v)", err)
	case cfg.BotToken == "":
		a.log.Printf("refused logins: in this log only (no TG_BOT_TOKEN)")
	case notify == nil || notify.TelegramID == "":
		a.log.Printf("refused logins: in this log only (no notify person with a Telegram id)")
	default:
		a.log.Printf("refused logins: messaged to %s", notify.Key)
	}
	if cfg.Admin == "" {
		a.log.Printf("no HUB_ADMIN: nobody is admin")
	}
	a.telegram = cfg.ClientID != ""
	if !a.telegram {
		a.log.Printf("no TG_CLIENT_ID: Telegram login is off, passkeys only")
	}
	if a.wa, err = newWebAuthn(a.issuer); err != nil {
		a.missing = append(a.missing, fmt.Sprintf("WebAuthn (%v)", err))
		a.log.Printf("hub not configured, serving nothing: %s", strings.Join(a.missing, "; "))
		return a
	}
	a.discovery = a.discoveryDoc()
	a.apiMux = a.apiRoutes()
	a.ui = loadAdminUI()
	a.adminLink()
	remote := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), a.client), a.tg+"/.well-known/jwks.json")
	a.verifier = oidc.NewVerifier(a.tg, remote, &oidc.Config{
		ClientID: or(cfg.Audience, cfg.ClientID),
		// Telegram's JWKS also has an ES256K (secp256k1) key, which go-jose can't verify; tokens
		// signed with it would be rejected and logged as «ID token rejected»
		SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256, oidc.EdDSA},
		Now:                  a.now,
	})
	return a
}

// routes: path → method → handler; HEAD only where a GET has no side effects
func (a *Server) route(path, method string) (http.HandlerFunc, string) {
	type m = map[string]http.HandlerFunc
	var methods m
	switch path {
	case "/":
		methods = m{"GET": a.home, "HEAD": a.home}
	case "/.well-known/openid-configuration":
		methods = m{"GET": a.serveDiscovery, "HEAD": a.serveDiscovery}
	case "/jwks.json":
		methods = m{"GET": a.serveJWKS, "HEAD": a.serveJWKS}
	case "/authorize":
		methods = m{"GET": a.authorize}
	case "/token":
		methods = m{"POST": a.token}
	case "/login/telegram":
		methods = m{"GET": a.login}
	case "/login/passkey":
		methods = m{"GET": a.passkeyPage}
	case "/login/passkey/options":
		methods = m{"POST": a.passkeyOptions}
	case "/login/passkey/verify":
		methods = m{"POST": a.passkeyVerify}
	case "/callback":
		methods = m{"GET": a.callback}
	case "/logout":
		methods = m{"GET": a.logoutPage, "POST": a.logout}
	case "/admin/backup":
		methods = m{"GET": a.backup}
	case "/enroll":
		methods = m{"GET": a.enrollPage}
	case "/enroll/options":
		methods = m{"POST": a.enrollOptions}
	case "/enroll/verify":
		methods = m{"POST": a.enrollVerify}
	default:
		if path == "/admin" || strings.HasPrefix(path, "/admin/") {
			methods = m{"GET": a.adminUI, "HEAD": a.adminUI}
			break
		}
		return nil, ""
	}
	allow := make([]string, 0, len(methods))
	for _, k := range []string{"GET", "HEAD", "POST"} {
		if methods[k] != nil {
			allow = append(allow, k)
		}
	}
	return methods[method], strings.Join(allow, ", ")
}

func (a *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")                                        // apps never see the hub's URLs with codes in them
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'") // page() sets the full one for its pages
	h.Set("X-Frame-Options", "DENY")
	if a.secure {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
	defer func() {
		if err := recover(); err != nil {
			if err == http.ErrAbortHandler {
				panic(err)
			}
			a.log.Printf("error: %v", err)
			page(w, http.StatusInternalServerError, pageFailed("/"))
		}
	}()

	p := r.URL.Path
	if p == "/healthz" {
		if len(a.missing) > 0 {
			text(w, http.StatusServiceUnavailable, "not configured\n")
			return
		}
		text(w, http.StatusOK, "ok\n")
		return
	}
	if strings.HasPrefix(p, "/admin/api/") && len(a.missing) == 0 {
		a.apiMux.ServeHTTP(w, r)
		return
	}
	handler, allow := a.route(p, r.Method)
	switch {
	case allow == "":
		text(w, http.StatusNotFound, "Не найдено")
	case handler == nil:
		h.Set("Allow", allow)
		text(w, http.StatusMethodNotAllowed, "")
	case len(a.missing) > 0:
		page(w, http.StatusServiceUnavailable, pageClosed)
	default:
		handler(w, r)
	}
}

func (a *Server) home(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Add("Vary", "Cookie")
	id, err := a.resolve(a.session(r))
	if err != nil {
		a.broken(w, err)
		return
	}
	page(w, http.StatusOK, pageHome(id, id.person != nil && id.person.Key == a.cfg.Admin && a.cfg.Admin != ""))
}

func (a *Server) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode})
}

func text(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprint(w, body)
}

func redirect(w http.ResponseWriter, location string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

func or(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

// seed: HUB_SEED goes into an empty database once; afterwards it is ignored (and should be
// deleted). A database without apps serves nothing: every login would fail anyway.
func (a *Server) seed() error {
	people, err := a.store.Count("people")
	if err != nil {
		return fmt.Errorf("database: %v", err)
	}
	switch {
	case len(a.cfg.Seed) > 0 && people == 0:
		f, err := store.ParseSeed(a.cfg.Seed)
		if err != nil {
			return fmt.Errorf("HUB_SEED: %v", err)
		}
		if err := a.store.Import(f, "HUB_SEED"); err != nil {
			return fmt.Errorf("HUB_SEED: %v", err)
		}
		a.log.Printf("seeded: %d people, %d apps. Delete HUB_SEED now", len(f.People), len(f.Apps))
	case len(a.cfg.Seed) > 0:
		a.log.Printf("HUB_SEED ignored: the database already has people. Delete the variable")
	}
	// nobody to let in: a database that was never seeded. Apps can come later, from the admin UI.
	if people, err = a.store.Count("people"); err != nil {
		return fmt.Errorf("database: %v", err)
	}
	if people == 0 {
		return errors.New("no people in the database (set HUB_SEED for a new one)")
	}
	return nil
}

// adminLink: while the admin has no passkey, each start logs a link to make one. That is the way
// in for a hub without Telegram, and only someone who can read the hub's log sees it.
func (a *Server) adminLink() {
	if a.cfg.Admin == "" {
		return
	}
	p, err := a.store.Person(a.cfg.Admin)
	switch {
	case err != nil:
		a.log.Printf("admin: %v", err)
		return
	case p == nil:
		a.log.Printf("admin: HUB_ADMIN %q is not in the database", a.cfg.Admin)
		return
	}
	if has, err := a.store.HasPasskeys(p.Key); err != nil || has {
		return
	}
	token, err := a.store.CreateEnrollment(p.Key, "startup", enrollTTL)
	if err != nil {
		a.log.Printf("admin: %v", err)
		return
	}
	a.log.Printf("admin: %s has no passkey yet. Make one here (single use, 24 h): %s/enroll?t=%s", p.Key, a.issuer, token)
}

// methods: the login methods of app c this hub can offer now (Telegram only when configured)
func (a *Server) methods(c *store.App) []string {
	return slices.DeleteFunc(c.Methods(), func(m string) bool { return m == "telegram" && !a.telegram })
}
