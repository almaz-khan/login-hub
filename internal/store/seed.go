package store

// The seed: people, groups and apps as JSON, imported once into an empty database (HUB_SEED on
// Railway, `hub import` locally). The real one lives in private/ (gitignored), never in git.
// Everything is checked before anything is written; one mistake refuses the whole seed.
//
//	{
//	  "notify": "<person key>",
//	  "people": {"<person key>": {"name": "…", "telegram": "<Telegram id>"}},
//	  "groups": {"<group>": ["<person key>"]},
//	  "apps": {"<client id>": {"name": "…", "redirect_uris": […], "post_logout_redirect_uris": […],
//	           "login": ["telegram", "passkey"], "secret_sha256": "<hex>", "allow": ["group:<group>", "<person key>"]}}
//	}

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

type Seed struct {
	Notify string                `json:"notify"`
	People map[string]seedPerson `json:"people"`
	Groups map[string][]string   `json:"groups"`
	Apps   map[string]seedApp    `json:"apps"`
}

type seedPerson struct {
	Name     string `json:"name"`
	Telegram string `json:"telegram"`
}

type seedApp struct {
	Name                   string   `json:"name"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	Login                  []string `json:"login"`
	SecretSHA256           string   `json:"secret_sha256"`
	Allow                  []string `json:"allow"`
}

var (
	personKey   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	clientIDRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	groupNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	sha256Hex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	localHost   = regexp.MustCompile(`^(?:localhost|127\.0\.0\.1|::1)$`) // url.Hostname() drops the brackets
	methods     = map[string]bool{"telegram": true, "passkey": true}
)

func ParseSeed(raw []byte) (*Seed, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields() // a misspelt key ("allows") would otherwise silently mean nobody
	var f Seed
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	var errs []string
	bad := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	if len(f.People) == 0 {
		bad("people: empty")
	}
	telegram := map[string]string{}
	for key, p := range f.People {
		if !personKey.MatchString(key) {
			bad("people: bad key %q (letters, digits, _ and -; it is the sub apps see, so never rename it)", key)
		}
		if strings.TrimSpace(p.Name) == "" {
			bad("people.%s: no name", key)
		}
		if p.Telegram != "" {
			if !digits.MatchString(p.Telegram) {
				bad("people.%s: telegram %q is not a Telegram id", key, p.Telegram)
			} else if other, dup := telegram[p.Telegram]; dup {
				bad("people: %s and %s have the same Telegram id", min(key, other), max(key, other))
			}
			telegram[p.Telegram] = key
		}
	}
	if f.Notify != "" {
		if p, ok := f.People[f.Notify]; !ok {
			bad("notify: %q is not in people", f.Notify)
		} else if p.Telegram == "" {
			bad("notify: %s has no Telegram id to message", f.Notify)
		}
	}
	for g, keys := range f.Groups {
		if !groupNameRe.MatchString(g) {
			bad("groups: bad name %q", g)
		}
		for _, k := range keys {
			if _, ok := f.People[k]; !ok {
				bad("groups.%s: %q is not in people", g, k)
			}
		}
	}
	if len(f.Apps) == 0 {
		bad("apps: empty")
	}
	for id, e := range f.Apps {
		for _, err := range checkApp(id, e.Name, e.RedirectURIs, e.PostLogoutRedirectURIs, e.Login, e.SecretSHA256) {
			bad("apps.%s: %s", id, err)
		}
		if len(e.Allow) == 0 {
			bad("apps.%s: allow is empty", id)
		}
		for _, who := range e.Allow {
			if g, ok := strings.CutPrefix(who, "group:"); ok {
				if _, found := f.Groups[g]; !found {
					bad("apps.%s.allow: unknown group %q", id, g)
				}
			} else if _, found := f.People[who]; !found {
				bad("apps.%s.allow: %q is not in people (or write group:<name>)", id, who)
			}
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return &f, nil
}

// checkApp: the rules for an app, shared by the seed and (later) the admin API
func checkApp(id, name string, redirects, logouts, login []string, secret string) []string {
	var errs []string
	if !clientIDRe.MatchString(id) {
		errs = append(errs, "bad client id (a-z, 0-9, -)")
	}
	if strings.TrimSpace(name) == "" {
		errs = append(errs, "no name")
	}
	if len(redirects) == 0 {
		errs = append(errs, "no redirect_uris")
	}
	for _, u := range redirects {
		if err := CheckAppURL(u); err != nil {
			errs = append(errs, fmt.Sprintf("redirect_uris: %q %v", u, err))
		}
	}
	for _, u := range logouts {
		if err := CheckAppURL(u); err != nil {
			errs = append(errs, fmt.Sprintf("post_logout_redirect_uris: %q %v", u, err))
		}
	}
	for _, m := range login {
		if !methods[m] {
			errs = append(errs, fmt.Sprintf("login: unknown method %q (telegram, passkey)", m))
		}
	}
	if !sha256Hex.MatchString(secret) {
		errs = append(errs, "secret_sha256 must be 64 lowercase hex characters (go run ./cmd/hub secret)")
	}
	return errs
}

func decodeHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// CheckAppURL: an absolute https URL with no fragment; http only for localhost (local runs and tests)
func CheckAppURL(s string) error {
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return err
	case u.Host == "" || u.User != nil:
		return errors.New("is not an absolute URL")
	case u.Fragment != "" || strings.Contains(s, "#"):
		return errors.New("has a fragment")
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && localHost.MatchString(u.Hostname()):
		return nil
	default:
		return errors.New("is not https")
	}
}
