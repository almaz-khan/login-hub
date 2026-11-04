package main

// The access config (config/access.json, baked into the image): who exists, which groups they're
// in, and which apps they may open. Anything wrong in it — an unknown person or group, a redirect
// URL that isn't https, a missing secret hash — is an error, and the hub serves nothing until it's
// fixed (see app.missing).

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

type accessFile struct {
	Notify string              `json:"notify"`
	People map[string]string   `json:"people"`
	Groups map[string][]string `json:"groups"`
	Apps   map[string]appEntry `json:"apps"`
}

type appEntry struct {
	Name                   string   `json:"name"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	SecretSHA256           string   `json:"secret_sha256"`
	Allow                  []string `json:"allow"`
}

// Access is access.json checked and resolved: groups expanded, hashes decoded.
type Access struct {
	Notify string            // Telegram id messaged about refused logins, or ""
	People map[string]string // Telegram id → name (for the log and messages)
	Apps   map[string]*client
}

type client struct {
	ID         string
	Name       string
	redirects  map[string]bool
	logouts    map[string]bool
	secretHash []byte
	allowed    map[string]bool // Telegram ids
}

var (
	clientIDChars = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	groupChars    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	sha256Hex     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	localHost     = regexp.MustCompile(`^(?:localhost|127\.0\.0\.1|\[::1\])$`)
)

func loadAccess(file string) (*Access, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return parseAccess(raw)
}

func parseAccess(raw []byte) (*Access, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields() // a misspelt key ("allows") would otherwise silently mean nobody
	var f accessFile
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	var errs []string
	bad := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	if len(f.People) == 0 {
		bad("people: empty")
	}
	for id, name := range f.People {
		if !digits.MatchString(id) {
			bad("people: %q is not a Telegram id", id)
		}
		if strings.TrimSpace(name) == "" {
			bad("people: %s has no name", id)
		}
	}
	if f.Notify != "" && f.People[f.Notify] == "" {
		bad("notify: %q is not in people", f.Notify)
	}
	for g, ids := range f.Groups {
		if !groupChars.MatchString(g) {
			bad("groups: bad name %q", g)
		}
		for _, id := range ids {
			if f.People[id] == "" {
				bad("groups.%s: %q is not in people", g, id)
			}
		}
	}
	if len(f.Apps) == 0 {
		bad("apps: empty")
	}
	a := &Access{Notify: f.Notify, People: f.People, Apps: map[string]*client{}}
	for id, e := range f.Apps {
		c := &client{ID: id, Name: strings.TrimSpace(e.Name), redirects: map[string]bool{}, logouts: map[string]bool{}, allowed: map[string]bool{}}
		if !clientIDChars.MatchString(id) {
			bad("apps: bad client id %q (a-z, 0-9, -)", id)
		}
		if c.Name == "" {
			bad("apps.%s: no name", id)
		}
		if len(e.RedirectURIs) == 0 {
			bad("apps.%s: no redirect_uris", id)
		}
		for _, u := range e.RedirectURIs {
			if err := checkAppURL(u); err != nil {
				bad("apps.%s.redirect_uris: %q %v", id, u, err)
			}
			c.redirects[u] = true
		}
		for _, u := range e.PostLogoutRedirectURIs {
			if err := checkAppURL(u); err != nil {
				bad("apps.%s.post_logout_redirect_uris: %q %v", id, u, err)
			}
			c.logouts[u] = true
		}
		if !sha256Hex.MatchString(e.SecretSHA256) {
			bad("apps.%s: secret_sha256 must be 64 lowercase hex characters", id)
		} else {
			c.secretHash, _ = hex.DecodeString(e.SecretSHA256)
		}
		if len(e.Allow) == 0 {
			bad("apps.%s: allow is empty", id)
		}
		for _, who := range e.Allow {
			if g, ok := strings.CutPrefix(who, "group:"); ok {
				ids, found := f.Groups[g]
				if !found {
					bad("apps.%s.allow: unknown group %q", id, g)
				}
				for _, p := range ids {
					c.allowed[p] = true
				}
			} else if f.People[who] == "" {
				bad("apps.%s.allow: %q is not in people (or write group:<name>)", id, who)
			} else {
				c.allowed[who] = true
			}
		}
		a.Apps[id] = c
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return a, nil
}

// checkAppURL: an absolute https URL with no fragment; http only for localhost (local runs and tests)
func checkAppURL(s string) error {
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

// may: whether Telegram id may open this app
func (c *client) may(id string) bool { return c.allowed[id] }
