package store

// The same seed as the hub's tests: three people (Alice in club), five apps.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

const (
	alice = "111"
	bob   = "222"
	carol = "333"
)

var secrets = map[string]string{
	"running-club": strings.Repeat("ab", 32),
	"stub":         strings.Repeat("cd", 32),
	"plus":         "a+b/c=d",
	"both":         strings.Repeat("ef", 32),
	"pk":           strings.Repeat("01", 32),
}

func appURL(client string) string {
	port := map[string]string{"running-club": "1", "stub": "2", "plus": "3", "both": "4", "pk": "5", "new-app": "7"}[client]
	return "http://[::1]:" + port
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func seedJSON(allowRC ...string) string {
	if allowRC == nil {
		allowRC = []string{"group:club"}
	}
	apps := map[string]any{}
	login := map[string][]string{"both": {"telegram", "passkey"}, "pk": {"passkey"}}
	for id, allow := range map[string][]string{"running-club": allowRC, "stub": {"group:club", "Bob"}, "plus": {"Alice"}, "both": {"group:club"}, "pk": {"group:club"}} {
		methods := login[id]
		if methods == nil {
			methods = []string{"telegram"}
		}
		apps[id] = map[string]any{
			"name":                      map[string]string{"running-club": "Running Club Wrapped", "stub": "Stub", "plus": "Plus", "both": "Both", "pk": "Passkey Only"}[id],
			"redirect_uris":             []string{appURL(id) + "/auth/callback"},
			"post_logout_redirect_uris": []string{appURL(id) + "/"},
			"secret_sha256":             sha(secrets[id]),
			"login":                     methods,
			"allow":                     allow,
		}
	}
	b, _ := json.Marshal(map[string]any{
		"notify": "Alice",
		"people": map[string]any{
			"Alice": map[string]string{"name": "Alice", "telegram": alice},
			"Bob":   map[string]string{"name": "Bob", "telegram": bob},
			"Carol": map[string]string{"name": "Carol", "telegram": carol},
		},
		"groups": map[string][]string{"club": {"Alice"}},
		"apps":   apps,
	})
	return string(b)
}

func testStore(t *testing.T, seed string) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "hub.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	f, err := ParseSeed([]byte(seed))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Import(f, "test"); err != nil {
		t.Fatal(err)
	}
	return s
}
