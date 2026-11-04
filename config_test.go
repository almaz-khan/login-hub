package main

import (
	"strings"
	"testing"
)

func TestAccessConfig(t *testing.T) {
	good := accessJSON()
	if _, err := parseAccess([]byte(good)); err != nil {
		t.Fatal(err)
	}
	a, _ := parseAccess([]byte(good))
	if !a.Apps["running-club"].may(alice) || a.Apps["running-club"].may(bob) || !a.Apps["stub"].may(bob) || a.Apps["stub"].may(carol) {
		t.Fatal("allow lists")
	}
	for name, c := range map[string]struct{ from, to, want string }{
		"unknown person":    {`"allow":["group:club"]`, `"allow":["999"]`, `"999" is not in people`},
		"unknown group":     {`"allow":["group:club"]`, `"allow":["group:nope"]`, `unknown group "nope"`},
		"group member":      {`"club":["111"]`, `"club":["999"]`, `groups.club: "999" is not in people`},
		"http redirect":     {`http://localhost:1/auth/callback`, `http://running.example/auth/callback`, `is not https`},
		"fragment":          {`http://localhost:1/auth/callback`, `https://running.example/auth/callback#x`, `has a fragment`},
		"relative redirect": {`http://localhost:1/auth/callback`, `/auth/callback`, `not an absolute URL`},
		"no secret":         {`"secret_sha256":"` + sha(secrets["running-club"]) + `"`, `"secret_sha256":""`, `secret_sha256`},
		"upper hex secret":  {`"secret_sha256":"` + sha(secrets["running-club"]) + `"`, `"secret_sha256":"` + strings.ToUpper(sha(secrets["running-club"])) + `"`, `secret_sha256`},
		"misspelt key":      {`"allow":["group:club"]`, `"allows":["group:club"]`, `unknown field "allows"`},
		"notify outsider":   {`"notify":"111"`, `"notify":"999"`, `notify: "999"`},
		"bad client id":     {`"running-club":{`, `"Running Club":{`, `bad client id`},
		"not json":          {`{`, `[`, `invalid character`},
	} {
		raw := strings.Replace(good, c.from, c.to, 1)
		if raw == good {
			t.Fatalf("%s: %q not in the config", name, c.from)
		}
		if _, err := parseAccess([]byte(raw)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
