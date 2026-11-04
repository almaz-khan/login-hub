package store

import (
	"crypto/rand"
	"encoding/base64"
	"regexp"
)

var (
	b64    = base64.RawURLEncoding
	digits = regexp.MustCompile(`^\d+$`)
)

func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b64.EncodeToString(b)
}

func or(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}
