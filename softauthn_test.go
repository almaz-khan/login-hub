package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"

	"encoding/binary"
	"encoding/json"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
)

// softAuthenticator is a software passkey: a real P-256 key producing real
// signatures, so tests exercise go-webauthn's verification end to end (ported from p2pvc)
// instead of mocking it (as the budget app's tests/helpers/authenticator.ts).
type softAuthenticator struct {
	origin  string
	rpID    string
	id      []byte
	key     *ecdsa.PrivateKey
	counter uint32
	// userHandle is what registration gave us; returned on every sign-in.
	userHandle []byte
	// overrideHandle, if set, is returned instead (a manager altering it).
	overrideHandle []byte
	// utf8RoundTrip reproduces NordPass: the handle is decoded as UTF-8 text
	// and re-encoded, so invalid bytes become U+FFFD.
	utf8RoundTrip bool
	// forge corrupts the signature; noUV leaves out user verification.
	noUV  bool
	forge bool
}

func newSoftAuthenticator(origin, rpID string) *softAuthenticator {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	rand.Read(id)
	return &softAuthenticator{origin: origin, rpID: rpID, id: id, key: key}
}

const (
	flagUP = 0x01
	flagUV = 0x04
	flagAT = 0x40
)

func (a *softAuthenticator) clientData(typ string, challenge protocol.URLEncodedBase64) []byte {
	cd, _ := json.Marshal(map[string]any{
		"type":        typ,
		"challenge":   b64.EncodeToString(challenge),
		"origin":      a.origin,
		"crossOrigin": false,
	})
	return cd
}

func (a *softAuthenticator) authData(flags byte, attested []byte) []byte {
	rp := sha256.Sum256([]byte(a.rpID))
	out := append([]byte{}, rp[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.counter)
	return append(out, attested...)
}

// register answers registration options with a "none" attestation.
func (a *softAuthenticator) register(opts *protocol.CredentialCreation) []byte {
	a.userHandle = []byte(opts.Response.User.ID.(protocol.URLEncodedBase64))
	if a.utf8RoundTrip {
		a.userHandle = []byte(strings.ToValidUTF8(string(a.userHandle), "�"))
	}

	cose, _ := cbor.Marshal(map[int]any{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: a.key.X.FillBytes(make([]byte, 32)),
		-3: a.key.Y.FillBytes(make([]byte, 32)),
	})
	attested := make([]byte, 16) // AAGUID: zeros
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(a.id)))
	attested = append(attested, a.id...)
	attested = append(attested, cose...)

	attObj, _ := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": a.authData(flagUP|flagUV|flagAT, attested),
	})
	resp, _ := json.Marshal(map[string]any{
		"id":    b64.EncodeToString(a.id),
		"rawId": b64.EncodeToString(a.id),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", opts.Response.Challenge)),
			"attestationObject": b64.EncodeToString(attObj),
			"transports":        []string{"internal"},
		},
		"clientExtensionResults": map[string]any{},
	})
	return resp
}

// authenticate answers sign-in options with a signed assertion.
func (a *softAuthenticator) authenticate(opts *protocol.CredentialAssertion) []byte {
	a.counter++
	flags := byte(flagUP | flagUV)
	if a.noUV {
		flags = flagUP
	}
	authData := a.authData(flags, nil)
	cd := a.clientData("webauthn.get", opts.Response.Challenge)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if a.forge {
		sig[len(sig)-1] ^= 0xff
	}
	handle := a.userHandle
	if a.overrideHandle != nil {
		handle = a.overrideHandle
	}
	resp, _ := json.Marshal(map[string]any{
		"id":    b64.EncodeToString(a.id),
		"rawId": b64.EncodeToString(a.id),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(authData),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(handle),
		},
		"clientExtensionResults": map[string]any{},
	})
	return resp
}
