package store

// Passkeys and WebAuthn challenges in the database. A passkey row keeps go-webauthn's Credential
// as JSON (public key, flags, sign counter); its id is the credential id. Challenges are single
// use: taking one deletes it, so a captured response can't be replayed.

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

const maxChallenges = 1000 // live ones; more means someone is hammering the options endpoint

var ErrBusy = errors.New("too many logins in progress")

func (s *Store) PutChallenge(id, purpose string, data []byte, person string, ttl time.Duration) error {
	return s.tx(func(tx *sql.Tx) error {
		now := s.now().Unix()
		if _, err := tx.Exec(`DELETE FROM challenges WHERE expires_at <= ?`, now); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(`SELECT count(*) FROM challenges`).Scan(&n); err != nil {
			return err
		}
		if n >= maxChallenges {
			return ErrBusy
		}
		_, err := tx.Exec(`INSERT INTO challenges (id, purpose, data, person, expires_at) VALUES (?, ?, ?, ?, ?)`,
			id, purpose, data, nullable(person), s.now().Add(ttl).Unix())
		return err
	})
}

// TakeChallenge: the challenge, gone from the database whatever happens next; ok false if it
// doesn't exist, has expired or was made for something else
func (s *Store) TakeChallenge(id, purpose string) (data []byte, person string, ok bool, err error) {
	var p sql.NullString
	err = s.db.QueryRow(`DELETE FROM challenges WHERE id = ? AND purpose = ? AND expires_at > ? RETURNING data, person`,
		id, purpose, s.now().Unix()).Scan(&data, &p)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", false, nil
	}
	return data, p.String, err == nil, err
}

// Passkeys: every credential of person, as stored JSON
func (s *Store) Passkeys(person string) ([][]byte, error) {
	rows, err := s.db.Query(`SELECT data FROM passkeys WHERE person = ? ORDER BY created_at`, person)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out [][]byte
	for rows.Next() {
		var d []byte
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) HasPasskeys(person string) (bool, error) {
	var ok bool
	err := s.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM passkeys WHERE person = ?)`, person).Scan(&ok)
	return ok, err
}

// PasskeyOwner: whose credential id this is, or "" for one the hub doesn't know
func (s *Store) PasskeyOwner(id []byte) (string, error) {
	var person string
	err := s.db.QueryRow(`SELECT person FROM passkeys WHERE id = ?`, id).Scan(&person)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return person, err
}

// PasskeyOf: whether credential id (base64url) is still one of person's passkeys
func (s *Store) PasskeyOf(cred, person string) (bool, error) {
	id, err := b64.DecodeString(cred)
	if err != nil {
		return false, nil
	}
	var ok bool
	err = s.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM passkeys WHERE id = ? AND person = ?)`, id, person).Scan(&ok)
	return ok, err
}

// PasskeyUsed: the credential after a login (its counter and flags), and when
func (s *Store) PasskeyUsed(id, data []byte) error {
	_, err := s.db.Exec(`UPDATE passkeys SET data = ?, last_used_at = ? WHERE id = ?`, data, s.now().Unix(), id)
	return err
}

func (s *Store) AddPasskey(person string, id, data []byte, label, actor string) error {
	return s.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO passkeys (id, person, data, label, created_at) VALUES (?, ?, ?, ?, ?)`,
			id, person, data, label, s.now().Unix()); err != nil {
			return err
		}
		return s.audit(tx, actor, "passkey add", person+": "+label)
	})
}

// WebAuthnHandle: person's WebAuthn user handle, made on first use. 128 random bits as hex, so
// password managers that treat it as text (NordPass) keep it intact.
func (s *Store) WebAuthnHandle(person string) ([]byte, error) {
	var h []byte
	err := s.tx(func(tx *sql.Tx) error {
		if err := tx.QueryRow(`SELECT webauthn_handle FROM people WHERE key = ?`, person).Scan(&h); err != nil {
			return err
		}
		if h != nil {
			return nil
		}
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		h = []byte(hex.EncodeToString(b))
		_, err := tx.Exec(`UPDATE people SET webauthn_handle = ? WHERE key = ?`, h, person)
		return err
	})
	return h, err
}

var ErrLinkUsed = errors.New("enrollment link used or expired")

func TokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// CreateEnrollment: a single-use link token for person; only its hash is stored
func (s *Store) CreateEnrollment(person, actor string, ttl time.Duration) (string, error) {
	token := random()
	err := s.tx(func(tx *sql.Tx) error {
		now := s.now()
		if _, err := tx.Exec(`DELETE FROM enrollments WHERE expires_at <= ? OR used_at IS NOT NULL`, now.Unix()); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO enrollments (token_hash, person, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
			TokenHash(token), person, actor, now.Unix(), now.Add(ttl).Unix()); err != nil {
			return err
		}
		return s.audit(tx, actor, "enrollment link", person)
	})
	return token, err
}

// Enrollment: whom an unused, unexpired link is for, or ""
func (s *Store) Enrollment(token string) (string, error) {
	var person string
	err := s.db.QueryRow(`SELECT person FROM enrollments WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`,
		TokenHash(token), s.now().Unix()).Scan(&person)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return person, err
}

// AddPasskeyWithLink: the passkey and the link (by its hash) spent together, or neither
func (s *Store) AddPasskeyWithLink(linkHash []byte, person string, id, data []byte, label string) error {
	return s.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE enrollments SET used_at = ? WHERE token_hash = ? AND person = ? AND used_at IS NULL AND expires_at > ?`,
			s.now().Unix(), linkHash, person, s.now().Unix())
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrLinkUsed
		}
		if _, err := tx.Exec(`INSERT INTO passkeys (id, person, data, label, created_at) VALUES (?, ?, ?, ?, ?)`,
			id, person, data, label, s.now().Unix()); err != nil {
			return err
		}
		return s.audit(tx, "link", "passkey add", person+": "+label)
	})
}

func (s *Store) DeletePasskey(id []byte, actor string) (bool, error) {
	var deleted bool
	err := s.tx(func(tx *sql.Tx) error {
		var person, label string
		err := tx.QueryRow(`DELETE FROM passkeys WHERE id = ? RETURNING person, label`, id).Scan(&person, &label)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		deleted = true
		return s.audit(tx, actor, "passkey delete", person+": "+label)
	})
	return deleted, err
}

type passkeyRow struct {
	ID       []byte
	Label    string
	Created  int64
	LastUsed int64
}

type personRow struct {
	Person
	LastSeen int64
	Passkeys []passkeyRow
}

// People: everyone with their passkeys, for the admin page
func (s *Store) people() ([]personRow, error) {
	rows, err := s.db.Query(`SELECT p.key, p.name, coalesce(p.telegram_id, ''), coalesce(p.last_seen_at, 0),
		k.id, coalesce(k.label, ''), coalesce(k.created_at, 0), coalesce(k.last_used_at, 0)
		FROM people p LEFT JOIN passkeys k ON k.person = p.key ORDER BY p.key, k.created_at`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []personRow
	for rows.Next() {
		var p personRow
		var k passkeyRow
		if err := rows.Scan(&p.Key, &p.Name, &p.TelegramID, &p.LastSeen, &k.ID, &k.Label, &k.Created, &k.LastUsed); err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1].Key != p.Key {
			out = append(out, p)
		}
		if k.ID != nil {
			last := &out[len(out)-1]
			last.Passkeys = append(last.Passkeys, k)
		}
	}
	return out, rows.Err()
}
