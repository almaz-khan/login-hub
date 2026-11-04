package main

// The hub's database: SQLite on the Railway volume (pure Go, modernc.org/sqlite, so the image stays
// FROM scratch). People, groups, apps and who may open them; later passkeys and enrollment links.
// Never the signing key or the session secret: a copy of this file can't sign or forge anything.
//
// Migrations are numbered (PRAGMA user_version) and each runs in one transaction at start.
// A database that can't be opened, migrated or passes no quick_check fails the hub closed.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var migrations = []string{
	// 1: people, groups, apps, access, settings, audit
	`CREATE TABLE people (
		key          TEXT PRIMARY KEY,
		name         TEXT NOT NULL CHECK (name <> ''),
		telegram_id  TEXT UNIQUE,
		created_at   INTEGER NOT NULL,
		last_seen_at INTEGER
	) STRICT;
	CREATE TABLE groups (
		name TEXT PRIMARY KEY
	) STRICT;
	CREATE TABLE group_members (
		group_name TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE ON UPDATE CASCADE,
		person     TEXT NOT NULL REFERENCES people(key) ON DELETE CASCADE,
		PRIMARY KEY (group_name, person)
	) STRICT;
	CREATE TABLE apps (
		id             TEXT PRIMARY KEY,
		name           TEXT NOT NULL CHECK (name <> ''),
		secret_sha256  BLOB NOT NULL CHECK (length(secret_sha256) = 32),
		login_telegram INTEGER NOT NULL DEFAULT 1 CHECK (login_telegram IN (0, 1)),
		login_passkey  INTEGER NOT NULL DEFAULT 0 CHECK (login_passkey IN (0, 1)),
		created_at     INTEGER NOT NULL,
		CHECK (login_telegram + login_passkey > 0)
	) STRICT;
	CREATE TABLE app_urls (
		app  TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
		kind TEXT NOT NULL CHECK (kind IN ('redirect', 'logout')),
		url  TEXT NOT NULL,
		PRIMARY KEY (app, kind, url)
	) STRICT;
	CREATE TABLE app_access (
		app        TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
		person     TEXT REFERENCES people(key) ON DELETE CASCADE,
		group_name TEXT REFERENCES groups(name) ON DELETE CASCADE ON UPDATE CASCADE,
		CHECK ((person IS NULL) <> (group_name IS NULL)),
		UNIQUE (app, person),
		UNIQUE (app, group_name)
	) STRICT;
	CREATE INDEX app_access_person ON app_access(person);
	CREATE INDEX app_access_group ON app_access(group_name);
	CREATE INDEX group_members_person ON group_members(person);
	CREATE TABLE settings (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	) STRICT;
	CREATE TABLE audit (
		id     INTEGER PRIMARY KEY,
		at     INTEGER NOT NULL,
		actor  TEXT NOT NULL,
		action TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT ''
	) STRICT;`,
}

type Store struct {
	db   *sql.DB
	path string
	now  func() time.Time
}

// client: an app, as /authorize, /token and /logout see it
type client struct {
	ID         string
	Name       string
	Telegram   bool // login methods it accepts
	Passkey    bool
	redirects  map[string]bool
	logouts    map[string]bool
	secretHash []byte
}

type Person struct {
	Key        string
	Name       string
	TelegramID string // "" if none
}

func openStore(path string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer, and the hub's traffic is tiny
	s := &Store{db: db, path: path, now: now}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	var check string
	if err := db.QueryRow(`PRAGMA quick_check`).Scan(&check); err != nil || check != "ok" {
		_ = db.Close()
		return nil, fmt.Errorf("quick_check: %v %s", err, check)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("database is at version %d, this hub knows %d: refusing to run an older hub on it", version, len(migrations))
	}
	for i := version; i < len(migrations); i++ {
		err := s.tx(func(tx *sql.Tx) error {
			if _, err := tx.Exec(migrations[i]); err != nil {
				return err
			}
			_, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1))
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
	}
	return nil
}

func (s *Store) tx(fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) audit(tx *sql.Tx, actor, action, detail string) error {
	_, err := tx.Exec(`INSERT INTO audit (at, actor, action, detail) VALUES (?, ?, ?, ?)`, s.now().Unix(), actor, action, detail)
	return err
}

func (s *Store) count(table string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n)
	return n, err
}

// Import writes a checked seed into an empty database, all or nothing
func (s *Store) Import(f *seedFile, actor string) error {
	return s.tx(func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRow(`SELECT count(*) FROM people`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return errors.New("the database already has people: a seed only goes into an empty one")
		}
		now := s.now().Unix()
		for key, p := range f.People {
			if _, err := tx.Exec(`INSERT INTO people (key, name, telegram_id, created_at) VALUES (?, ?, ?, ?)`,
				key, strings.TrimSpace(p.Name), nullable(p.Telegram), now); err != nil {
				return fmt.Errorf("person %s: %w", key, err)
			}
		}
		for g, keys := range f.Groups {
			if _, err := tx.Exec(`INSERT INTO groups (name) VALUES (?)`, g); err != nil {
				return err
			}
			for _, k := range keys {
				if _, err := tx.Exec(`INSERT OR IGNORE INTO group_members (group_name, person) VALUES (?, ?)`, g, k); err != nil {
					return err
				}
			}
		}
		for id, e := range f.Apps {
			tg, pk := 1, 0
			if len(e.Login) > 0 {
				tg, pk = bool01(contains(e.Login, "telegram")), bool01(contains(e.Login, "passkey"))
			}
			if _, err := tx.Exec(`INSERT INTO apps (id, name, secret_sha256, login_telegram, login_passkey, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
				id, strings.TrimSpace(e.Name), decodeHex(e.SecretSHA256), tg, pk, now); err != nil {
				return fmt.Errorf("app %s: %w", id, err)
			}
			for kind, urls := range map[string][]string{"redirect": e.RedirectURIs, "logout": e.PostLogoutRedirectURIs} {
				for _, u := range urls {
					if _, err := tx.Exec(`INSERT OR IGNORE INTO app_urls (app, kind, url) VALUES (?, ?, ?)`, id, kind, u); err != nil {
						return err
					}
				}
			}
			for _, who := range e.Allow {
				var err error
				if g, ok := strings.CutPrefix(who, "group:"); ok {
					_, err = tx.Exec(`INSERT OR IGNORE INTO app_access (app, group_name) VALUES (?, ?)`, id, g)
				} else {
					_, err = tx.Exec(`INSERT OR IGNORE INTO app_access (app, person) VALUES (?, ?)`, id, who)
				}
				if err != nil {
					return err
				}
			}
		}
		if f.Notify != "" {
			if _, err := tx.Exec(`INSERT INTO settings (key, value) VALUES ('notify', ?)`, f.Notify); err != nil {
				return err
			}
		}
		return s.audit(tx, actor, "import", fmt.Sprintf("%d people, %d groups, %d apps", len(f.People), len(f.Groups), len(f.Apps)))
	})
}

// App: one app with everything /authorize, /token and /logout need, or nil
func (s *Store) App(id string) (*client, error) {
	c := &client{ID: id, redirects: map[string]bool{}, logouts: map[string]bool{}}
	var tg, pk int
	err := s.db.QueryRow(`SELECT name, secret_sha256, login_telegram, login_passkey FROM apps WHERE id = ?`, id).
		Scan(&c.Name, &c.secretHash, &tg, &pk)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.Telegram, c.Passkey = tg == 1, pk == 1
	rows, err := s.db.Query(`SELECT kind, url FROM app_urls WHERE app = ?`, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var kind, u string
		if err := rows.Scan(&kind, &u); err != nil {
			return nil, err
		}
		if kind == "redirect" {
			c.redirects[u] = true
		} else {
			c.logouts[u] = true
		}
	}
	return c, rows.Err()
}

// Allowed: whether person may open app, directly or through a group
func (s *Store) Allowed(app, person string) (bool, error) {
	var ok bool
	err := s.db.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM app_access a
		LEFT JOIN group_members m ON m.group_name = a.group_name
		WHERE a.app = ? AND (a.person = ? OR m.person = ?))`, app, person, person).Scan(&ok)
	return ok, err
}

func (s *Store) person(where string, args ...any) (*Person, error) {
	var p Person
	var tg sql.NullString
	err := s.db.QueryRow(`SELECT key, name, telegram_id FROM people WHERE `+where, args...).Scan(&p.Key, &p.Name, &tg)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.TelegramID = tg.String
	return &p, nil
}

func (s *Store) Person(key string) (*Person, error)          { return s.person(`key = ?`, key) }
func (s *Store) PersonByTelegram(id string) (*Person, error) { return s.person(`telegram_id = ?`, id) }

// Notify: the person the bot messages about refused attempts, or nil
func (s *Store) Notify() (*Person, error) {
	return s.person(`key = (SELECT value FROM settings WHERE key = 'notify')`)
}

// Seen: when the hub last let person into an app (for the admin UI)
func (s *Store) Seen(person string) error {
	_, err := s.db.Exec(`UPDATE people SET last_seen_at = ? WHERE key = ?`, s.now().Unix(), person)
	return err
}

// PasskeyOf: whether credential cred is (still) one of person's passkeys. Passkeys come in phase 4;
// until then no passkey proof can exist.
func (s *Store) PasskeyOf(cred, person string) (bool, error) { return false, nil }

// Backup: a consistent copy of the whole database at path (which must not exist)
func (s *Store) Backup(path string) error {
	_, err := s.db.Exec(`VACUUM INTO ?`, path)
	return err
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func bool01(b bool) int {
	if b {
		return 1
	}
	return 0
}
