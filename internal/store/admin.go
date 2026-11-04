package store

// What the admin UI reads and changes. Every change runs in one transaction, is checked with the
// same rules as the seed, and goes into the audit log. Person keys and client ids never change
// once made: they are the sub and the client id apps rely on.

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// UserError: a refusal the admin should read, as opposed to a broken database
type UserError struct{ Msg string }

func (e *UserError) Error() string { return e.Msg }

func refuse(format string, args ...any) error { return &UserError{Msg: fmt.Sprintf(format, args...)} }

type State struct {
	Me     string        `json:"me"`
	Notify string        `json:"notify"`
	People []StatePerson `json:"people"`
	Groups []StateGroup  `json:"groups"`
	Apps   []StateApp    `json:"apps"`
}

type StatePerson struct {
	Key        string         `json:"key"`
	Name       string         `json:"name"`
	TelegramID string         `json:"telegram_id"`
	LastSeen   int64          `json:"last_seen"`
	Groups     []string       `json:"groups"`
	Apps       []string       `json:"apps"` // what they can open, directly or through a group
	Passkeys   []StatePasskey `json:"passkeys"`
}

type StatePasskey struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Created  int64  `json:"created"`
	LastUsed int64  `json:"last_used"`
}

type StateGroup struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

type StateApp struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Redirects []string `json:"redirect_uris"`
	Logouts   []string `json:"post_logout_redirect_uris"`
	Login     []string `json:"login"`
	Allow     []string `json:"allow"` // "group:<name>" or a person key, as in the seed
	Created   int64    `json:"created"`
}

func (s *Store) column(query string, args ...any) ([]string, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// State: everything the admin UI shows, in one read
func (s *Store) State() (*State, error) {
	st := &State{People: []StatePerson{}, Groups: []StateGroup{}, Apps: []StateApp{}}
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key = 'notify'`).Scan(&st.Notify)

	people, err := s.people()
	if err != nil {
		return nil, err
	}
	for _, p := range people {
		pj := StatePerson{Key: p.Key, Name: p.Name, TelegramID: p.TelegramID, LastSeen: p.LastSeen, Passkeys: []StatePasskey{}}
		for _, k := range p.Passkeys {
			pj.Passkeys = append(pj.Passkeys, StatePasskey{ID: b64.EncodeToString(k.ID), Label: k.Label, Created: k.Created, LastUsed: k.LastUsed})
		}
		if pj.Groups, err = s.column(`SELECT group_name FROM group_members WHERE person = ? ORDER BY group_name`, p.Key); err != nil {
			return nil, err
		}
		if pj.Apps, err = s.column(`SELECT DISTINCT a.app FROM app_access a LEFT JOIN group_members m ON m.group_name = a.group_name
			WHERE a.person = ? OR m.person = ? ORDER BY a.app`, p.Key, p.Key); err != nil {
			return nil, err
		}
		st.People = append(st.People, pj)
	}

	groups, err := s.column(`SELECT name FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		members, err := s.column(`SELECT person FROM group_members WHERE group_name = ? ORDER BY person`, g)
		if err != nil {
			return nil, err
		}
		st.Groups = append(st.Groups, StateGroup{Name: g, Members: members})
	}

	rows, err := s.db.Query(`SELECT id, name, login_telegram, login_passkey, created_at FROM apps ORDER BY id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a StateApp
		var tg, pk int
		if err := rows.Scan(&a.ID, &a.Name, &tg, &pk, &a.Created); err != nil {
			_ = rows.Close()
			return nil, err
		}
		a.Login = []string{}
		if tg == 1 {
			a.Login = append(a.Login, "telegram")
		}
		if pk == 1 {
			a.Login = append(a.Login, "passkey")
		}
		st.Apps = append(st.Apps, a)
	}
	_ = rows.Close()
	for i := range st.Apps {
		a := &st.Apps[i]
		if a.Redirects, err = s.column(`SELECT url FROM app_urls WHERE app = ? AND kind = 'redirect' ORDER BY url`, a.ID); err != nil {
			return nil, err
		}
		if a.Logouts, err = s.column(`SELECT url FROM app_urls WHERE app = ? AND kind = 'logout' ORDER BY url`, a.ID); err != nil {
			return nil, err
		}
		if a.Allow, err = s.column(`SELECT coalesce('group:' || group_name, person) FROM app_access WHERE app = ? ORDER BY group_name IS NULL, group_name, person`, a.ID); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// ------------------------------------------------------------------ people

func checkPerson(name, telegram string) error {
	if strings.TrimSpace(name) == "" {
		return refuse("Нужно имя")
	}
	if telegram != "" && !digits.MatchString(telegram) {
		return refuse("Telegram id — это число (его показывает бот при отказе во входе)")
	}
	return nil
}

func dbRefusal(err error) error {
	switch {
	case err == nil:
		return nil
	case strings.Contains(err.Error(), "people.telegram_id"):
		return refuse("Этот Telegram id уже у другого человека")
	case strings.Contains(err.Error(), "UNIQUE constraint failed: people.key"),
		strings.Contains(err.Error(), "UNIQUE constraint failed: groups.name"),
		strings.Contains(err.Error(), "UNIQUE constraint failed: apps.id"):
		return refuse("Такой уже есть")
	case strings.Contains(err.Error(), "FOREIGN KEY constraint failed"):
		return refuse("Нет такого человека или группы")
	}
	return err
}

func (s *Store) CreatePerson(key, name, telegram, actor string) error {
	if !personKey.MatchString(key) {
		return refuse("Ключ: латиница, цифры, _ и -, до 64 символов. Его видят сайты, менять его потом нельзя")
	}
	if err := checkPerson(name, telegram); err != nil {
		return err
	}
	return dbRefusal(s.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO people (key, name, telegram_id, created_at) VALUES (?, ?, ?, ?)`,
			key, strings.TrimSpace(name), nullable(telegram), s.now().Unix()); err != nil {
			return err
		}
		return s.audit(tx, actor, "person add", key)
	}))
}

// UpdatePerson: name and Telegram id. The admin can't take away their own only way in.
func (s *Store) UpdatePerson(key, name, telegram, actor, admin string) error {
	if err := checkPerson(name, telegram); err != nil {
		return err
	}
	return dbRefusal(s.tx(func(tx *sql.Tx) error {
		if key == admin && telegram == "" {
			var pk bool
			if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM passkeys WHERE person = ?)`, key).Scan(&pk); err != nil {
				return err
			}
			if !pk {
				return refuse("Без Telegram id и без passkey админ не сможет войти")
			}
		}
		res, err := tx.Exec(`UPDATE people SET name = ?, telegram_id = ? WHERE key = ?`, strings.TrimSpace(name), nullable(telegram), key)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return refuse("Нет такого человека")
		}
		return s.audit(tx, actor, "person edit", fmt.Sprintf("%s: %s, telegram %s", key, strings.TrimSpace(name), or(telegram, "—")))
	}))
}

func (s *Store) DeletePerson(key, actor, admin string) error {
	if key == admin {
		return refuse("Админа удалить нельзя")
	}
	return s.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM people WHERE key = ?`, key)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return refuse("Нет такого человека")
		}
		if _, err := tx.Exec(`DELETE FROM settings WHERE key = 'notify' AND value = ?`, key); err != nil {
			return err
		}
		return s.audit(tx, actor, "person delete", key)
	})
}

// DeletePasskeyChecked: like DeletePasskey, but never the admin's last passkey: only a passkey
// opens the admin UI, so that would lock the admin out
func (s *Store) DeletePasskeyChecked(id []byte, actor, admin string) error {
	var person string
	err := s.db.QueryRow(`SELECT person FROM passkeys WHERE id = ?`, id).Scan(&person)
	if errors.Is(err, sql.ErrNoRows) {
		return refuse("Нет такого passkey")
	}
	if err != nil {
		return err
	}
	if person == admin {
		var n int
		if err := s.db.QueryRow(`SELECT count(*) FROM passkeys WHERE person = ?`, person).Scan(&n); err != nil {
			return err
		}
		if n == 1 {
			return refuse("Это последний passkey админа, а админка открывается только с passkey: сначала добавь другой")
		}
	}
	_, err = s.DeletePasskey(id, actor)
	return err
}

// ------------------------------------------------------------------ groups

func (s *Store) CreateGroup(name, actor string) error {
	if !groupNameRe.MatchString(name) {
		return refuse("Имя группы: строчная латиница, цифры и -")
	}
	return dbRefusal(s.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO groups (name) VALUES (?)`, name); err != nil {
			return err
		}
		return s.audit(tx, actor, "group add", name)
	}))
}

func (s *Store) DeleteGroup(name, actor string) error {
	return s.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM groups WHERE name = ?`, name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return refuse("Нет такой группы")
		}
		return s.audit(tx, actor, "group delete", name)
	})
}

func (s *Store) SetGroupMembers(name string, members []string, actor string) error {
	members = uniqueSorted(members)
	return dbRefusal(s.tx(func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM groups WHERE name = ?)`, name).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return refuse("Нет такой группы")
		}
		if _, err := tx.Exec(`DELETE FROM group_members WHERE group_name = ?`, name); err != nil {
			return err
		}
		for _, m := range members {
			if _, err := tx.Exec(`INSERT INTO group_members (group_name, person) VALUES (?, ?)`, name, m); err != nil {
				return err
			}
		}
		return s.audit(tx, actor, "group members", name+": "+strings.Join(members, ", "))
	}))
}

// ------------------------------------------------------------------- apps

// AppInput: an app as the admin UI sends it (the id comes from the path)
type AppInput struct {
	Name      string   `json:"name"`
	Redirects []string `json:"redirect_uris"`
	Logouts   []string `json:"post_logout_redirect_uris"`
	Login     []string `json:"login"`
	Allow     []string `json:"allow"`
}

func (in *AppInput) clean() {
	in.Name = strings.TrimSpace(in.Name)
	in.Redirects = uniqueSorted(in.Redirects)
	in.Logouts = uniqueSorted(in.Logouts)
	in.Login = uniqueSorted(in.Login)
	in.Allow = uniqueSorted(in.Allow)
}

// checkInput: the seed's rules; secret "-" stands for one that's already valid
func checkInput(id string, in *AppInput) error {
	if len(in.Login) == 0 {
		return refuse("Нужен хотя бы один способ входа")
	}
	if errs := checkApp(id, in.Name, in.Redirects, in.Logouts, in.Login, strings.Repeat("0", 64)); len(errs) > 0 {
		return refuse("%s", strings.Join(errs, "; "))
	}
	return nil
}

// writeApp: an app's URLs, login methods and access, replacing what was there
func (s *Store) writeApp(tx *sql.Tx, id string, in *AppInput) error {
	if _, err := tx.Exec(`UPDATE apps SET name = ?, login_telegram = ?, login_passkey = ? WHERE id = ?`,
		in.Name, bool01(slices.Contains(in.Login, "telegram")), bool01(slices.Contains(in.Login, "passkey")), id); err != nil {
		return err
	}
	for _, q := range []string{`DELETE FROM app_urls WHERE app = ?`, `DELETE FROM app_access WHERE app = ?`} {
		if _, err := tx.Exec(q, id); err != nil {
			return err
		}
	}
	for kind, urls := range map[string][]string{"redirect": in.Redirects, "logout": in.Logouts} {
		for _, u := range urls {
			if _, err := tx.Exec(`INSERT INTO app_urls (app, kind, url) VALUES (?, ?, ?)`, id, kind, u); err != nil {
				return err
			}
		}
	}
	for _, who := range in.Allow {
		var err error
		if g, ok := strings.CutPrefix(who, "group:"); ok {
			_, err = tx.Exec(`INSERT INTO app_access (app, group_name) VALUES (?, ?)`, id, g)
		} else {
			_, err = tx.Exec(`INSERT INTO app_access (app, person) VALUES (?, ?)`, id, who)
		}
		if err != nil {
			return refuse("Нет такого человека или группы: %s", who)
		}
	}
	return nil
}

func (s *Store) CreateApp(id string, in AppInput, secretHash []byte, actor string) error {
	in.clean()
	if err := checkInput(id, &in); err != nil {
		return err
	}
	return dbRefusal(s.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO apps (id, name, secret_sha256, created_at) VALUES (?, ?, ?, ?)`, id, in.Name, secretHash, s.now().Unix()); err != nil {
			return err
		}
		if err := s.writeApp(tx, id, &in); err != nil {
			return err
		}
		return s.audit(tx, actor, "app add", id)
	}))
}

func (s *Store) UpdateApp(id string, in AppInput, actor string) error {
	in.clean()
	if err := checkInput(id, &in); err != nil {
		return err
	}
	return dbRefusal(s.tx(func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM apps WHERE id = ?)`, id).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return refuse("Нет такого сайта")
		}
		if err := s.writeApp(tx, id, &in); err != nil {
			return err
		}
		return s.audit(tx, actor, "app edit", fmt.Sprintf("%s: login %s; allow %s; redirect %s", id,
			strings.Join(in.Login, "+"), strings.Join(in.Allow, ", "), strings.Join(in.Redirects, " ")))
	}))
}

func (s *Store) SetAppSecret(id string, secretHash []byte, actor string) error {
	return s.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE apps SET secret_sha256 = ? WHERE id = ?`, secretHash, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return refuse("Нет такого сайта")
		}
		return s.audit(tx, actor, "app secret", id)
	})
}

func (s *Store) DeleteApp(id, actor string) error {
	return s.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM apps WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return refuse("Нет такого сайта")
		}
		return s.audit(tx, actor, "app delete", id)
	})
}

// --------------------------------------------------------------- settings

func (s *Store) SetNotify(person, actor string) error {
	return s.tx(func(tx *sql.Tx) error {
		if person == "" {
			if _, err := tx.Exec(`DELETE FROM settings WHERE key = 'notify'`); err != nil {
				return err
			}
			return s.audit(tx, actor, "notify", "—")
		}
		var tg sql.NullString
		err := tx.QueryRow(`SELECT telegram_id FROM people WHERE key = ?`, person).Scan(&tg)
		if errors.Is(err, sql.ErrNoRows) {
			return refuse("Нет такого человека")
		}
		if err != nil {
			return err
		}
		if !tg.Valid {
			return refuse("Боту некому писать: у этого человека нет Telegram id")
		}
		if _, err := tx.Exec(`INSERT INTO settings (key, value) VALUES ('notify', ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, person); err != nil {
			return err
		}
		return s.audit(tx, actor, "notify", person)
	})
}

// ------------------------------------------------------------------ audit

type AuditEntry struct {
	ID     int64  `json:"id"`
	At     int64  `json:"at"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

// Audit: up to limit entries older than before (0: the newest), newest first
func (s *Store) Audit(before int64, limit int) ([]AuditEntry, error) {
	if before <= 0 {
		before = 1 << 62
	}
	rows, err := s.db.Query(`SELECT id, at, actor, action, detail FROM audit WHERE id < ? ORDER BY id DESC LIMIT ?`, before, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []AuditEntry{}
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.ID, &a.At, &a.Actor, &a.Action, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// NewClientSecret: 256 random bits as hex (nothing to escape in Basic auth or a shell), and the
// SHA-256 the database keeps instead of it
func NewClientSecret() (string, []byte) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	secret := hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(secret))
	return secret, sum[:]
}
