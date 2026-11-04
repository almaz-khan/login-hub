package hub

// identity: who a session's proofs belong to, read from the database on every request, so a
// deleted person, a changed Telegram id or a removed passkey count at once. Proofs of two
// different people never add up: the newer one wins and the other is ignored.

import (
	"slices"
	"strings"
	"time"

	"hub/internal/store"
)

type identity struct {
	person *store.Person // nil: nobody, or a Telegram account the hub doesn't know
	tg     *tgProof      // the proofs that belong to person (tg alone may be an unknown account)
	pk     *pkProof
}

func (id identity) methods() []string {
	var m []string
	if id.tg != nil {
		m = append(m, "telegram")
	}
	if id.pk != nil {
		m = append(m, "passkey")
	}
	return m
}

func (id identity) proven() bool { return id.tg != nil || id.pk != nil }

// accepts: the methods this person proved that app c accepts
func (id identity) accepted(c *store.App) []string {
	return slices.DeleteFunc(id.methods(), func(m string) bool { return !c.Accepts(m) })
}

// authTime: when they last proved who they are
func (id identity) authTime() int64 {
	var t int64
	if id.tg != nil {
		t = id.tg.At
	}
	if id.pk != nil && id.pk.At > t {
		t = id.pk.At
	}
	return t
}

func (a *Server) resolve(s *sessionData) (identity, error) {
	fresh := func(at int64) bool { return a.now().Sub(time.Unix(at, 0)) < sessionTTL }
	var id identity
	var tgPerson, pkPerson *store.Person
	var err error
	if s.TG != nil && fresh(s.TG.At) {
		if tgPerson, err = a.store.PersonByTelegram(s.TG.ID); err != nil {
			return id, err
		}
		id.tg = s.TG
	}
	if s.PK != nil && fresh(s.PK.At) {
		ok, err := a.store.PasskeyOf(s.PK.Cred, s.PK.Person)
		if err != nil {
			return id, err
		}
		if ok {
			if pkPerson, err = a.store.Person(s.PK.Person); err != nil {
				return id, err
			}
		}
		if pkPerson != nil {
			id.pk = s.PK
		}
	}
	switch {
	case id.pk == nil:
		id.person = tgPerson
	case id.tg == nil:
		id.person = pkPerson
	case tgPerson != nil && tgPerson.Key == pkPerson.Key:
		id.person = tgPerson
	case id.pk.At >= id.tg.At: // two different people: the newer login wins
		id.person, id.tg = pkPerson, nil
	default:
		id.person, id.pk = tgPerson, nil
	}
	return id, nil
}

// addProof: the session after a new login. A proof that belongs to someone else is dropped.
func (a *Server) addProof(old *sessionData, tg *tgProof, pk *pkProof) (*sessionData, *store.Person, error) {
	s := &sessionData{TG: old.TG, PK: old.PK}
	if tg != nil {
		s.TG = tg
	}
	if pk != nil {
		s.PK = pk
	}
	id, err := a.resolve(s)
	if err != nil {
		return nil, nil, err
	}
	// the login just made always wins, even against an older proof from the same second
	if tg != nil && id.tg == nil {
		id, err = a.resolve(&sessionData{TG: tg})
	} else if pk != nil && id.pk == nil {
		id, err = a.resolve(&sessionData{PK: pk})
	}
	if err != nil {
		return nil, nil, err
	}
	return &sessionData{TG: id.tg, PK: id.pk}, id.person, nil
}

func (id identity) username() string {
	if id.tg != nil {
		return id.tg.Username
	}
	return ""
}

// label: for the log
func (id identity) label() string {
	switch {
	case id.person != nil:
		return id.person.Key + " (" + strings.Join(id.methods(), "+") + ")"
	case id.tg != nil:
		return "unknown Telegram account " + id.tg.ID + " (" + id.tg.Name + " @" + id.tg.Username + ")"
	}
	return "nobody"
}
