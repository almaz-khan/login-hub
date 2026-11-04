package hub

// The admin UI's JSON API. Every call needs the admin logged in (HUB_ADMIN) and comes from the
// hub's own page: Sec-Fetch-Site same-origin (or, without it, the hub's Origin), and a JSON body
// for writes, so no form or link on another site can change anything.
//
//	GET    /admin/api/state                   people, groups, apps, notify
//	GET    /admin/api/audit?before=<id>       the newest 100 entries (older with before)
//	POST   /admin/api/people                  {key, name, telegram_id}
//	PUT    /admin/api/people/{key}            {name, telegram_id}
//	DELETE /admin/api/people/{key}
//	POST   /admin/api/people/{key}/enroll     → {link}: a passkey link, single use, 24 h
//	DELETE /admin/api/passkeys/{id}
//	POST   /admin/api/groups                  {name}
//	PUT    /admin/api/groups/{name}/members   {members: [...]}
//	DELETE /admin/api/groups/{name}
//	POST   /admin/api/apps                    {id, name, redirect_uris, post_logout_redirect_uris, login, allow} → {secret}
//	PUT    /admin/api/apps/{id}               the same without id
//	POST   /admin/api/apps/{id}/secret        → {secret}: a new one; the old stops working
//	DELETE /admin/api/apps/{id}
//	PUT    /admin/api/settings                {notify}

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"hub/internal/store"
)

type apiFunc func(r *http.Request, admin *store.Person) (any, error)

func (a *Server) apiRoutes() http.Handler {
	mux := http.NewServeMux()
	h := func(pattern string, fn apiFunc) { mux.Handle(pattern, a.api(fn)) }

	h("GET /admin/api/state", func(r *http.Request, admin *store.Person) (any, error) {
		st, err := a.store.State()
		if st != nil {
			st.Me = admin.Key
		}
		return st, err
	})
	h("GET /admin/api/audit", func(r *http.Request, _ *store.Person) (any, error) {
		before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
		return a.store.Audit(before, 100)
	})

	h("POST /admin/api/people", func(r *http.Request, admin *store.Person) (any, error) {
		var in struct {
			Key        string `json:"key"`
			Name       string `json:"name"`
			TelegramID string `json:"telegram_id"`
		}
		if err := readJSON(r, &in); err != nil {
			return nil, err
		}
		return nil, a.store.CreatePerson(in.Key, in.Name, in.TelegramID, admin.Key)
	})
	h("PUT /admin/api/people/{key}", func(r *http.Request, admin *store.Person) (any, error) {
		var in struct {
			Name       string `json:"name"`
			TelegramID string `json:"telegram_id"`
		}
		if err := readJSON(r, &in); err != nil {
			return nil, err
		}
		return nil, a.store.UpdatePerson(r.PathValue("key"), in.Name, in.TelegramID, admin.Key, a.cfg.Admin)
	})
	h("DELETE /admin/api/people/{key}", func(r *http.Request, admin *store.Person) (any, error) {
		return nil, a.store.DeletePerson(r.PathValue("key"), admin.Key, a.cfg.Admin)
	})
	h("POST /admin/api/people/{key}/enroll", func(r *http.Request, admin *store.Person) (any, error) {
		p, err := a.store.Person(r.PathValue("key"))
		if err != nil {
			return nil, err
		}
		if p == nil {
			return nil, refuse("Нет такого человека")
		}
		token, err := a.store.CreateEnrollment(p.Key, admin.Key, enrollTTL)
		if err != nil {
			return nil, err
		}
		a.log.Printf("admin: %s made a passkey link for %s", admin.Key, p.Key)
		return map[string]any{"link": a.issuer + "/enroll?t=" + token, "expires": a.now().Add(enrollTTL).Unix()}, nil
	})
	h("DELETE /admin/api/passkeys/{id}", func(r *http.Request, admin *store.Person) (any, error) {
		id, err := b64.DecodeString(r.PathValue("id"))
		if err != nil {
			return nil, refuse("Нет такого passkey")
		}
		return nil, a.store.DeletePasskeyChecked(id, admin.Key, a.cfg.Admin)
	})

	h("POST /admin/api/groups", func(r *http.Request, admin *store.Person) (any, error) {
		var in struct {
			Name string `json:"name"`
		}
		if err := readJSON(r, &in); err != nil {
			return nil, err
		}
		return nil, a.store.CreateGroup(in.Name, admin.Key)
	})
	h("PUT /admin/api/groups/{name}/members", func(r *http.Request, admin *store.Person) (any, error) {
		var in struct {
			Members []string `json:"members"`
		}
		if err := readJSON(r, &in); err != nil {
			return nil, err
		}
		return nil, a.store.SetGroupMembers(r.PathValue("name"), in.Members, admin.Key)
	})
	h("DELETE /admin/api/groups/{name}", func(r *http.Request, admin *store.Person) (any, error) {
		return nil, a.store.DeleteGroup(r.PathValue("name"), admin.Key)
	})

	h("POST /admin/api/apps", func(r *http.Request, admin *store.Person) (any, error) {
		var in struct {
			ID string `json:"id"`
			store.AppInput
		}
		if err := readJSON(r, &in); err != nil {
			return nil, err
		}
		secret, hash := store.NewClientSecret()
		if err := a.store.CreateApp(in.ID, in.AppInput, hash, admin.Key); err != nil {
			return nil, err
		}
		return map[string]string{"secret": secret}, nil
	})
	h("PUT /admin/api/apps/{id}", func(r *http.Request, admin *store.Person) (any, error) {
		var in store.AppInput
		if err := readJSON(r, &in); err != nil {
			return nil, err
		}
		return nil, a.store.UpdateApp(r.PathValue("id"), in, admin.Key)
	})
	h("POST /admin/api/apps/{id}/secret", func(r *http.Request, admin *store.Person) (any, error) {
		secret, hash := store.NewClientSecret()
		if err := a.store.SetAppSecret(r.PathValue("id"), hash, admin.Key); err != nil {
			return nil, err
		}
		return map[string]string{"secret": secret}, nil
	})
	h("DELETE /admin/api/apps/{id}", func(r *http.Request, admin *store.Person) (any, error) {
		return nil, a.store.DeleteApp(r.PathValue("id"), admin.Key)
	})

	h("PUT /admin/api/settings", func(r *http.Request, admin *store.Person) (any, error) {
		var in struct {
			Notify string `json:"notify"`
		}
		if err := readJSON(r, &in); err != nil {
			return nil, err
		}
		return nil, a.store.SetNotify(in.Notify, admin.Key)
	})

	mux.HandleFunc("/admin/api/", func(w http.ResponseWriter, r *http.Request) {
		jsonError(w, http.StatusNotFound, "Нет такого запроса")
	})
	return mux
}

// api: the checks every admin call shares, then fn; a userErr becomes a 400 the UI shows
func (a *Server) api(fn apiFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		site, origin := r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Origin")
		write := r.Method != http.MethodGet && r.Method != http.MethodHead
		same := site == "same-origin" || site == "" && (!write || origin == a.issuer)
		if !same || write && r.ContentLength != 0 && r.Header.Get("Content-Type") != "application/json" {
			jsonError(w, http.StatusForbidden, "Только со страницы админки")
			return
		}
		admin := a.admin(r)
		if admin == nil {
			jsonError(w, http.StatusForbidden, "Только для админа: войди заново")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		out, err := fn(r, admin)
		var ue *store.UserError
		switch {
		case errors.As(err, &ue):
			jsonError(w, http.StatusBadRequest, ue.Msg)
		case err != nil:
			a.log.Printf("admin api: %s %s: %v", r.Method, r.URL.Path, err)
			jsonError(w, http.StatusInternalServerError, "Не получилось: подробности в логе хаба")
		case out == nil:
			jsonOut(w, http.StatusOK, map[string]bool{"ok": true})
		default:
			jsonOut(w, http.StatusOK, out)
		}
		if err == nil && write {
			a.log.Printf("admin: %s %s %s", admin.Key, r.Method, r.URL.Path)
		}
	})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return refuse("Не получилось прочитать запрос: %v", err)
	}
	return nil
}

// refuse: an answer the admin reads (a 400), as opposed to a broken database
func refuse(format string, args ...any) error {
	return &store.UserError{Msg: fmt.Sprintf(format, args...)}
}
