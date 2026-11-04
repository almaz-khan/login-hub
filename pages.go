package main

// The hub's pages. Self-contained (system fonts, no scripts) and served with a CSP that allows
// exactly their one inline style. Everything that comes from Telegram or a request is escaped.

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"net/url"
)

const css = `:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px 16px;background:#141118;color:#f5f1fb;font:16px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}
main{width:100%;max-width:420px;display:grid;gap:16px;padding:40px 24px 28px;border-radius:22px;background:#1d1922;box-shadow:0 30px 80px -30px rgba(0,0,0,.7)}
.kick{font:500 12px/1.4 ui-monospace,Menlo,monospace;letter-spacing:.14em;text-transform:uppercase;opacity:.75}
h1{margin:0;font:800 30px/1.1 system-ui,-apple-system,'Segoe UI',sans-serif;letter-spacing:-.01em}
p{margin:0;color:#d9d3e3}
b{color:#f5f1fb}
form{margin:0}
.btn{display:block;width:100%;border:0;cursor:pointer;font:inherit;margin-top:8px;padding:14px 18px;border-radius:999px;background:#d6f23c;color:#141118;font-weight:700;text-align:center;text-decoration:none}
.btn.alt{background:transparent;color:#f5f1fb;box-shadow:inset 0 0 0 1px #4a4352}
.btn:focus-visible{outline:3px solid #f5f1fb;outline-offset:3px}
.note{font-size:13px;color:#a59eb2}`

var cssHash = hash(css)

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

func csp(formAction string) string {
	if formAction != "" {
		formAction = " " + formAction
	}
	return fmt.Sprintf("default-src 'none'; style-src '%s'; img-src data:; base-uri 'none'; form-action 'self'%s; frame-ancestors 'none'", cssHash, formAction)
}

func page(w http.ResponseWriter, status int, body string) { pageCSP(w, status, body, "") }

func pageCSP(w http.ResponseWriter, status int, body, formAction string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", csp(formAction))
	w.WriteHeader(status)
	_, _ = fmt.Fprint(w, body)
}

func layout(title, body string) string {
	return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔑</text></svg>">
<title>` + title + ` · Вход</title>
<style>` + css + `</style>
</head>
<body>
<main>
<div class="kick">Вход через Telegram</div>
` + body + `
</main>
</body>
</html>`
}

var e = html.EscapeString

// loginButton: a fresh Telegram login, then on to next (an /authorize request)
func loginButton(label, next string, alt bool) string {
	href := "/login"
	if next = safeNext(next); next != "/" {
		href += "?next=" + url.QueryEscape(next)
	}
	class := "btn"
	if alt {
		class += " alt"
	}
	return `<a class="` + class + `" href="` + e(href) + `">` + label + `</a>`
}

func account(who sessionData) string {
	s := "<b>" + e(or(who.Name, "без имени")) + "</b>"
	if who.Username != "" {
		s += " (@" + e(who.Username) + ")"
	}
	return s
}

var (
	pageClosed = layout("Закрыто", `<h1>Вход закрыт</h1>
<p>Вход ещё не настроен или настроен с ошибкой, поэтому сейчас никто войти не может.</p>`)

	pageBadLink = layout("Неверная ссылка", `<h1>Неверная ссылка для входа</h1>
<p>Сайт, с которого ты пришёл, прислал ссылку, которой здесь не знают. Вернись на сайт и попробуй ещё раз. Если не выйдет, напиши тому, кто дал ссылку.</p>`)
)

func pageHome(who *sessionData) string {
	if who == nil {
		return layout("Вход", `<h1>Один вход на все сайты</h1>
<p>Сайты отправляют сюда, чтобы узнать, кто ты. Войти через Telegram нужно один раз, дальше сайты открываются сами.</p>
<p class="note">Сюда приходят с сайта: открой нужный сайт, он сам пришлёт на вход.</p>`)
	}
	return layout("Вход", `<h1>Ты вошёл</h1>
<p>Как `+account(*who)+`. Сайты, куда у тебя есть доступ, откроются без Telegram.</p>
<a class="btn alt" href="/logout">Выйти на всех сайтах</a>`)
}

func pageFailed(next string) string {
	return layout("Не получилось войти", `<h1>Не получилось войти</h1>
<p>Telegram не подтвердил вход, или ссылка для входа устарела. Попробуй ещё раз.</p>
`+loginButton("Войти через Telegram", next, false))
}

func pageDenied(appName string, who sessionData, next string) string {
	return layout("Нет доступа", `<h1>Нет доступа</h1>
<p>У аккаунта `+account(who)+` нет доступа к сайту «`+e(appName)+`». Если он нужен, напиши тому, кто прислал ссылку.</p>
`+loginButton("Войти другим аккаунтом", next, true))
}

func pageLogout(who sessionData, t logoutTarget) string {
	hidden := ""
	if t.app != nil {
		hidden += `<input type="hidden" name="client_id" value="` + e(t.app.ID) + `">`
	}
	if t.back != "" {
		hidden += `<input type="hidden" name="post_logout_redirect_uri" value="` + e(t.back) + `">`
	}
	if t.state != "" {
		hidden += `<input type="hidden" name="state" value="` + e(t.state) + `">`
	}
	return layout("Выход", `<h1>Выйти на всех сайтах?</h1>
<p>Ты вошёл как `+account(who)+`. Это устройство забудет вход, и чтобы вернуться на любой сайт, понадобится Telegram.</p>
<p class="note">Сайты, открытые сейчас, попросят войти заново не позже чем через сутки.</p>
<form method="post" action="/logout">`+hidden+`<button class="btn" type="submit">Выйти на всех сайтах</button></form>`)
}

func pageLoggedOut(t logoutTarget) string {
	back := ""
	if t.back != "" {
		back = `<a class="btn alt" href="` + e(t.url()) + `">Вернуться на «` + e(t.app.Name) + `»</a>`
	}
	return layout("Выход", `<h1>Ты вышел</h1>
<p>Это устройство больше не помнит вход через Telegram.</p>`+back)
}
