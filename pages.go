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
	"strings"
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
.note{font-size:13px;color:#a59eb2}
.btn:disabled{opacity:.6;cursor:progress}
.note:empty{display:none}`

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

// passkeyJS: the only script the hub serves, inline and allowed by its hash. It asks the browser
// for a passkey and posts the answer back; base64url ↔ bytes by hand, since the JSON helpers
// (parseRequestOptionsFromJSON, toJSON) aren't in every browser yet.
const passkeyJS = `const d=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)).buffer;
const u=a=>btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const btn=document.getElementById('pk'),msg=document.getElementById('msg');
const post=async(path,body)=>{const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||'Не получилось войти');return j};
btn.addEventListener('click',async()=>{btn.disabled=true;msg.textContent='';try{
const o=await post('/login/passkey/options',{});const p=o.options.publicKey;p.challenge=d(p.challenge);
const c=await navigator.credentials.get({publicKey:p});const r=c.response;
const j=await post('/login/passkey/verify',{challenge:o.challenge,next:btn.dataset.next,credential:{id:c.id,rawId:u(c.rawId),type:c.type,response:{clientDataJSON:u(r.clientDataJSON),authenticatorData:u(r.authenticatorData),signature:u(r.signature),userHandle:r.userHandle?u(r.userHandle):null},clientExtensionResults:c.getClientExtensionResults()}});
location.assign(j.next)}catch(e){msg.textContent=e.name==='NotAllowedError'?'Вход отменён. Попробуй ещё раз.':e.message;btn.disabled=false}});`

var passkeyCSP = fmt.Sprintf("default-src 'none'; style-src '%s'; script-src '%s'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", cssHash, hash(passkeyJS))

func pageScript(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", passkeyCSP)
	w.WriteHeader(status)
	_, _ = fmt.Fprint(w, body)
}

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
<div class="kick">Один вход</div>
` + body + `
</main>
</body>
</html>`
}

var e = html.EscapeString

var (
	methodButton = map[string]string{"telegram": "Войти через Telegram", "passkey": "Войти с passkey"}
	methodOther  = map[string]string{"telegram": "Другой аккаунт Telegram", "passkey": "Другой passkey"}
	methodName   = map[string]string{"telegram": "Telegram", "passkey": "passkey"}
)

// methodsText: «Telegram», «passkey» or «Telegram или passkey»
func methodsText(methods []string) string {
	names := make([]string, len(methods))
	for i, m := range methods {
		names[i] = methodName[m]
	}
	return strings.Join(names, " или ")
}

// loginButton: a login with method, then on to next (an /authorize request)
func loginButton(method, label, next string, alt bool) string {
	href := "/login/" + method
	if next = safeNext(next); next != "/" {
		href += "?next=" + url.QueryEscape(next)
	}
	class := "btn"
	if alt {
		class += " alt"
	}
	return `<a class="` + class + `" href="` + e(href) + `">` + label + `</a>`
}

func account(id identity) string {
	name := "без имени"
	switch {
	case id.person != nil:
		name = id.person.Name
	case id.tg != nil && id.tg.Name != "":
		name = id.tg.Name
	}
	s := "<b>" + e(name) + "</b>"
	if u := id.username(); u != "" {
		s += " (@" + e(u) + ")"
	}
	return s
}

var (
	pageClosed = layout("Закрыто", `<h1>Вход закрыт</h1>
<p>Вход ещё не настроен или настроен с ошибкой, поэтому сейчас никто войти не может.</p>`)

	pageBadLink = layout("Неверная ссылка", `<h1>Неверная ссылка для входа</h1>
<p>Сайт, с которого ты пришёл, прислал ссылку, которой здесь не знают. Вернись на сайт и попробуй ещё раз. Если не выйдет, напиши тому, кто дал ссылку.</p>`)
)

func pageHome(id identity) string {
	if !id.proven() {
		return layout("Вход", `<h1>Один вход на все сайты</h1>
<p>Сайты отправляют сюда, чтобы узнать, кто ты. Войти нужно один раз, дальше сайты открываются сами.</p>
<p class="note">Сюда приходят с сайта: открой нужный сайт, он сам пришлёт на вход.</p>`)
	}
	return layout("Вход", `<h1>Ты вошёл</h1>
<p>Как `+account(id)+`, через `+methodsText(id.methods())+`. Сайты, куда у тебя есть доступ, откроются сами.</p>
<a class="btn alt" href="/logout">Выйти на всех сайтах</a>`)
}

// pageChooser: the app's login methods; for someone already logged in another way, a step-up
func pageChooser(c *client, id identity, next string) string {
	var b strings.Builder
	if id.proven() {
		fmt.Fprintf(&b, `<p>Ты вошёл как %s через %s, а для «%s» нужен вход через %s.</p>`, account(id), methodsText(id.methods()), e(c.Name), methodsText(c.methods()))
	} else {
		fmt.Fprintf(&b, `<p>Сайт «%s» узнает, кто ты. Войти нужно один раз, дальше сайты открываются сами.</p>`, e(c.Name))
	}
	for i, m := range c.methods() {
		b.WriteString(loginButton(m, methodButton[m], next, i > 0))
	}
	return layout("Вход", `<h1>Вход на «`+e(c.Name)+`»</h1>
`+b.String())
}

func pagePasskey(next string) string {
	return layout("Вход с passkey", `<h1>Вход с passkey</h1>
<p>Телефон или компьютер попросит Face ID, отпечаток или код устройства.</p>
<button class="btn" type="button" id="pk" data-next="`+e(next)+`">Войти с passkey</button>
<p class="note" id="msg" role="status" aria-live="polite"></p>
<script>`+passkeyJS+`</script>`)
}

// pageNoPasskey: a passkey-only app, for someone the hub knows but who has no passkey yet
func pageNoPasskey(c *client, id identity) string {
	return layout("Нужен passkey", `<h1>Нужен passkey</h1>
<p>Ты вошёл как `+account(id)+`, но в «`+e(c.Name)+`» входят только с passkey, а у тебя его ещё нет. Попроси ссылку, чтобы его создать.</p>`)
}

func pageFailed(next string) string {
	return layout("Не получилось войти", `<h1>Не получилось войти</h1>
<p>Вход не подтвердился, или ссылка для входа устарела. Попробуй ещё раз.</p>
`+loginButton("telegram", methodButton["telegram"], next, false))
}

func pageDenied(c *client, id identity, next string) string {
	var b strings.Builder
	for _, m := range c.methods() {
		b.WriteString(loginButton(m, methodOther[m], next, true))
	}
	return layout("Нет доступа", `<h1>Нет доступа</h1>
<p>У аккаунта `+account(id)+` нет доступа к сайту «`+e(c.Name)+`». Если он нужен, напиши тому, кто прислал ссылку.</p>
`+b.String())
}

func pageLogout(id identity, t logoutTarget) string {
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
<p>Ты вошёл как `+account(id)+`. Это устройство забудет вход, и чтобы вернуться на любой сайт, понадобится войти снова.</p>
<p class="note">Сайты, открытые сейчас, попросят войти заново не позже чем через сутки.</p>
<form method="post" action="/logout">`+hidden+`<button class="btn" type="submit">Выйти на всех сайтах</button></form>`)
}

func pageLoggedOut(t logoutTarget) string {
	back := ""
	if t.back != "" {
		back = `<a class="btn alt" href="` + e(t.url()) + `">Вернуться на «` + e(t.app.Name) + `»</a>`
	}
	return layout("Выход", `<h1>Ты вышел</h1>
<p>Это устройство больше не помнит вход.</p>`+back)
}
