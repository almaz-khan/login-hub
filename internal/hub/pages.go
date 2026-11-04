package hub

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

	"hub/internal/store"
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
.note:empty{display:none}
[hidden]{display:none!important}
label{display:grid;gap:6px;font-size:14px;color:#d9d3e3}
input{font:inherit;padding:12px 14px;border-radius:12px;border:1px solid #4a4352;background:#141118;color:#f5f1fb}
input:focus-visible{outline:3px solid #f5f1fb;outline-offset:2px}
main.wide{max-width:760px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;vertical-align:top;padding:10px 8px;border-top:1px solid #322c39}
th{font-weight:600;color:#a59eb2}
.mini{display:inline-block;width:auto;margin:0;padding:6px 12px;font-size:13px}
.row{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
code{font:13px/1.4 ui-monospace,Menlo,monospace;word-break:break-all;background:#141118;padding:10px 12px;border-radius:10px;display:block;user-select:all}
.scroll{overflow-x:auto}
.stack{display:grid;gap:12px}`

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

// passkeyJS: the only script the hub serves, inline and allowed by its hash: the login (#pk) and
// adding a passkey (#enroll). It asks the browser and posts the answer back; base64url ↔ bytes by
// hand, since the JSON helpers (parseRequestOptionsFromJSON, toJSON) aren't in every browser yet.
const passkeyJS = `const d=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)).buffer;
const u=a=>btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const $=id=>document.getElementById(id),msg=$('msg');
const post=async(path,body)=>{const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||'Не получилось');return j};
const run=(btn,fn)=>btn&&btn.addEventListener('click',async()=>{btn.disabled=true;msg.textContent='';try{await fn()}catch(e){msg.textContent=e.name==='NotAllowedError'?'Отменено. Попробуй ещё раз.':e.name==='InvalidStateError'?'Этот passkey уже добавлен.':e.message;btn.disabled=false}});
run($('pk'),async()=>{const o=await post('/login/passkey/options',{});const p=o.options.publicKey;p.challenge=d(p.challenge);
const c=await navigator.credentials.get({publicKey:p});const r=c.response;
const j=await post('/login/passkey/verify',{challenge:o.challenge,next:$('pk').dataset.next,credential:{id:c.id,rawId:u(c.rawId),type:c.type,response:{clientDataJSON:u(r.clientDataJSON),authenticatorData:u(r.authenticatorData),signature:u(r.signature),userHandle:r.userHandle?u(r.userHandle):null},clientExtensionResults:c.getClientExtensionResults()}});
location.assign(j.next)});
run($('enroll'),async()=>{const o=await post('/enroll/options',{token:$('enroll').dataset.token});const p=o.options.publicKey;p.challenge=d(p.challenge);p.user.id=d(p.user.id);(p.excludeCredentials||[]).forEach(c=>c.id=d(c.id));
const c=await navigator.credentials.create({publicKey:p});const r=c.response;
await post('/enroll/verify',{challenge:o.challenge,label:$('label').value,credential:{id:c.id,rawId:u(c.rawId),type:c.type,response:{clientDataJSON:u(r.clientDataJSON),attestationObject:u(r.attestationObject),transports:r.getTransports?r.getTransports():[]},clientExtensionResults:c.getClientExtensionResults()}});
$('form').hidden=true;$('done').hidden=false});`

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

func layout(title, body string) string { return layoutClass("", title, body) }

func layoutClass(class, title, body string) string {
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
<main` + class + `>
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

func pageHome(id identity, admin bool) string {
	if !id.proven() {
		return layout("Вход", `<h1>Один вход на все сайты</h1>
<p>Сайты отправляют сюда, чтобы узнать, кто ты. Войти нужно один раз, дальше сайты открываются сами.</p>
<p class="note">Сюда приходят с сайта: открой нужный сайт, он сам пришлёт на вход.</p>
<a class="btn alt" href="/admin">Админка</a>`)
	}
	return layout("Вход", `<h1>Ты вошёл</h1>
<p>Как `+account(id)+`, через `+methodsText(id.methods())+`. Сайты, куда у тебя есть доступ, откроются сами.</p>
`+homeLinks(id, admin)+`<a class="btn alt" href="/logout">Выйти на всех сайтах</a>`)
}

func homeLinks(id identity, admin bool) string {
	s := ""
	if id.person != nil {
		s += `<a class="btn alt" href="/enroll">Добавить passkey на этом устройстве</a>`
	}
	if admin {
		s += `<a class="btn alt" href="/admin">Админка</a>`
	}
	return s
}

// pageChooser: the app's login methods; for someone already logged in another way, a step-up
func pageChooser(c *store.App, id identity, next string, methods []string) string {
	var b strings.Builder
	if id.proven() {
		fmt.Fprintf(&b, `<p>Ты вошёл как %s через %s, а для «%s» нужен вход через %s.</p>`, account(id), methodsText(id.methods()), e(c.Name), methodsText(methods))
	} else {
		fmt.Fprintf(&b, `<p>Сайт «%s» узнает, кто ты. Войти нужно один раз, дальше сайты открываются сами.</p>`, e(c.Name))
	}
	for i, m := range methods {
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

var (
	pageLinkUsed = layout("Ссылка не работает", `<h1>Ссылка не работает</h1>
<p>Ссылка для passkey работает один раз и 24 часа. Эта уже использована или устарела: попроси новую.</p>`)

	pageLoginFirst = layout("Сначала войди", `<h1>Сначала войди</h1>
<p>Добавить passkey можно по ссылке от админа или войдя на любой сайт, куда у тебя есть доступ.</p>`)

	pageAdminOnly = layout("Только для админа", `<h1>Только для админа</h1>
<p>Ты вошёл, но не как тот, кто раздаёт доступ. Выйди и войди его аккаунтом.</p>
<a class="btn alt" href="/logout">Выйти</a>`)

	pageUINotBuilt = layout("Админка не собрана", `<h1>Админка не собрана</h1>
<p>В этой сборке хаба нет админки: <code>cd admin &amp;&amp; npm ci &amp;&amp; npm run build</code>, потом собери хаб заново.</p>`)
)

func pageEnroll(p *store.Person, token string) string {
	return layout("Новый passkey", `<h1>Новый passkey</h1>
<div id="form" class="stack">
<p>Для <b>`+e(p.Name)+`</b>. Телефон или компьютер попросит Face ID, отпечаток или код устройства, и дальше вход на сайты будет таким же.</p>
<label>Как назвать это устройство<input id="label" maxlength="60" placeholder="Например, iPhone" autocomplete="off"></label>
<button class="btn" type="button" id="enroll" data-token="`+e(token)+`">Создать passkey</button>
<p class="note" id="msg" role="status" aria-live="polite"></p>
</div>
<div id="done" hidden><p>Готово: passkey сохранён, и ты уже вошёл с ним на этом устройстве.</p><a class="btn alt" href="/">На главную</a></div>
<script>`+passkeyJS+`</script>`)
}

// pageAdminLogin: the admin UI asks for a passkey; Telegram never opens it
func pageAdminLogin() string {
	return layout("Админка", `<h1>Админка</h1>
<p>Для того, кто раздаёт доступ. Вход только с passkey.</p>
`+loginButton("passkey", methodButton["passkey"], "/admin", false))
}

// pageTelegramOff: a Telegram login asked for on a hub without one; c is the app, if known
func pageTelegramOff(c *store.App) string {
	what := "Вход через Telegram"
	if c != nil {
		what = "«" + e(c.Name) + "» принимает только вход через Telegram, а он"
	}
	return layout("Telegram выключен", `<h1>Telegram пока выключен</h1>
<p>`+what+` здесь ещё не настроен. Войти можно с passkey, если сайт его принимает.</p>`)
}

// pageNoPasskey: a passkey-only app, for someone the hub knows but who has no passkey yet
func pageNoPasskey(c *store.App, id identity) string {
	return layout("Нужен passkey", `<h1>Нужен passkey</h1>
<p>Ты вошёл как `+account(id)+`, но в «`+e(c.Name)+`» входят только с passkey, а у тебя его ещё нет. Попроси ссылку, чтобы его создать.</p>`)
}

func pageFailed(next string) string {
	return layout("Не получилось войти", `<h1>Не получилось войти</h1>
<p>Вход не подтвердился, или ссылка для входа устарела. Попробуй ещё раз.</p>
`+loginButton("telegram", methodButton["telegram"], next, false))
}

func pageDenied(c *store.App, id identity, next string, methods []string) string {
	var b strings.Builder
	for _, m := range methods {
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
