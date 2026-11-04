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
const post=async(path,body)=>{const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||'Something went wrong');return j};
const run=(btn,fn)=>btn&&btn.addEventListener('click',async()=>{btn.disabled=true;msg.textContent='';try{await fn()}catch(e){msg.textContent=e.name==='NotAllowedError'?'Cancelled. Try again.':e.name==='InvalidStateError'?'This passkey is already added.':e.message;btn.disabled=false}});
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
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔑</text></svg>">
<title>` + title + ` · Sign in</title>
<style>` + css + `</style>
</head>
<body>
<main` + class + `>
<div class="kick">One sign-in</div>
` + body + `
</main>
</body>
</html>`
}

var e = html.EscapeString

var (
	methodButton = map[string]string{"telegram": "Sign in with Telegram", "passkey": "Sign in with a passkey"}
	methodOther  = map[string]string{"telegram": "Another Telegram account", "passkey": "Another passkey"}
	methodName   = map[string]string{"telegram": "Telegram", "passkey": "passkey"}
)

// methodsText: "Telegram", "passkey" or "Telegram or passkey"
func methodsText(methods []string) string {
	names := make([]string, len(methods))
	for i, m := range methods {
		names[i] = methodName[m]
	}
	return strings.Join(names, " or ")
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
	name := "no name"
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
	pageClosed = layout("Closed", `<h1>Sign-in is closed</h1>
<p>Sign-in isn't set up yet, or is set up wrong, so nobody can sign in right now.</p>`)

	pageBadLink = layout("Wrong link", `<h1>Wrong sign-in link</h1>
<p>The site you came from sent a link this hub doesn't know. Go back to the site and try again. If that doesn't work, tell whoever gave you the link.</p>`)
)

func pageHome(id identity, admin bool) string {
	if !id.proven() {
		return layout("Sign in", `<h1>One sign-in for every site</h1>
<p>Sites send you here to find out who you are. Sign in once, and the sites open by themselves after that.</p>
<p class="note">You get here from a site: open the site you want, and it sends you here to sign in.</p>
<a class="btn alt" href="/admin">Admin</a>`)
	}
	return layout("Sign in", `<h1>You're signed in</h1>
<p>As `+account(id)+`, with `+methodsText(id.methods())+`. Sites you have access to open by themselves.</p>
`+homeLinks(id, admin)+`<a class="btn alt" href="/logout">Sign out everywhere</a>`)
}

func homeLinks(id identity, admin bool) string {
	s := ""
	if id.person != nil {
		s += `<a class="btn alt" href="/enroll">Add a passkey on this device</a>`
	}
	if admin {
		s += `<a class="btn alt" href="/admin">Admin</a>`
	}
	return s
}

// pageChooser: the app's login methods; for someone already logged in another way, a step-up
func pageChooser(c *store.App, id identity, next string, methods []string) string {
	var b strings.Builder
	if id.proven() {
		fmt.Fprintf(&b, `<p>You're signed in as %s with %s, but “%s” needs a sign-in with %s.</p>`, account(id), methodsText(id.methods()), e(c.Name), methodsText(methods))
	} else {
		fmt.Fprintf(&b, `<p>“%s” will find out who you are. Sign in once, and sites open by themselves after that.</p>`, e(c.Name))
	}
	for i, m := range methods {
		b.WriteString(loginButton(m, methodButton[m], next, i > 0))
	}
	return layout("Sign in", `<h1>Sign in to “`+e(c.Name)+`”</h1>
`+b.String())
}

func pagePasskey(next string) string {
	return layout("Sign in with a passkey", `<h1>Sign in with a passkey</h1>
<p>Your phone or computer will ask for Face ID, a fingerprint or the device passcode.</p>
<button class="btn" type="button" id="pk" data-next="`+e(next)+`">Sign in with a passkey</button>
<p class="note" id="msg" role="status" aria-live="polite"></p>
<script>`+passkeyJS+`</script>`)
}

var (
	pageLinkUsed = layout("Link doesn't work", `<h1>This link doesn't work</h1>
<p>A passkey link works once, for 24 hours. This one was already used or has expired: ask for a new one.</p>`)

	pageLoginFirst = layout("Sign in first", `<h1>Sign in first</h1>
<p>You can add a passkey with a link from the admin, or after signing in to any site you have access to.</p>`)

	pageAdminOnly = layout("Admin only", `<h1>Admin only</h1>
<p>You're signed in, but not as the person who gives out access. Sign out and sign in with their account.</p>
<a class="btn alt" href="/logout">Sign out</a>`)

	pageUINotBuilt = layout("Admin UI not built", `<h1>The admin UI isn't built</h1>
<p>This build of the hub has no admin UI: run <code>cd admin &amp;&amp; npm ci &amp;&amp; npm run build</code>, then build the hub again.</p>`)
)

func pageEnroll(p *store.Person, token string) string {
	return layout("New passkey", `<h1>New passkey</h1>
<div id="form" class="stack">
<p>For <b>`+e(p.Name)+`</b>. Your phone or computer will ask for Face ID, a fingerprint or the device passcode, and signing in to sites will work the same way from then on.</p>
<label>Name this device<input id="label" maxlength="60" placeholder="For example, iPhone" autocomplete="off"></label>
<button class="btn" type="button" id="enroll" data-token="`+e(token)+`">Create passkey</button>
<p class="note" id="msg" role="status" aria-live="polite"></p>
</div>
<div id="done" hidden><p>Done: the passkey is saved, and you're already signed in with it on this device.</p><a class="btn alt" href="/">Home</a></div>
<script>`+passkeyJS+`</script>`)
}

// pageAdminLogin: the admin UI asks for a passkey, right here (served with pageScript); Telegram
// never opens it
func pageAdminLogin() string {
	return layout("Admin", `<h1>Admin</h1>
<p>For the person who gives out access. Passkey sign-in only.</p>
<button class="btn" type="button" id="pk" data-next="/admin">`+methodButton["passkey"]+`</button>
<p class="note" id="msg" role="status" aria-live="polite"></p>
<script>`+passkeyJS+`</script>`)
}

// pageTelegramOff: a Telegram login asked for on a hub without one; c is the app, if known
func pageTelegramOff(c *store.App) string {
	what := "Sign-in with Telegram isn't set up here yet."
	if c != nil {
		what = "“" + e(c.Name) + "” only takes a Telegram sign-in, and that isn't set up here yet."
	}
	return layout("Telegram is off", `<h1>Telegram is off for now</h1>
<p>`+what+` You can sign in with a passkey if the site takes one.</p>`)
}

// pageNoPasskey: a passkey-only app, for someone the hub knows but who has no passkey yet
func pageNoPasskey(c *store.App, id identity) string {
	return layout("Passkey needed", `<h1>Passkey needed</h1>
<p>You're signed in as `+account(id)+`, but “`+e(c.Name)+`” only takes a passkey sign-in, and you don't have a passkey yet. Ask for a link to create one.</p>`)
}

func pageFailed(next string) string {
	return layout("Sign-in failed", `<h1>Sign-in failed</h1>
<p>The sign-in wasn't confirmed, or the sign-in link has expired. Try again.</p>
`+loginButton("telegram", methodButton["telegram"], next, false))
}

func pageDenied(c *store.App, id identity, next string, methods []string) string {
	var b strings.Builder
	for _, m := range methods {
		b.WriteString(loginButton(m, methodOther[m], next, true))
	}
	return layout("No access", `<h1>No access</h1>
<p>The account `+account(id)+` has no access to “`+e(c.Name)+`”. If you need it, tell whoever sent you the link.</p>
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
	return layout("Sign out", `<h1>Sign out everywhere?</h1>
<p>You're signed in as `+account(id)+`. This device will forget the sign-in, and you'll need to sign in again to get back to any site.</p>
<p class="note">Sites open right now will ask you to sign in again within a day.</p>
<form method="post" action="/logout">`+hidden+`<button class="btn" type="submit">Sign out everywhere</button></form>`)
}

func pageLoggedOut(t logoutTarget) string {
	back := ""
	if t.back != "" {
		back = `<a class="btn alt" href="` + e(t.url()) + `">Back to “` + e(t.app.Name) + `”</a>`
	}
	return layout("Sign out", `<h1>You're signed out</h1>
<p>This device no longer remembers the sign-in.</p>`+back)
}
