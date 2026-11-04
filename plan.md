# Login hub: one login for all apps

## Goal

One small service, the **hub** at `https://login.almaz.dev`, logs people in for every app and decides
who may open which app. Each app stops doing its own login and becomes a standard OpenID Connect
client of the hub.

- Two ways to log in: **Telegram** and **passkey**. Each app chooses which it accepts: both, only
  Telegram, or only passkey.
- Log in once; every other app you're allowed in opens without a login screen (as long as your
  hub login used a method that app accepts).
- Different people get different apps.
- The hub knows only who someone is, how they proved it, and which apps they may open. It never
  holds app data (no chat data, photos or stats).
- **No personal data in git.** The repo can go public at any time: people, access and passkeys
  live only in the hub's database.

## Why this shape

- **Standard OIDC between hub and apps.** Apps on `*.almaz.dev`, on Railway domains, and on the
  Hetzner server (`almaz.gdn`) all work the same way: OIDC only uses redirects, so no shared cookie
  is needed. Running Club already does an OIDC code flow against Telegram (`server/auth.go`), so
  switching it to the hub is mostly config. Other apps use an off-the-shelf OIDC client library.
- **`login.almaz.dev`, not a Railway domain:** the issuer is baked into every app and every token,
  so it must not change if the Railway service is ever recreated.
- **Built, not bought.** Keycloak, Authentik and Zitadel need Postgres and hundreds of MB of RAM,
  and Telegram isn't a standard login source for them. The hub is a ~15 MB Go binary on a
  `FROM scratch` image, reusing Running Club's tested Telegram login and p2pvc's passkey rules.
- **SQLite, not a config file.** An admin UI is planned, and the data is relational (people ↔
  groups ↔ apps, passkeys per person). SQLite gives foreign keys, cascades and transactions for
  free; `modernc.org/sqlite` is pure Go (no CGO), as in p2pvc and subdrop.

## Data

SQLite at `/data/hub.db` on a Railway volume, opened with `foreign_keys`, WAL and a busy timeout.
Migrations are numbered and run at start, in one transaction each (`PRAGMA user_version`).

| Table | What |
|---|---|
| `people` | `key` (stable, = `sub` in tokens, never renamed), `name`, `telegram_id` (unique, optional) |
| `groups`, `group_members` | Named groups of people |
| `apps` | Client id, name, `secret_sha256`, which login methods it accepts |
| `app_urls` | Exact redirect URLs and logout return URLs per app |
| `app_access` | Who may open an app: a person or a group (exactly one per row) |
| `settings` | `notify`: the person the bot messages about refused attempts |
| `passkeys`, `challenges` | Credential id, go-webauthn's credential (public key, flags, counter), person, label, added, last used; single-use WebAuthn challenges |
| `enrollments` | Single-use passkey enrollment links (phase 4) |
| `audit` | Every change: when, who, what |

- **Never in the database:** `HUB_SIGNING_KEY` and `SESSION_SECRET`. They stay in Railway
  variables, so a copy of the database can't sign tokens or forge sessions.
- **Seed:** on a database with no people, the hub imports `HUB_SEED` (the same JSON shape as
  `private/access.json`) once, then that variable is deleted. `hub import` does the same into a
  local file. The seed is validated like any change: unknown people or groups, non-https redirect
  URLs or a missing secret hash fail the whole import.
- **Backups:** Railway volume backups, plus `GET /admin/backup` (admin session or
  `HUB_BACKUP_TOKEN`), a consistent snapshot made with `VACUUM INTO`. `scripts/backup.sh` pulls it
  to the Mac. Losing the volume without a backup means re-enrolling every passkey.
- **Fails closed:** a database that can't be opened, a failed migration or a failed
  `quick_check` → nothing served, `/healthz` answers 503, and Railway keeps the previous deploy.

## Identity and login methods

- A **person** has a key, a name, optionally a Telegram id, and zero or more passkeys.
- An **app** accepts `telegram`, `passkey` or both (default `telegram`).
- The **hub session** records **proofs**, one per method (each valid 180 days); who they belong to
  is looked up on every request. Logging in another way adds that proof. Proofs of two different
  people never add up: the newer login wins and the older proof is dropped.
- The **ID token** carries `sub` = person key, `telegram_id` when the person has one, and `amr`
  (`telegram` and/or `passkey`): how they proved it this session.

What `/authorize` does (access is read from the database on every request, never stored in the session):

| Session | App accepts | Result |
|---|---|---|
| none | one method | that method's login screen |
| none | both | a chooser: «Войти через Telegram» / «Войти с passkey» |
| proven with an accepted method | | straight back with a code (silent) |
| proven only with a method the app doesn't accept | | step-up with that app's methods, same person required |
| person not allowed, or an unknown Telegram account | | «нет доступа» page naming the app; the bot messages `notify` (once an hour per person and app) |
| passkey-only app, person has no passkey | | «для этого сайта нужен passkey» |

`prompt=none`: `login_required` when a login or step-up would be needed, `access_denied` when not allowed.

## How a login works

1. Someone opens app A without a session. A redirects to the hub's `/authorize` with its client id,
   redirect URL, state, nonce and a PKCE challenge.
2. The hub logs them in if needed (table above) and sets its own session cookie.
3. Allowed: a redirect back to A's callback with a one-time code and `iss`.
4. A exchanges the code at `/token` (client secret + PKCE verifier) for an ID token signed by the
   hub (EdDSA), `aud` = A.
5. A verifies the token with the hub's public key, maps `sub` to its own user, and sets its own
   session cookie.
6. Opening app B later: B → hub → straight back with a code. It looks like a quick reload.

## The hub

### Endpoints

| Path | What it does |
|---|---|
| `GET /.well-known/openid-configuration` | Discovery: `code` only, `S256` only, `EdDSA`, `client_secret_basic` |
| `GET /jwks.json` | Public Ed25519 key(s); the old key stays listed during a rotation |
| `GET /authorize` | Checks client and redirect URL (exact match) first, then PKCE S256, state, nonce; logs in if needed; checks access; redirects with a code |
| `POST /token` | Client secret + code + redirect URL + PKCE verifier → `id_token` (5 min) and an `access_token` (client libraries require one; nothing accepts it) |
| `GET /login/telegram`, `GET /callback` | The Telegram login (`/callback` is the URL registered in @BotFather) |
| `GET /login`, passkey endpoints | Chooser, passkey login and enrollment (phases 2–4) |
| `GET /logout`, `POST /logout` | «Выйти на всех сайтах?»; the POST is same-origin only (every `*.almaz.dev` app is same-site, so not «same-site») |
| `GET /admin/backup` | Database snapshot, admin only |
| `/admin/…` | The admin UI and its API (last phase) |
| `GET /healthz` | `200 ok`, or `503` when anything is missing or broken |

Rules that matter:
- An unknown `client_id` or a `redirect_uri` that isn't listed exactly shows an error page and
  **never redirects**.
- Codes are random, single use, valid for 60 seconds, bound to client, redirect URL, nonce and
  PKCE challenge, and kept in memory. The hub runs as one instance.

### Railway variables

| Variable | |
|---|---|
| `PUBLIC_URL` | `https://login.almaz.dev` |
| `HUB_SIGNING_KEY`, `HUB_SIGNING_KEY_OLD` | Ed25519 seeds; the old one only during a rotation |
| `SESSION_SECRET` | Hub session cookies |
| `TG_CLIENT_ID`, `TG_CLIENT_SECRET`, `TG_BOT_TOKEN` | The login bot (a new neutral bot) |
| `HUB_ADMIN` | Person key that is always admin, so the UI can't lock you out |
| `HUB_BACKUP_TOKEN` | For `scripts/backup.sh` |
| `HUB_SEED` | Only until the first start |
| `DATA_DIR` | Default `/data` (the volume) |

### Cookies

- `__Host-hub_session`: Secure, HttpOnly, SameSite=Lax, 180 days.
- `__Host-hub_oauth_<state>`: one per Telegram login in progress, 10 minutes.
  `__Host-` everywhere, so sibling `*.almaz.dev` sites can't set or shadow them.

## Passkeys (phase 3)

- `go-webauthn/webauthn`, as in p2pvc. RP ID `login.almaz.dev`, exact origin check.
- Discoverable credentials, user verification required. The person is found by credential id plus
  signature, never by the unsigned user handle (password managers like NordPass alter it).
- Challenges are stored in the database, single use (taking one deletes it) and valid 5 minutes,
  so a captured answer can't be replayed. At most 1000 are live at once.
- One passkey works for every app, because the login always happens at the hub. Passkeys from
  p2pvc or subdrop are bound to their own hosts and can't be reused.
- The sign counter is stored but not enforced: synced passkeys (iCloud, Google) always report 0.
- The passkey pages need one small script (`navigator.credentials`), allowed by its hash in the
  CSP. Every other page stays script-free.

## Enrollment (phase 4)

1. The admin makes a link for a person on `/admin` (later the admin UI). Single use, 24 hours;
   only the token's hash is stored, and the link and the new passkey are spent in one transaction.
2. The person opens it and creates a passkey; it's saved at once. The bot tells the admin.
3. Logged-in people can add another device's passkey themselves (proven with any method that's
   already theirs).

Removing a passkey: for now `/admin`, a server-rendered page listing people and passkeys
(«Ссылка для passkey», «Удалить»); later the admin UI.

## Admin UI (last phase)

- **SvelteKit** (`adapter-static`), built into the Go binary with `embed` and served at `/admin`,
  as in p2pvc. **Go** serves a JSON API at `/admin/api/…`.
- Only for the admin (`HUB_ADMIN`), with a hub session; assets too. Every API call needs a
  same-origin request (Sec-Fetch-Site / Origin) and a JSON body for writes; changes run in one
  transaction, are validated like the seed, and are written to `audit`. The admin can't delete
  themselves or remove their own last way in.
- Screens: people (Telegram id, passkeys, groups, apps they can open, last login), groups, apps
  (URLs, login methods, access; a new or rotated client secret is shown once), enrollment links,
  audit log, backup download.
- Its own strict CSP, sent by the hub: `script-src 'self'` plus the hash of SvelteKit's inline
  bootstrap, `style-src 'self'`, `connect-src 'self'`. No third-party code at runtime.

## Apps

### App sessions and removing someone

- The app cookie stores when the hub last approved the person. A **page load** more than **24 h**
  after that goes back through the hub; it's a silent bounce while the hub session lives.
- Files (JS, photos, videos) keep loading for up to **7 days**, so a tab left open doesn't end up
  with broken images.
- Removing someone at the hub is immediate there; each app notices within its re-check window.

### Logout

The app's logout clears its cookie and redirects to
`/logout?client_id=…&post_logout_redirect_uri=…` (the return URL must be listed for that app).
If the app's logout is a form POST, its CSP needs `form-action 'self' https://login.almaz.dev`:
browsers apply form-action to the redirect after the POST too.

### If the hub is down

People already logged in keep using every app until their app session needs a re-check. Only new
logins and re-checks fail, on the app's «не получилось войти» page.

## Running Club changes (phase 5)

- **Config:** `OIDC_ISSUER`, `OIDC_CLIENT_ID` (`running-club`), `OIDC_CLIENT_SECRET` replace the
  `TG_*` variables; `TG_BOT_TOKEN`, `NOTIFY_MEMBER` and `notify.go` go away.
- **Login code:** endpoints from discovery; EdDSA only; `Endpoint.AuthStyle = AuthStyleInHeader`;
  `sub` is the person key, the same keys as `members.json`; nonce, state and PKCE as today.
- **Session:** the hub-approved time and the 24 h / 7 day rule; old cookies count as expired.
- **Access:** the hub decides; `members.json` stays as a second check.
- **Logout:** redirect to the hub, with the CSP `form-action` above.
- **Tests:** a fake hub (same OIDC shape, EdDSA keys): re-check after 24 h on a page load but not
  on a file; logout goes to the hub; a token for another app is refused.

## Work plan

Each phase is one commit with tests (`go test -race`, `golangci-lint` clean), pushed to
`github.com/almaz-khan/login-hub` (public: no personal data in git). Nothing is deployed without a
go-ahead. Everything that touches real apps, Telegram or Railway comes last.

1. ✅ **Hub skeleton + OIDC provider:** Telegram login, session, pages, notifications, headers,
   discovery, JWKS, `/authorize`, `/token`, codes, logout. Tested with go-oidc as the client.
2. ✅ **SQLite storage + people:** migrations, the schema above (without passkeys), seed import
   (`HUB_SEED`, `hub import`), access read from the database, `sub` = person key and
   `telegram_id`, backups (`/admin/backup`, `HUB_BACKUP_TOKEN`), fail closed on a bad database.
3. ✅ **Login methods per app:** proven methods in the session, the chooser and step-up pages, `amr`.
   Telegram is still the only working method.
4. ✅ **Passkey login:** WebAuthn with a software authenticator in the tests: wrong origin or RP ID,
   no user verification, unknown or removed credential, a passkey-only app refusing a Telegram
   session, step-up refusing a different person.
5. ✅ **Enrollment:** admin links, the enrollment page, adding a device, the bot message, removing a passkey.
6. ✅ **Admin UI:** SvelteKit + Go API as above. Replaces the interim `/admin` page.
7. ✅ **End-to-end in headless Chrome**, against the hub alone: a stub OIDC app, the fake Telegram and
   Chrome's virtual authenticator. Telegram-only, passkey-only and both, step-up, a denied app,
   enrollment by link, logout everywhere, the admin UI's main paths, and no CSP violations.
8. **Integration, last:** the real world.
   1. Running Club as the first client (its own repo, a branch): the changes above, with tests.
   2. Deploy: the volume (the image runs as 65534, Railway mounts volumes as root), variables, the
      bot in @BotFather, `HUB_SEED`, deploy, checks from outside, an external uptime check on
      `/healthz`.
   3. Running Club pointing at the hub, with its old variables kept until a few days of good logins.

## Adding an app

1. `go run ./cmd/hub secret` prints a client secret (hex) and its hash.
2. Add the app (name, exact callback URL, logout return URL, login methods, hash, access): in the
   admin UI, or until then in the seed for a fresh database.
3. On the app: `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`.
4. In the app: a Go app copies Running Club's login code; any other stack uses its OIDC library
   (code flow, PKCE, nonce, `client_secret_basic`, EdDSA); an app you can't change gets
   oauth2-proxy in front of it.

## Security checklist

- Exact redirect URL match per app; errors never redirect.
- PKCE S256 required. State and nonce required; nonce copied into the token; `iss` on the redirect.
- `aud` = client id, so a token for one app is refused by every other.
- 60-second single-use codes, 5-minute ID tokens.
- Client secrets only as hashes in the database; signing key and session secret only in Railway variables.
- Access checked on every `/authorize`, not stored in the session; login methods checked per app.
- Passkeys: user verification required, exact origin and RP ID, sign-in by credential id + signature.
- `__Host-` cookies, HttpOnly, SameSite=Lax; logout and admin changes only same-origin.
- Strict CSP with hashes on every page, `frame-ancestors 'none'`, HSTS.
- Refused attempts logged and messaged (person or Telegram id, name, @username, app).
- Fails closed: missing secrets or a broken database → nothing served, the reason in the log.
- No personal data in git: the seed lives in `private/` (gitignored) and in a temporary variable.

## Open questions

Each has a default I'll use unless you say otherwise.

1. **Bot:** a new neutral bot (for example «Almaz Login»), since its name shows on Telegram's
   login screen for every app.
2. **Removal window:** 24 h for page loads, 7 days for files.
3. **Running Club's own `members.json` check:** keep it.
4. **Other apps and who gets them:** brochat-wrapped (needs a git repo first); p2pvc as an extra
   sign-in next to its own passkeys; subdrop stays as it is.
5. **Requiring two methods for one app (2FA):** not planned; a later `telegram+passkey` method.

## Not in this plan

- Login methods other than Telegram and passkeys.
- Instant removal everywhere (apps asking the hub on every request).
- Refresh tokens or API access tokens for third-party APIs.
