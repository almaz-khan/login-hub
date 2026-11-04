# Login hub

One login for every app. The hub is a small OpenID Connect provider at **https://login.almaz.dev**:
apps send people to it, it logs them in (Telegram now, passkeys next), checks in its database
whether that person may open that app, and sends them back with a code that the app exchanges for
an ID token. The hub never holds app data. The design, its reasons and the phases are in
[`plan.md`](plan.md).

**No personal data in this repo.** People, groups, apps and access live in SQLite on the hub's
Railway volume. The seed for a new database is `private/seed.json` (gitignored).

- **Railway:** project `login-hub` (`3def631d-1da8-42b2-9608-ecb8bb4f4803`), service `hub`,
  `europe-west4`, 1 replica. Health check `/healthz` (60 s), restart on failure (3 retries),
  `Dockerfile` builder: all set on the service, there is no `railway.json`.
- **DNS:** `login.almaz.dev` CNAME → `aku90nm1.up.railway.app`, plus `_railway-verify.login` TXT,
  in Netlify DNS. Apps use `login.almaz.dev`: it is the issuer, baked into every app and token.
- **Image:** `FROM scratch`, ~17 MB: the binary (pure-Go SQLite included) and CA roots.

## Endpoints

| Path | |
| --- | --- |
| `GET /.well-known/openid-configuration` | Discovery: `code` only, `S256` only, `EdDSA`, `client_secret_basic` |
| `GET /jwks.json` | The signing key, plus the old one during a rotation |
| `GET /authorize` | Client and exact redirect URL first (a mismatch shows an error page and never redirects), then PKCE S256, state, nonce, `openid`; logs in if needed; checks access in the database; redirects with a 60-second single-use code and `iss` |
| `POST /token` | Basic auth with the client secret, code, same redirect URL, PKCE verifier → `id_token` (5 min) and an `access_token` nothing accepts |
| `GET /login`, `GET /callback` | The Telegram login (`/callback` is the redirect URL registered in @BotFather) |
| `GET /logout` | «Выйти на всех сайтах?»; takes `client_id`, `post_logout_redirect_uri` (listed for that app) and `state` |
| `POST /logout` | Same-origin only (not same-site: every `*.almaz.dev` app is same-site); ends the hub session |
| `GET /admin/backup` | A consistent copy of the database: the admin (`HUB_ADMIN`) logged in, or `Authorization: Bearer $HUB_BACKUP_TOKEN` |
| `GET /healthz` | `200 ok`, or `503` when anything is missing or broken, so Railway never switches to a hub that would serve nothing |

The ID token: `sub` = the person key (stable, never renamed), `aud` = the client id, `nonce`,
`name`, `auth_time`, `telegram_id` when the person has one, `preferred_username` for a Telegram login.

`prompt=none` is supported: `error=login_required` without a hub session, `error=access_denied`
for someone not allowed.

## Настройка

Railway variables on `hub`:

| Variable | |
| --- | --- |
| `PUBLIC_URL` | `https://login.almaz.dev`: the issuer, no trailing slash |
| `HUB_SIGNING_KEY` | Ed25519 seed, base64 (`go run . keygen`). Only here, never in the database or git |
| `HUB_SIGNING_KEY_OLD` | Only during a rotation (below) |
| `SESSION_SECRET` | 32+ characters (`openssl rand -hex 32`). Changing it logs everyone out of the hub |
| `TG_CLIENT_ID`, `TG_CLIENT_SECRET` | The bot's OpenID Connect client, from @BotFather |
| `TG_BOT_TOKEN` | Optional: the bot messages the `notify` person about refused attempts (they press Start in the bot once) |
| `TG_AUDIENCE` | Optional: Telegram's ID token `aud`, if it isn't `TG_CLIENT_ID` |
| `HUB_ADMIN` | The person key that is admin (backups now, the admin UI later) |
| `HUB_BACKUP_TOKEN` | 32+ characters, for `scripts/backup.sh` |
| `HUB_SEED` | Only until the first start on a new database (`scripts/seed.sh`) |
| `DATA_DIR` | `/data`: the volume, holding `hub.db` |

In @BotFather, the bot's allowed redirect URL is `https://login.almaz.dev/callback`.

### The database

SQLite (`modernc.org/sqlite`, no CGO) at `$DATA_DIR/hub.db`, with foreign keys and WAL. Numbered
migrations run at start (`PRAGMA user_version`); a database from a newer hub, a failed migration
or a failed `quick_check` serves nothing. So does a database without apps.

| Table | |
| --- | --- |
| `people` | `key` (= `sub`), `name`, `telegram_id` (unique, optional), `last_seen_at` |
| `groups`, `group_members` | Groups of people; deleting a person or renaming a group cascades |
| `apps`, `app_urls` | Client id, name, `secret_sha256`, login methods; exact redirect and logout URLs |
| `app_access` | A person or a group per row, never both |
| `settings` | `notify`: the person the bot messages |
| `audit` | When, who, what changed |

### The seed

```json
{
  "notify": "<person key>",
  "people": { "<person key>": { "name": "…", "telegram": "<Telegram id>" } },
  "groups": { "club": ["<person key>"] },
  "apps": {
    "<client id>": {
      "name": "Shown on the «нет доступа» page",
      "redirect_uris": ["https://app.almaz.dev/auth/callback"],
      "post_logout_redirect_uris": ["https://app.almaz.dev/"],
      "login": ["telegram"],
      "secret_sha256": "<from go run . secret>",
      "allow": ["group:club", "<person key>"]
    }
  }
}
```

`go run . check` checks `private/seed.json` the way the hub does. Unknown keys, an unknown person
or group, a redirect URL that isn't https (http only for `localhost`), a duplicate Telegram id or a
missing secret hash refuse the whole seed, with every reason listed. Person keys are what apps see
as `sub`: never rename one.

## Runbooks

### Deploy

```sh
scripts/deploy.sh   # clean checkout; vet, lint, tests, smoke test in Docker; railway up
```

### A new database

```sh
scripts/seed.sh            # hub check, then HUB_SEED on Railway (no deploy triggered)
# deploy or restart; the log says «seeded: N people, M apps»
scripts/seed.sh --delete
```

Locally: `go run . import -db data/hub.db private/seed.json`, then run with `DATA_DIR=data`.

### Backups

```sh
scripts/backup.sh          # ~/Backups/login-hub/hub-<time>.db, newest 30 kept
```

Also turn on Railway's volume backups. Restoring: stop the service, put the file at
`/data/hub.db` on the volume, start it. Without a backup, a lost volume means re-seeding and
re-enrolling every passkey.

### Add an app

1. `go run . secret` prints a client secret and its hash. The secret is hex, so nothing needs
   escaping anywhere.
2. Add the app (name, exact callback URL(s), logout return URL(s), login methods, the hash,
   access) in the database: the admin UI once it exists; until then the seed for a new database,
   or SQL on a backup copy.
3. On the app: `OIDC_ISSUER=https://login.almaz.dev`, `OIDC_CLIENT_ID=<client id>`,
   `OIDC_CLIENT_SECRET=<secret>`.
4. In the app:
   - a Go app copies Running Club's login code (go-oidc + oauth2), with
     `Endpoint.AuthStyle = oauth2.AuthStyleInHeader`: auto-detect retries without Basic after
     any error and reports the wrong one;
   - any other stack uses its OIDC library: code flow, PKCE S256, state, nonce, `client_secret_basic`, EdDSA;
   - an app you can't change gets oauth2-proxy in front of it.
5. Logout in the app: clear its own cookie, then redirect to
   `https://login.almaz.dev/logout?client_id=<id>&post_logout_redirect_uri=<listed URL>`.
   If that's a form POST, the app's CSP needs `form-action 'self' https://login.almaz.dev`.

### Give or take access

A change in the database applies at the hub's next `/authorize`, no deploy. Each app re-checks on
its own schedule (Running Club: a page load more than 24 h after the last approval). Running Club
also keeps its own `members.json` as a second check.

### Rotate the signing key

1. `go run . keygen` → new seed.
2. On Railway: `HUB_SIGNING_KEY_OLD` = the current `HUB_SIGNING_KEY`, then `HUB_SIGNING_KEY` = the
   new one. Deploy. JWKS lists both; go-oidc refetches JWKS when it meets the new `kid`.
3. After 10 minutes (ID tokens live 5), delete `HUB_SIGNING_KEY_OLD` and deploy again.

### Rotate a client secret

`go run . secret`; set the new `OIDC_CLIENT_SECRET` on the app with `--skip-deploys`, change the
app's hash in the hub, then redeploy the app. Logins in the minute between fail once and work on retry.

### If the hub is down

People already logged in to an app keep using it until that app wants to re-check. New logins and
re-checks fail on the app's «не получилось войти» page.

## Development

```sh
go test -race ./...     # the whole flow against a fake Telegram, with go-oidc and oauth2 as the apps
golangci-lint run ./...
scripts/smoke.sh        # the image, with throwaway secrets and seed (needs Docker)
```
