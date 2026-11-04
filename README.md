# Login hub

One «Войти через Telegram» for every app. The hub is a small OpenID Connect provider at
**https://login.almaz.dev**: apps send people to it, it logs them in with Telegram once (a 180-day
session), checks `config/access.json` for that app on every visit, and sends them back with a code
that the app exchanges for an ID token. The hub never holds app data. The design and its reasons
are in [`plan.md`](plan.md).

- **Railway:** project `login-hub` (`3def631d-1da8-42b2-9608-ecb8bb4f4803`), service `hub`,
  `europe-west4`, 1 replica. Health check `/healthz` (60 s), restart on failure (3 retries),
  `Dockerfile` builder: all set on the service, there is no `railway.json`.
- **DNS:** `login.almaz.dev` CNAME → `aku90nm1.up.railway.app`, plus `_railway-verify.login` TXT,
  in Netlify DNS. The Railway domain `hub-production-6d93.up.railway.app` also answers, but apps
  use `login.almaz.dev`: it is the issuer, baked into every app's config and every token.
- **Image:** `FROM scratch`, ~11 MB: the binary, CA roots and `access.json`.

## Endpoints

| Path | |
| --- | --- |
| `GET /.well-known/openid-configuration` | Discovery: `code` only, `S256` only, `EdDSA`, `client_secret_basic` |
| `GET /jwks.json` | The signing key, plus the old one during a rotation |
| `GET /authorize` | Client and exact redirect URL first (a mismatch shows an error page and never redirects), then PKCE S256, state, nonce, `openid`; logs in if needed; checks access; redirects with a 60-second single-use code and `iss` |
| `POST /token` | Basic auth with the client secret, code, same redirect URL, PKCE verifier → `id_token` (5 min, `aud` = client id, `sub` = Telegram id, `nonce`, `name`, `preferred_username`, `auth_time`) and an `access_token` nothing accepts |
| `GET /login`, `GET /callback` | The Telegram login (`/callback` is the redirect URL registered in @BotFather) |
| `GET /logout` | «Выйти на всех сайтах?»; takes `client_id`, `post_logout_redirect_uri` (must be listed for that app) and `state` |
| `POST /logout` | Same-origin only (not same-site: every `*.almaz.dev` app is same-site); ends the hub session |
| `GET /healthz` | `200 ok`, or `503` when anything is missing or wrong, so Railway never switches to a hub that would serve nothing |

`prompt=none` is supported: without a hub session the app gets `error=login_required` instead of
the Telegram screen; someone not allowed gets `error=access_denied`.

## Настройка

Railway variables on `hub`:

| Variable | |
| --- | --- |
| `PUBLIC_URL` | `https://login.almaz.dev`: the issuer, no trailing slash |
| `HUB_SIGNING_KEY` | Ed25519 seed, base64 (`go run . keygen`). Only here, never in git |
| `HUB_SIGNING_KEY_OLD` | Only during a rotation (below) |
| `SESSION_SECRET` | 32+ characters (`openssl rand -hex 32`). Changing it logs everyone out of the hub |
| `TG_CLIENT_ID`, `TG_CLIENT_SECRET` | The bot's OpenID Connect client, from @BotFather |
| `TG_BOT_TOKEN` | Optional: the bot messages `notify` about refused attempts (press Start in the bot once) |
| `TG_AUDIENCE` | Optional: Telegram's ID token `aud`, if it isn't `TG_CLIENT_ID` |
| `ACCESS_FILE` | Default `/srv/access.json` (baked into the image) |

In @BotFather, the bot's allowed redirect URL is `https://login.almaz.dev/callback`.

### `config/access.json`

```json
{
  "notify": "<Telegram id messaged about refused attempts>",
  "people": { "<Telegram id>": "<name>" },
  "groups": { "club": ["<Telegram id>"] },
  "apps": {
    "<client id>": {
      "name": "Shown on the «нет доступа» page",
      "redirect_uris": ["https://app.almaz.dev/auth/callback"],
      "post_logout_redirect_uris": ["https://app.almaz.dev/"],
      "secret_sha256": "<from go run . secret>",
      "allow": ["group:club", "<Telegram id>"]
    }
  }
}
```

Anything wrong is refused, with every reason listed: unknown keys, an unknown person or group, a
redirect URL that isn't https (http only for `localhost`), a fragment, a missing secret hash.
`go run . check` shows the same errors on the Mac; the Docker build runs it too, so a broken file
never even builds.

## Runbooks

### Deploy

```sh
scripts/deploy.sh   # clean checkout; vet, lint, tests, check, smoke test in Docker; railway up
```

### Add an app

1. `go run . secret` prints a client secret and its hash. The secret is hex, so nothing needs
   escaping anywhere.
2. Add the app to `access.json`: name, exact callback URL(s), logout return URL(s), the hash,
   `allow`. `go run . check`, commit, `scripts/deploy.sh`.
3. On the app: `OIDC_ISSUER=https://login.almaz.dev`, `OIDC_CLIENT_ID=<client id>`,
   `OIDC_CLIENT_SECRET=<secret>`.
4. In the app:
   - a Go app copies Running Club's login code (go-oidc + oauth2). Set
     `Endpoint.AuthStyle = oauth2.AuthStyleInHeader`: auto-detect retries without Basic after
     any error and reports the wrong one;
   - any other stack uses its OIDC library: code flow, PKCE S256, state, nonce, `client_secret_basic`, EdDSA;
   - an app you can't change gets oauth2-proxy in front of it, pointed at the hub.
5. Logout in the app: clear its own cookie, then redirect to
   `https://login.almaz.dev/logout?client_id=<id>&post_logout_redirect_uri=<listed URL>`.
   If the app's logout is a form POST, its CSP needs `form-action 'self' https://login.almaz.dev`:
   browsers apply form-action to the redirect after the POST too.

### Give or take access

Edit `people`, `groups` or an app's `allow`, then `go run . check` and deploy. Access is read on
every `/authorize`, so the change applies from the next deploy. An app re-checks with the hub on
its own schedule (Running Club: a page load more than 24 h after the last approval), so a removed
person loses each app within that window.

Running Club also keeps its own `members.json` as a second check, so a new club member goes into
both files.

### Rotate the signing key

1. `go run . keygen` → new seed.
2. On Railway: `HUB_SIGNING_KEY_OLD` = the current `HUB_SIGNING_KEY`, then `HUB_SIGNING_KEY` = the
   new one. Deploy. JWKS lists both; go-oidc refetches JWKS when it meets the new `kid`.
3. After 10 minutes (ID tokens live 5), delete `HUB_SIGNING_KEY_OLD` and deploy again.

### Rotate a client secret

1. `go run . secret`.
2. Temporarily there's one hash per app, so do it in this order: set the new `OIDC_CLIENT_SECRET`
   on the app with `--skip-deploys`, put the new hash in `access.json`, deploy the hub, then
   redeploy the app. Logins that land in the minute between the two deploys fail once and work
   on retry.

### If the hub is down

People already logged in to an app keep using it until that app wants to re-check. New logins and
re-checks fail on the app's «не получилось войти» page. Railway restarts the hub on failure; a
deploy that doesn't pass `/healthz` never replaces the running one.

## Development

```sh
go test -race ./...     # the whole flow against a fake Telegram, with go-oidc and oauth2 as the apps
golangci-lint run ./...
scripts/smoke.sh        # the image, with throwaway secrets (needs Docker)
```
