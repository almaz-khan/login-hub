#!/usr/bin/env bash
# Builds the image and runs it with throwaway secrets and a throwaway seed: /healthz, discovery,
# JWKS and the headers must come back as in production, and the image must refuse to serve
# without its secrets.
set -euo pipefail
cd "$(dirname "$0")/.."

image=hub-smoke
port=${SMOKE_PORT:-18080}
docker build -q -t "$image" . >/dev/null

name=hub-smoke-$$
cleanup() { docker rm -f "$name" "$name-bare" >/dev/null 2>&1 || true; }
trap cleanup EXIT

url=http://localhost:$port
seed='{"people":{"Smoke":{"name":"Smoke","telegram":"1"}},"apps":{"smoke":{"name":"Smoke","redirect_uris":["https://smoke.example/cb"],"secret_sha256":"'$(printf x | shasum -a 256 | cut -d' ' -f1)'","allow":["Smoke"]}}}'
docker run -d --rm --name "$name" -p "$port:8080" -e HUB_SEED="$seed" \
	-e PUBLIC_URL="$url" \
	-e TG_CLIENT_ID=1 -e TG_CLIENT_SECRET=x \
	-e SESSION_SECRET="$(openssl rand -hex 32)" \
	-e HUB_SIGNING_KEY="$(openssl rand -base64 32)" \
	"$image" >/dev/null

for _ in $(seq 30); do curl -fsS "$url/healthz" >/dev/null 2>&1 && break; sleep 0.3; done
fail() { echo "smoke: $*" >&2; docker logs "$name" >&2 || true; exit 1; }

[ "$(curl -fsS "$url/healthz")" = ok ] || fail "/healthz is not ok"
curl -fsS "$url/.well-known/openid-configuration" | grep -q "\"issuer\":\"$url\"" || fail "discovery"
curl -fsS "$url/jwks.json" | grep -q '"alg":"EdDSA"' || fail "jwks"
headers=$(curl -fsSI "$url/")
grep -qi "content-security-policy: default-src 'none'" <<<"$headers" || fail "CSP"
grep -qi "x-frame-options: DENY" <<<"$headers" || fail "X-Frame-Options"
code=$(curl -s -o /dev/null -w '%{http_code}' "$url/admin")
[ "$code" = 403 ] || fail "/admin for nobody gave $code"
code=$(curl -s -o /dev/null -w '%{http_code}' "$url/authorize?client_id=evil")
[ "$code" = 400 ] || fail "unknown client gave $code"

# no secrets: nothing served, and /healthz says so (Railway then keeps the previous deploy)
docker run -d --rm --name "$name-bare" -p "$((port + 1)):8080" "$image" >/dev/null
for _ in $(seq 30); do curl -sS "http://localhost:$((port + 1))/healthz" >/dev/null 2>&1 && break; sleep 0.3; done
code=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$((port + 1))/healthz")
[ "$code" = 503 ] || fail "unconfigured /healthz gave $code"

echo "smoke: ok"
