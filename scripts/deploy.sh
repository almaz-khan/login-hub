#!/usr/bin/env bash
# Checks and uploads the hub to Railway from this Mac (there is no CI):
#
#   1. refuses unless the checkout is clean (and, once there is a remote, exactly origin/main);
#   2. the admin UI's type check and build, go vet, golangci-lint, go test -race, the browser tests
#      (e2e/) and a smoke test of the image (needs Docker running; the image builds the UI again);
#   3. uploads to the `hub` service; Railway switches over only once /healthz answers 200,
#      so a hub that would serve nothing never replaces a working one.
#
#   scripts/deploy.sh [--skip-checks]
#
#   --skip-checks  skip lint, tests and the smoke test (emergencies only)
#
# People, groups and apps are not deployed: they live in the database on the volume
# (scripts/seed.sh fills a new one).
#
# Railway project and environment are fixed below, so this needs `railway login` but not `railway link`.
set -euo pipefail
cd "$(dirname "$0")/.."

project=3def631d-1da8-42b2-9608-ecb8bb4f4803 # Railway project "login-hub"
environment=${RAILWAY_ENVIRONMENT:-production}
service=${RAILWAY_SERVICE:-hub}

checks=true
for arg; do
	case $arg in
	--skip-checks) checks=false ;;
	*) echo "usage: $0 [--skip-checks]" >&2; exit 2 ;;
	esac
done

if [ -n "$(git status --porcelain)" ]; then
	echo "uncommitted changes: commit first" >&2
	exit 1
fi
if git remote get-url origin >/dev/null 2>&1; then
	git fetch -q origin main
	if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
		echo "HEAD ($(git rev-parse --short HEAD)) is not origin/main ($(git rev-parse --short origin/main)): deploy only what is pushed to main" >&2
		exit 1
	fi
fi
message=${DEPLOY_MESSAGE:-$(git log -1 --format='%h %s')}

if $checks; then
	if ! docker info >/dev/null 2>&1; then
		echo "Docker isn't running: start Docker Desktop for the smoke test (or pass --skip-checks)" >&2
		exit 1
	fi
	(cd admin && npm ci --no-audit --no-fund && npm run check && npm run build)
	go vet ./...
	golangci-lint run ./...
	go test -race -count=1 ./...
	(cd e2e && npm ci --no-audit --no-fund && npx playwright test) # Chromium: npx playwright install chromium, once
	scripts/smoke.sh
fi

railway up --ci --project "$project" --environment "$environment" --service "$service" --message "$message"
