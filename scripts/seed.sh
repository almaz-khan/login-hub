#!/usr/bin/env bash
# Puts private/seed.json into HUB_SEED on Railway, after `hub check`. The hub imports it at its
# next start if (and only if) its database has no people; then delete the variable:
#
#   scripts/seed.sh            check, then set HUB_SEED (no deploy is triggered)
#   scripts/seed.sh --delete   remove HUB_SEED once the log says «seeded» (this redeploys)
set -euo pipefail
cd "$(dirname "$0")/.."
project=3def631d-1da8-42b2-9608-ecb8bb4f4803 # Railway project "login-hub"
service=${RAILWAY_SERVICE:-hub}
environment=${RAILWAY_ENVIRONMENT:-production}
file=${SEED_FILE:-private/seed.json}

if [ "${1:-}" = --delete ]; then
	railway variable delete HUB_SEED --project "$project" --environment "$environment" --service "$service" # redeploys: delete has no --skip-deploys
	exit
fi
go run ./cmd/hub check "$file"
# compact JSON through stdin: the people never appear in a command line or the shell history
node -e 'process.stdout.write(JSON.stringify(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))))' "$file" |
	railway variable set HUB_SEED --stdin --project "$project" --environment "$environment" --service "$service" --skip-deploys >/dev/null
echo "HUB_SEED set; it is imported at the next start into an empty database. Then: $0 --delete"
