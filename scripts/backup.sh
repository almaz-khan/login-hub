#!/usr/bin/env bash
# Pulls a consistent copy of the hub's database to this Mac (GET /admin/backup with
# HUB_BACKUP_TOKEN, read from Railway) and keeps the newest 30.
#
#   scripts/backup.sh [dir]     default ~/Backups/login-hub
set -euo pipefail
cd "$(dirname "$0")/.."
project=3def631d-1da8-42b2-9608-ecb8bb4f4803 # Railway project "login-hub"
dir=${1:-$HOME/Backups/login-hub}
url=${HUB_URL:-https://login.almaz.dev}

token=$(railway variable list --project "$project" --service hub --kv | sed -n 's/^HUB_BACKUP_TOKEN=//p')
[ -n "$token" ] || { echo "HUB_BACKUP_TOKEN is not set on the hub" >&2; exit 1; }
mkdir -p "$dir"
chmod 700 "$dir"
out="$dir/hub-$(date -u +%Y%m%dT%H%M%SZ).db"
curl -fsS --proto =https -H @- -o "$out.part" "$url/admin/backup" <<<"Authorization: Bearer $token"
mv "$out.part" "$out"
chmod 600 "$out"
ls -1t "$dir"/hub-*.db | tail -n +31 | while read -r old; do rm -- "$old"; done
echo "backup: $out ($(du -h "$out" | cut -f1))"
