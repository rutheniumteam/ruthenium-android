#!/usr/bin/env bash
set -euo pipefail
umask 077

if [ "$#" -ne 1 ]; then
  echo "usage: github_preflight.sh AUTH_CONFIG" >&2
  exit 2
fi
if [ "${RUTHENIUM_TOR_VERIFIED:-}" != 1 ]; then
  echo "GitHub preflight requires scripts/with_tor.sh" >&2
  exit 1
fi
if [ "$(/usr/bin/id -un)" != "ruthenium-publisher" ]; then
  echo "GitHub preflight requires the fail-closed publisher user" >&2
  exit 1
fi
case "${ALL_PROXY:-}" in
  socks5h://*) ;;
  *) echo "GitHub preflight requires a socks5h proxy" >&2; exit 1 ;;
esac

AUTH_CONFIG="$1"
test -f "$AUTH_CONFIG"
test "$(/usr/bin/stat -c '%a' "$AUTH_CONFIG")" = 600

USER_RESPONSE="$(/usr/bin/mktemp)"
REPOSITORY_RESPONSE="$(/usr/bin/mktemp)"
trap '/usr/bin/rm -f -- "$USER_RESPONSE" "$REPOSITORY_RESPONSE"' EXIT

/usr/bin/curl --disable --fail --silent --show-error \
  --config "$AUTH_CONFIG" \
  --header 'Accept: application/vnd.github+json' \
  --header 'X-GitHub-Api-Version: 2026-03-10' \
  https://api.github.com/user > "$USER_RESPONSE"

/usr/bin/curl --disable --fail --silent --show-error \
  --config "$AUTH_CONFIG" \
  --header 'Accept: application/vnd.github+json' \
  --header 'X-GitHub-Api-Version: 2026-03-10' \
  https://api.github.com/repos/rutheniumteam/ruthenium-android \
  > "$REPOSITORY_RESPONSE"

/usr/bin/python3 - "$USER_RESPONSE" "$REPOSITORY_RESPONSE" <<'PY'
import json
from pathlib import Path
import sys

user = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
repository = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
if repository.get("full_name") != "rutheniumteam/ruthenium-android":
    raise SystemExit("GitHub token resolved an unexpected repository")
if repository.get("private") is not False:
    raise SystemExit("GitHub destination must remain public")
permissions = repository.get("permissions", {})
if permissions.get("push") is not True:
    raise SystemExit("GitHub token lacks Contents: write permission")
print(f"GitHub actor: {user.get('login', '<unknown>')}")
print("GitHub repository: rutheniumteam/ruthenium-android")
print("GitHub Contents permission: write")
print("GitHub preflight: passed through verified Tor")
PY
