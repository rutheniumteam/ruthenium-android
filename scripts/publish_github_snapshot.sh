#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly GITHUB_REMOTE="https://github.com/rutheniumteam/ruthenium-android.git"
readonly PUBLISHER_USER="ruthenium-publisher"
readonly PUBLISHER_HOME="/srv/"ruthenium-publisher

if [ "$#" -ne 4 ]; then
  echo "usage: publish_github_snapshot.sh SNAPSHOT AUTH_CONFIG TOKEN_FILE SHA256" >&2
  exit 2
fi
if [ "${RUTHENIUM_TOR_VERIFIED:-}" != 1 ]; then
  echo "GitHub publication requires scripts/with_tor.sh" >&2
  exit 1
fi
if [ "$(/usr/bin/id -un)" != "$PUBLISHER_USER" ]; then
  echo "GitHub publication requires the fail-closed publisher user" >&2
  exit 1
fi
case "${ALL_PROXY:-}" in
  socks5h://*:*@127.0.0.1:9050) ;;
  *) echo "GitHub publication requires the fixed Tor SOCKS endpoint" >&2; exit 1 ;;
esac

readonly SNAPSHOT="$1"
readonly AUTH_CONFIG="$2"
readonly TOKEN_FILE="$3"
readonly EXPECTED_SHA256="$4"
SCRIPT_DIRECTORY="$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY

[[ "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]]
for secret_file in "$AUTH_CONFIG" "$TOKEN_FILE"; do
  test -f "$secret_file"
  test "$(/usr/bin/stat -c '%a' "$secret_file")" = 600
  test "$(/usr/bin/stat -c '%U' "$secret_file")" = "$PUBLISHER_USER"
done
test -f "$SNAPSHOT"
test "$(/usr/bin/stat -c '%U' "$SNAPSHOT")" = "$PUBLISHER_USER"

/usr/bin/python3 "$SCRIPT_DIRECTORY/public_snapshot.py" verify \
  --archive "$SNAPSHOT" \
  --expected-sha256 "$EXPECTED_SHA256"
"$SCRIPT_DIRECTORY/github_preflight.sh" "$AUTH_CONFIG"

WORK_ROOT="$(/usr/bin/mktemp -d "$PUBLISHER_HOME/.public-snapshot.XXXXXX")"
readonly WORK_ROOT
readonly REPOSITORY="$WORK_ROOT/repository"
readonly ASKPASS="$WORK_ROOT/askpass.sh"
cleanup() {
  /usr/bin/find "$WORK_ROOT" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT
/usr/bin/mkdir -m 0700 "$REPOSITORY"

/usr/bin/tar \
  --extract \
  --file "$SNAPSHOT" \
  --directory "$REPOSITORY" \
  --strip-components=1 \
  --no-same-owner \
  --no-same-permissions

/usr/bin/tee "$ASKPASS" >/dev/null <<'ASKPASS_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  *Username*) printf '%s\n' x-access-token ;;
  *Password*) /usr/bin/cat "$RUTHENIUM_GITHUB_TOKEN_FILE" ;;
  *) exit 1 ;;
esac
ASKPASS_SCRIPT
/usr/bin/chmod 0700 "$ASKPASS"

export GIT_ASKPASS="$ASKPASS"
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_TERMINAL_PROMPT=0
export RUTHENIUM_GITHUB_TOKEN_FILE="$TOKEN_FILE"

/usr/bin/git -C "$REPOSITORY" init --quiet --initial-branch=main
/usr/bin/git -C "$REPOSITORY" remote add origin "$GITHUB_REMOTE"
REMOTE_HEAD=""
REMOTE_TREE=""
if /usr/bin/git -C "$REPOSITORY" ls-remote --exit-code --heads \
  origin refs/heads/main >/dev/null; then
  /usr/bin/git -C "$REPOSITORY" fetch --quiet --depth=1 origin refs/heads/main
  REMOTE_HEAD="$(/usr/bin/git -C "$REPOSITORY" rev-parse FETCH_HEAD)"
  REMOTE_TREE="$(/usr/bin/git -C "$REPOSITORY" rev-parse 'FETCH_HEAD^{tree}')"
else
  REMOTE_STATUS="$?"
  if [ "$REMOTE_STATUS" -ne 2 ]; then
    echo "Failed to inspect the remote main branch" >&2
    exit "$REMOTE_STATUS"
  fi
  echo "Remote main does not exist; bootstrapping it"
fi
readonly REMOTE_HEAD REMOTE_TREE

/usr/bin/git -C "$REPOSITORY" add --all --force -- .
/usr/bin/git -C "$REPOSITORY" diff --cached --check
MANIFEST_COUNT="$(/usr/bin/awk 'NF && $1 !~ /^#/ {count++} END {print count+0}' "$REPOSITORY/.public-files")"
INDEX_COUNT="$(/usr/bin/git -C "$REPOSITORY" ls-files | /usr/bin/wc -l)"
test "$INDEX_COUNT" = "$MANIFEST_COUNT"
PUBLIC_TREE="$(/usr/bin/git -C "$REPOSITORY" write-tree)"
readonly PUBLIC_TREE

if [ -n "$REMOTE_TREE" ] && [ "$PUBLIC_TREE" = "$REMOTE_TREE" ]; then
  PUBLIC_COMMIT="$REMOTE_HEAD"
  readonly PUBLIC_COMMIT
  echo "Public source tree is already current; no commit created"
else
  PUBLISH_DATE="$(/usr/bin/date -u +%Y-%m-%dT00:00:00Z)"
  readonly PUBLISH_DATE
  export GIT_AUTHOR_NAME="Ruthenium Project"
  export GIT_AUTHOR_EMAIL="ruthenium-project@localhost.invalid"
  export GIT_AUTHOR_DATE="$PUBLISH_DATE"
  export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME"
  export GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
  export GIT_COMMITTER_DATE="$PUBLISH_DATE"
  COMMIT_TREE_ARGS=("$PUBLIC_TREE")
  if [ -n "$REMOTE_HEAD" ]; then
    COMMIT_TREE_ARGS+=(-p "$REMOTE_HEAD")
  fi
  PUBLIC_COMMIT="$(
    /usr/bin/printf 'Publish source snapshot\n\nSnapshot-SHA256: %s\n' "$EXPECTED_SHA256" |
      /usr/bin/git -C "$REPOSITORY" commit-tree "${COMMIT_TREE_ARGS[@]}"
  )"
  readonly PUBLIC_COMMIT
  /usr/bin/git -C "$REPOSITORY" push --quiet origin \
    "$PUBLIC_COMMIT:refs/heads/main"
  echo "Published sanitized source commit $PUBLIC_COMMIT"
fi

readonly VERIFICATION_REPOSITORY="$WORK_ROOT/verification"
/usr/bin/mkdir -m 0700 "$VERIFICATION_REPOSITORY"
/usr/bin/git -C "$VERIFICATION_REPOSITORY" init --quiet --initial-branch=main
/usr/local/bin/ruthenium-with-tor \
  /usr/bin/env \
    -u GIT_ASKPASS \
    -u RUTHENIUM_GITHUB_TOKEN_FILE \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_TERMINAL_PROMPT=0 \
    /usr/bin/git -C "$VERIFICATION_REPOSITORY" fetch --quiet --depth=1 \
      "$GITHUB_REMOTE" refs/heads/main
VERIFIED_COMMIT="$(/usr/bin/git -C "$VERIFICATION_REPOSITORY" rev-parse FETCH_HEAD)"
VERIFIED_TREE="$(/usr/bin/git -C "$VERIFICATION_REPOSITORY" rev-parse 'FETCH_HEAD^{tree}')"
test "$VERIFIED_COMMIT" = "$PUBLIC_COMMIT"
test "$VERIFIED_TREE" = "$PUBLIC_TREE"

echo "PUBLICATION_COMMIT=$PUBLIC_COMMIT"
echo "PUBLICATION_TREE=$PUBLIC_TREE"
echo "PUBLICATION_FILES=$INDEX_COUNT"
echo "PUBLICATION_SNAPSHOT_SHA256=$EXPECTED_SHA256"
echo "PUBLICATION_VERIFICATION=PASS"
