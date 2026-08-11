#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: with_tor.sh COMMAND [ARG ...]" >&2
  exit 2
fi

TOR_SOCKS_HOST="127.0.0.1"
TOR_SOCKS_PORT="9050"
# A freshly built circuit is regularly too slow to answer the probe inside a
# handful of seconds, and every caller pays this probe. One slow circuit used to
# abort a publication that was otherwise fine, so try a few, each on its own
# circuit. The command still runs only on a circuit the probe verified.
TOR_VERIFY_ATTEMPTS=4

for attempt in $(seq 1 "$TOR_VERIFY_ATTEMPTS"); do
  TOR_CIRCUIT_ID="$(/usr/bin/tr -d '-' </proc/sys/kernel/random/uuid)"
  TOR_PROXY="socks5h://${TOR_CIRCUIT_ID}:${TOR_CIRCUIT_ID}@${TOR_SOCKS_HOST}:${TOR_SOCKS_PORT}"

  TOR_CHECK="$({
    /usr/bin/curl --disable --fail --silent --show-error \
      --proxy "$TOR_PROXY" \
      --connect-timeout 30 \
      --max-time 90 \
      https://check.torproject.org/api/ip
  } 2>/dev/null)" || {
    echo "Tor verification request failed on attempt $attempt/$TOR_VERIFY_ATTEMPTS" >&2
    continue
  }

  /usr/bin/python3 -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin).get("IsTor") is True else 1)' \
    <<<"$TOR_CHECK" || {
      echo "Tor Project did not verify circuit $attempt/$TOR_VERIFY_ATTEMPTS" >&2
      continue
    }

  export ALL_PROXY="$TOR_PROXY"
  export HTTPS_PROXY="$TOR_PROXY"
  export HTTP_PROXY="$TOR_PROXY"
  export all_proxy="$TOR_PROXY"
  export https_proxy="$TOR_PROXY"
  export http_proxy="$TOR_PROXY"
  export NO_PROXY=""
  export no_proxy=""
  export RUTHENIUM_TOR_VERIFIED=1
  exec "$@"
done

echo "No Tor circuit verified in $TOR_VERIFY_ATTEMPTS attempts; refusing to execute command" >&2
exit 1
