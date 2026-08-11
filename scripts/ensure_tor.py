#!/usr/bin/env python3
"""Configure and verify a Tor obfs4 bridge before GitHub publication."""

from __future__ import annotations

import argparse
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from urllib.parse import urlparse
from urllib.request import Request, urlopen


BRIDGEDB_URL = "https://bridges.torproject.org/bridges/en?transport=obfs4"
BRIDGEDB_HOST = "bridges.torproject.org"
TOR_CHECK_URL = "https://check.torproject.org/api/ip"
DEFAULT_POOL_PATH = Path("/var/lib/tor/ruthenium-obfs4-bridges")
DEFAULT_TORRC_PATH = Path("/etc/tor/torrc")
OBFS4PROXY_PATH = Path("/usr/bin/obfs4proxy")
TOR_PATH = Path("/usr/bin/tor")
CURL_PATH = Path("/usr/bin/curl")
SYSTEMCTL_PATH = Path("/usr/bin/systemctl")

BRIDGE_RE = re.compile(
    r"\bobfs4\s+"
    r"(?P<address>(?:\[[0-9A-Fa-f:]+\]|(?:[0-9]{1,3}\.){3}[0-9]{1,3}):[0-9]{1,5})\s+"
    r"(?P<fingerprint>[A-Fa-f0-9]{40})\s+"
    r"cert=(?P<cert>[A-Za-z0-9+/=]+)\s+"
    r"iat-mode=(?P<iat_mode>[0-2])\b"
)


def validate_address(address: str) -> None:
    if address.startswith("["):
        host, port_text = address[1:].split("]:", 1)
    else:
        host, port_text = address.rsplit(":", 1)
    ipaddress.ip_address(host)
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError(f"invalid bridge port: {port}")


def extract_obfs4_bridges(document: str) -> list[str]:
    decoded = html.unescape(document)
    bridges: list[str] = []
    seen: set[str] = set()
    for match in BRIDGE_RE.finditer(decoded):
        bridge = " ".join(match.group(0).split())
        validate_address(match.group("address"))
        if bridge not in seen:
            seen.add(bridge)
            bridges.append(bridge)
    return bridges


def fetch_obfs4_bridges(timeout: int) -> list[str]:
    request = Request(
        BRIDGEDB_URL,
        headers={"User-Agent": "Ruthenium-Tor-Bootstrap/1"},
    )
    # BRIDGEDB_URL is a constant HTTPS URL and redirects are constrained below.
    with urlopen(request, timeout=timeout) as response:  # nosec B310
        final_url = urlparse(response.geturl())
        if final_url.scheme != "https" or final_url.hostname != BRIDGEDB_HOST:
            raise RuntimeError(f"BridgeDB redirected to untrusted URL: {response.geturl()}")
        document = response.read(1_000_001)
        if len(document) > 1_000_000:
            raise RuntimeError("BridgeDB response is unexpectedly large")
    bridges = extract_obfs4_bridges(document.decode("utf-8", "strict"))
    if not bridges:
        raise RuntimeError(
            "BridgeDB returned no obfs4 lines; an interactive CAPTCHA may be required"
        )
    return bridges


def load_pool(path: Path) -> list[str]:
    if not path.exists():
        return []
    bridges: list[str] = []
    for line in path.read_text(encoding="ascii").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        matches = extract_obfs4_bridges(line)
        if matches != [line]:
            raise RuntimeError(f"invalid obfs4 line in {path}")
        bridges.append(line)
    return bridges


def atomic_write(path: Path, content: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def save_pool(path: Path, bridges: list[str]) -> None:
    atomic_write(path, "".join(f"{bridge}\n" for bridge in bridges), 0o600)


def render_torrc(bridge: str) -> str:
    return (
        "# Managed by scripts/ensure_tor.py.\n"
        "UseBridges 1\n"
        f"ClientTransportPlugin obfs4 exec {OBFS4PROXY_PATH}\n"
        f"Bridge {bridge}\n"
        "SocksPort 127.0.0.1:9050 IsolateSOCKSAuth\n"
    )


def install_bridge(torrc_path: Path, bridge: str) -> None:
    backup_path = torrc_path.with_name(f"{torrc_path.name}.pre-ruthenium")
    if torrc_path.exists() and not backup_path.exists():
        shutil.copy2(torrc_path, backup_path)
        os.chmod(backup_path, 0o600)
    content = render_torrc(bridge)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=torrc_path.parent, prefix=f".{torrc_path.name}.verify."
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as output:
            output.write(content)
        subprocess.run(
            [str(TOR_PATH), "--verify-config", "-f", str(temporary_path)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, torrc_path)
    finally:
        temporary_path.unlink(missing_ok=True)


def tor_is_verified(curl_timeout: int) -> bool:
    isolation = f"ruthenium-{secrets.token_hex(12)}"
    result = subprocess.run(
        [
            str(CURL_PATH),
            "--disable",
            "--fail",
            "--silent",
            "--show-error",
            "--proxy",
            "socks5h://127.0.0.1:9050",
            "--proxy-user",
            f"{isolation}:{secrets.token_hex(12)}",
            "--connect-timeout",
            str(curl_timeout),
            "--max-time",
            str(curl_timeout),
            TOR_CHECK_URL,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if result.returncode != 0:
        return False
    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError:
        return False
    return response.get("IsTor") is True


def wait_for_verified_tor(deadline_seconds: int, curl_timeout: int) -> bool:
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        if tor_is_verified(curl_timeout):
            return True
        time.sleep(3)
    return False


def ensure_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("ensure_tor.py must run as root")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pool", type=Path, default=DEFAULT_POOL_PATH)
    parser.add_argument("--torrc", type=Path, default=DEFAULT_TORRC_PATH)
    parser.add_argument("--fetch-timeout", type=int, default=30)
    parser.add_argument("--bridge-timeout", type=int, default=75)
    parser.add_argument("--curl-timeout", type=int, default=15)
    return parser.parse_args()


def try_bridges(
    candidates: list[str],
    known: list[str],
    args: argparse.Namespace,
) -> bool:
    """Install each candidate in turn until Tor verifies through one.

    The bridge that worked is stored first in the pool so the next run tries
    it before anything else.
    """
    for index, bridge in enumerate(candidates, start=1):
        print(f"Trying obfs4 bridge {index}/{len(candidates)}")
        install_bridge(args.torrc, bridge)
        subprocess.run(
            [str(SYSTEMCTL_PATH), "restart", "tor@default"], check=True
        )
        if wait_for_verified_tor(args.bridge_timeout, args.curl_timeout):
            save_pool(args.pool, [bridge, *(item for item in known if item != bridge)])
            print(f"Tor verified through obfs4 bridge {index}/{len(candidates)}")
            return True
        print(f"Bridge {index}/{len(candidates)} did not bootstrap")
    return False


def bootstrap(args: argparse.Namespace) -> bool:
    """Bring Tor up, preferring the cached pool over a BridgeDB request.

    BridgeDB is contacted only once every cached bridge has failed to
    bootstrap, so a working pool neither depends on BridgeDB being reachable
    nor produces traffic towards it.
    """
    pool = load_pool(args.pool)
    if pool:
        print(f"Trying {len(pool)} cached obfs4 bridge candidates")
        if try_bridges(pool, pool, args):
            return True
        print("No cached obfs4 bridge bootstrapped; requesting new candidates")

    try:
        fetched = fetch_obfs4_bridges(args.fetch_timeout)
    except (OSError, RuntimeError) as error:
        raise SystemExit(f"could not obtain obfs4 bridges from BridgeDB: {error}")
    known = list(dict.fromkeys([*pool, *fetched]))
    save_pool(args.pool, known)
    fresh = [bridge for bridge in known if bridge not in pool]
    print(f"BridgeDB returned {len(fresh)} new obfs4 bridge candidates")
    return bool(fresh) and try_bridges(fresh, known, args)


def main() -> int:
    args = parse_args()
    ensure_root()
    for required_path in (OBFS4PROXY_PATH, TOR_PATH, CURL_PATH, SYSTEMCTL_PATH):
        if not required_path.is_file():
            raise SystemExit(f"missing required executable: {required_path}")

    if bootstrap(args):
        return 0
    raise SystemExit("no obfs4 bridge produced a verified Tor circuit")


if __name__ == "__main__":
    raise SystemExit(main())
