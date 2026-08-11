#!/usr/bin/env python3
"""Derive the identity of a Ruthenium release from the inputs that produce it.

A release is exactly the APK set that a given set of inputs produces: the
Chromium revision, the patch applied to it, the GN arguments, the Ministry root,
the Android application ID and the signing certificate. The release identity is
a digest over those inputs, so equal inputs always name the same release and any
change to them names a different one without a counter to maintain.

Every hashed input is published under `.public-files`, so anyone holding a
public checkout can recompute the identity and confirm that a release tag
belongs to the source it claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


class ReleaseIdentityError(RuntimeError):
    """Raised when the release inputs are missing or malformed."""


PIPELINE_RELATIVE_PATH = Path(".gitlab-ci.yml")
LOCK_RELATIVE_PATH = Path("certificates/ministry-ca-lock.json")
# Hashed whole, because every byte of them reaches the APK.
HASHED_RELATIVE_PATHS = (
    Path("build/args.gn"),
    Path("scripts/patch_chromium.py"),
)
INPUT_RELATIVE_PATHS = (
    PIPELINE_RELATIVE_PATH,
    LOCK_RELATIVE_PATH,
) + HASHED_RELATIVE_PATHS

MAX_INPUT_SIZE = 1024 * 1024

VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){3}")
REVISION_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
APPLICATION_ID_RE = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")
CERTIFICATE_SHA256_RE = re.compile(r"(?:[0-9A-F]{2}:){31}[0-9A-F]{2}")

DIGEST_LENGTH = 12
RELEASE_ID_RE = re.compile(r"android-[0-9]+(?:\.[0-9]+){3}-[0-9a-f]{12}")

PIPELINE_FIELDS: dict[str, tuple[re.Pattern[str], re.Pattern[str]]] = {
    "chromium_version": (
        re.compile(r'^  CHROMIUM_VERSION: "([^"]*)"$', re.MULTILINE),
        VERSION_RE,
    ),
    "chromium_revision": (
        re.compile(r'^  CHROMIUM_REVISION: "([^"]*)"$', re.MULTILINE),
        REVISION_RE,
    ),
    "application_id": (
        re.compile(r'^  RUTHENIUM_APPLICATION_ID: "([^"]*)"$', re.MULTILINE),
        APPLICATION_ID_RE,
    ),
    "signing_certificate_sha256": (
        re.compile(r'^  RUTHENIUM_SIGNING_CERT_SHA256: "([^"]*)"$', re.MULTILINE),
        CERTIFICATE_SHA256_RE,
    ),
}


def _decode(path: Path, data: bytes) -> str:
    if len(data) > MAX_INPUT_SIZE:
        raise ReleaseIdentityError(f"release input is too large: {path.as_posix()}")
    try:
        return data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ReleaseIdentityError(
            f"release input is not UTF-8: {path.as_posix()}"
        ) from error


def release_inputs(sources: dict[Path, bytes]) -> dict[str, str]:
    """Reduce the release input files to the named values that identify a build."""
    missing = [path for path in INPUT_RELATIVE_PATHS if path not in sources]
    if missing:
        raise ReleaseIdentityError(
            f"missing release input: {missing[0].as_posix()}"
        )

    inputs: dict[str, str] = {}
    pipeline = _decode(PIPELINE_RELATIVE_PATH, sources[PIPELINE_RELATIVE_PATH])
    for key, (pattern, value_pattern) in PIPELINE_FIELDS.items():
        matches = pattern.findall(pipeline)
        if len(matches) != 1:
            raise ReleaseIdentityError(f"release input is not unique: {key}")
        if not value_pattern.fullmatch(matches[0]):
            raise ReleaseIdentityError(f"release input is malformed: {key}")
        inputs[key] = matches[0]

    lock_text = _decode(LOCK_RELATIVE_PATH, sources[LOCK_RELATIVE_PATH])
    try:
        lock = json.loads(lock_text)
    except json.JSONDecodeError as error:
        raise ReleaseIdentityError("certificate lock is not valid JSON") from error
    der_sha256 = lock.get("der_sha256") if isinstance(lock, dict) else None
    if not isinstance(der_sha256, str) or not SHA256_RE.fullmatch(der_sha256):
        raise ReleaseIdentityError("release input is malformed: ministry_ca_der_sha256")
    inputs["ministry_ca_der_sha256"] = der_sha256

    for path in HASHED_RELATIVE_PATHS:
        data = sources[path]
        if len(data) > MAX_INPUT_SIZE:
            raise ReleaseIdentityError(
                f"release input is too large: {path.as_posix()}"
            )
        inputs[f"sha256:{path.as_posix()}"] = hashlib.sha256(data).hexdigest()

    return inputs


def release_digest(inputs: dict[str, str]) -> str:
    canonical = json.dumps(
        inputs, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def release_id(inputs: dict[str, str]) -> str:
    version = inputs["chromium_version"]
    value = f"android-{version}-{release_digest(inputs)[:DIGEST_LENGTH]}"
    if not RELEASE_ID_RE.fullmatch(value):
        raise ReleaseIdentityError(f"invalid release identity: {value!r}")
    return value


def read_sources(root: Path) -> dict[Path, bytes]:
    sources: dict[Path, bytes] = {}
    for path in INPUT_RELATIVE_PATHS:
        absolute = root / path
        if not absolute.is_file() or absolute.is_symlink():
            raise ReleaseIdentityError(
                f"missing release input: {path.as_posix()}"
            )
        sources[path] = absolute.read_bytes()
    return sources


def main() -> int:
    parser = argparse.ArgumentParser(description="Print the release identity.")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument(
        "--field",
        choices=("release-id", "digest", "chromium-version"),
        default="release-id",
    )
    arguments = parser.parse_args()
    inputs = release_inputs(read_sources(arguments.root))
    if arguments.field == "digest":
        print(release_digest(inputs))
    elif arguments.field == "chromium-version":
        print(inputs["chromium_version"])
    else:
        print(release_id(inputs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
