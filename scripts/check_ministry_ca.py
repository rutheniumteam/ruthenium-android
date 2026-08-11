#!/usr/bin/env python3
"""Validate official Ministry CA copies and update the checked-in CA lock."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Any

try:
    from scripts.fetch_ministry_ca import canonical_pem
    from scripts.patch_chromium import (
        CERTIFICATE_PRIMARY_URL,
        CERTIFICATE_SECONDARY_URL,
        canonical_json,
        decode_pem,
        load_certificate_lock,
    )
except ModuleNotFoundError:
    from fetch_ministry_ca import canonical_pem  # type: ignore[no-redef]
    from patch_chromium import (  # type: ignore[no-redef]
        CERTIFICATE_PRIMARY_URL,
        CERTIFICATE_SECONDARY_URL,
        canonical_json,
        decode_pem,
        load_certificate_lock,
    )


MAX_CERTIFICATE_BYTES = 64 * 1024
MAX_SELECTION_BYTES = 64 * 1024
MINIMUM_REMAINING_SECONDS = 365 * 24 * 60 * 60
EXPECTED_SUBJECT = (
    "CN=Russian Trusted Root CA,"
    "O=The Ministry of Digital Development and Communications,C=RU"
)
SHA256_RE = re.compile(r"[0-9a-f]{64}")


class MinistryCaError(RuntimeError):
    """Raised when a candidate root or checked-in CA lock is inconsistent."""


def atomic_write(path: Path, data: bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}."
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, existing_mode if mode is None else mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_certificate(path: Path) -> tuple[bytes, bytes]:
    payload = path.read_bytes()
    if not payload or len(payload) > MAX_CERTIFICATE_BYTES:
        raise MinistryCaError(f"certificate has an invalid size: {path}")
    try:
        der = decode_pem(payload.decode("ascii", "strict"))
    except (UnicodeDecodeError, ValueError) as error:
        raise MinistryCaError(f"certificate is not a single ASCII PEM: {path}") from error
    return der, canonical_pem(der)


def run_openssl(
    openssl: str,
    arguments: list[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    executable = shutil.which(openssl)
    if executable is None:
        raise MinistryCaError(f"OpenSSL executable is unavailable: {openssl}")
    result = subprocess.run(
        [executable, *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise MinistryCaError(f"OpenSSL rejected the certificate: {detail}")
    return result


def validate_x509(path: Path, openssl: str = "openssl") -> str:
    identity = run_openssl(
        openssl,
        [
            "x509",
            "-in",
            str(path),
            "-noout",
            "-subject",
            "-issuer",
            "-nameopt",
            "RFC2253",
        ],
    ).stdout.splitlines()
    if identity != [f"subject={EXPECTED_SUBJECT}", f"issuer={EXPECTED_SUBJECT}"]:
        raise MinistryCaError("candidate has an unexpected subject or issuer")

    verification = run_openssl(
        openssl,
        ["verify", "-check_ss_sig", "-CAfile", str(path), str(path)],
    )
    if not verification.stdout.rstrip().endswith(": OK"):
        raise MinistryCaError("candidate root did not verify its self-signature")

    lifetime = run_openssl(
        openssl,
        [
            "x509",
            "-in",
            str(path),
            "-noout",
            "-checkend",
            str(MINIMUM_REMAINING_SECONDS),
        ],
        check=False,
    )
    if lifetime.returncode != 0:
        raise MinistryCaError("candidate expires in less than one year")

    text = run_openssl(
        openssl, ["x509", "-in", str(path), "-noout", "-text"]
    ).stdout
    if "Version: 3 " not in text:
        raise MinistryCaError("candidate is not an X.509 v3 certificate")
    signature_algorithms = re.findall(r"Signature Algorithm:\s*([^\n]+)", text)
    if not signature_algorithms or any(
        not re.fullmatch(r"sha(?:256|384|512)WithRSAEncryption", value.strip())
        for value in signature_algorithms
    ):
        raise MinistryCaError("candidate uses an unapproved signature algorithm")
    key_bits = re.search(r"Public-Key:\s*\(([0-9]+) bit\)", text)
    if key_bits is None or int(key_bits.group(1)) < 3072:
        raise MinistryCaError("candidate RSA public key is smaller than 3072 bits")
    if not re.search(
        r"X509v3 Basic Constraints:\s*critical\s*\n\s*CA:TRUE(?:,\s*pathlen:[0-9]+)?",
        text,
    ):
        raise MinistryCaError("candidate lacks critical CA basic constraints")
    key_usage = re.search(
        r"X509v3 Key Usage:\s*critical\s*\n\s*([^\n]+)", text
    )
    if key_usage is None:
        raise MinistryCaError("candidate lacks critical key usage")
    usages = {value.strip() for value in key_usage.group(1).split(",")}
    if not {"Certificate Sign", "CRL Sign"}.issubset(usages):
        raise MinistryCaError("candidate cannot sign certificates and CRLs")
    return EXPECTED_SUBJECT


def validate_locked_certificate(
    certificate_path: Path,
    lock_path: Path,
    openssl: str = "openssl",
) -> dict[str, str]:
    lock = load_certificate_lock(lock_path)
    der, _ = read_certificate(certificate_path)
    actual_sha256 = hashlib.sha256(der).hexdigest()
    if actual_sha256 != lock["der_sha256"]:
        raise MinistryCaError("checked-in certificate does not match the CA lock")
    validate_x509(certificate_path, openssl)
    return lock


def select_candidate(
    primary_path: Path,
    secondary_path: Path,
    current_path: Path,
    lock_path: Path,
    openssl: str = "openssl",
) -> tuple[dict[str, Any], bytes]:
    lock = validate_locked_certificate(current_path, lock_path, openssl)
    primary_der, candidate_pem = read_certificate(primary_path)
    secondary_der, _ = read_certificate(secondary_path)
    if primary_der != secondary_der:
        raise MinistryCaError("official certificate copies do not contain the same DER")
    validate_x509(primary_path, openssl)
    current_der, _ = read_certificate(current_path)
    candidate_sha256 = hashlib.sha256(primary_der).hexdigest()
    status = "current" if primary_der == current_der else "update"
    selection = {
        "current_der_sha256": lock["der_sha256"],
        "der_sha256": candidate_sha256,
        "primary_url": CERTIFICATE_PRIMARY_URL,
        "secondary_url": CERTIFICATE_SECONDARY_URL,
        "status": status,
        "subject": EXPECTED_SUBJECT,
    }
    return selection, candidate_pem


def load_selection(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if not data or len(data) > MAX_SELECTION_BYTES:
        raise MinistryCaError("CA selection file has an invalid size")
    try:
        value = json.loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MinistryCaError("CA selection file is invalid") from error
    if not isinstance(value, dict) or canonical_json(value) != data:
        raise MinistryCaError("CA selection file is not canonical JSON")
    expected_fields = {
        "current_der_sha256",
        "der_sha256",
        "primary_url",
        "secondary_url",
        "status",
        "subject",
    }
    if set(value) != expected_fields:
        raise MinistryCaError("CA selection file has unexpected fields")
    if value.get("status") not in {"current", "update"}:
        raise MinistryCaError("CA selection file has an invalid status")
    for key in ("current_der_sha256", "der_sha256"):
        if not isinstance(value.get(key), str) or not SHA256_RE.fullmatch(value[key]):
            raise MinistryCaError(f"CA selection file has an invalid {key}")
    if value.get("primary_url") != CERTIFICATE_PRIMARY_URL:
        raise MinistryCaError("CA selection primary URL changed")
    if value.get("secondary_url") != CERTIFICATE_SECONDARY_URL:
        raise MinistryCaError("CA selection secondary URL changed")
    if value.get("subject") != EXPECTED_SUBJECT:
        raise MinistryCaError("CA selection subject changed")
    return value


def update_repository(
    selection: dict[str, Any],
    candidate_path: Path,
    certificate_path: Path,
    lock_path: Path,
    readme_path: Path,
    openssl: str = "openssl",
) -> None:
    if selection.get("status") != "update":
        raise MinistryCaError("refusing to rewrite the CA lock without a new root")
    lock = validate_locked_certificate(certificate_path, lock_path, openssl)
    if selection.get("current_der_sha256") != lock["der_sha256"]:
        raise MinistryCaError("checked-in CA lock changed during the update")

    candidate_der, candidate_pem = read_certificate(candidate_path)
    candidate_sha256 = hashlib.sha256(candidate_der).hexdigest()
    if candidate_sha256 != selection.get("der_sha256"):
        raise MinistryCaError("candidate certificate changed after selection")
    validate_x509(candidate_path, openssl)

    new_lock = dict(lock)
    new_lock["der_sha256"] = candidate_sha256
    lock_data = canonical_json(new_lock)

    readme = readme_path.read_text(encoding="utf-8")
    old_sha256 = lock["der_sha256"]
    if readme.count(old_sha256) != 1:
        raise MinistryCaError("README CA fingerprint is not unique")
    readme = readme.replace(old_sha256, candidate_sha256)

    atomic_write(certificate_path, candidate_pem)
    atomic_write(lock_path, lock_data)
    atomic_write(readme_path, readme.encode("utf-8"))


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)

    verify = commands.add_parser("verify")
    verify.add_argument("--certificate", type=Path, required=True)
    verify.add_argument("--lock", type=Path, required=True)
    verify.add_argument("--openssl", default="openssl")

    select = commands.add_parser("select")
    select.add_argument("--primary", type=Path, required=True)
    select.add_argument("--secondary", type=Path, required=True)
    select.add_argument("--current", type=Path, required=True)
    select.add_argument("--lock", type=Path, required=True)
    select.add_argument("--candidate", type=Path, required=True)
    select.add_argument("--output", type=Path, required=True)
    select.add_argument("--openssl", default="openssl")

    update = commands.add_parser("update")
    update.add_argument("--selection", type=Path, required=True)
    update.add_argument("--candidate", type=Path, required=True)
    update.add_argument("--certificate", type=Path, required=True)
    update.add_argument("--lock", type=Path, required=True)
    update.add_argument("--readme", type=Path, required=True)
    update.add_argument("--openssl", default="openssl")
    return value


def main() -> int:
    arguments = parser().parse_args()
    if arguments.command == "verify":
        lock = validate_locked_certificate(
            arguments.certificate, arguments.lock, arguments.openssl
        )
        print(json.dumps({"der_sha256": lock["der_sha256"], "status": "verified"}))
        return 0
    if arguments.command == "select":
        selection, candidate = select_candidate(
            arguments.primary,
            arguments.secondary,
            arguments.current,
            arguments.lock,
            arguments.openssl,
        )
        atomic_write(arguments.candidate, candidate, mode=0o600)
        atomic_write(arguments.output, canonical_json(selection), mode=0o600)
        print(json.dumps(selection, sort_keys=True))
        return 0

    selection = load_selection(arguments.selection)
    update_repository(
        selection,
        arguments.candidate,
        arguments.certificate,
        arguments.lock,
        arguments.readme,
        arguments.openssl,
    )
    print(
        json.dumps(
            {"der_sha256": selection["der_sha256"], "status": "updated"},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, MinistryCaError, ValueError) as error:
        raise SystemExit(f"Ministry CA check failed: {error}") from error
