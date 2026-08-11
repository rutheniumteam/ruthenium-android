#!/usr/bin/env python3
"""Download and pin-verify the Ministry of Digital Development TLS root."""

from __future__ import annotations

import argparse
import base64
import os
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

try:
    from scripts.patch_chromium import (
        CERTIFICATE_PRIMARY_URL,
        CERTIFICATE_SOURCE_URLS,
        EXPECTED_DER_SHA256,
        decode_and_verify_pem,
    )
except ModuleNotFoundError:
    from patch_chromium import (  # type: ignore[no-redef]
        CERTIFICATE_PRIMARY_URL,
        CERTIFICATE_SOURCE_URLS,
        EXPECTED_DER_SHA256,
        decode_and_verify_pem,
    )


CERTIFICATE_URL = CERTIFICATE_PRIMARY_URL
CERTIFICATE_HOST = "gu-st.ru"
MAX_DOWNLOAD_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 30


def canonical_pem(der: bytes) -> bytes:
    encoded = base64.b64encode(der).decode("ascii")
    lines = [encoded[offset : offset + 64] for offset in range(0, len(encoded), 64)]
    return (
        "-----BEGIN CERTIFICATE-----\n"
        + "\n".join(lines)
        + "\n-----END CERTIFICATE-----\n"
    ).encode("ascii")


def download_certificate(
    url: str = CERTIFICATE_URL,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    opener: Callable[..., object] | None = None,
) -> bytes:
    parsed_url = urllib.parse.urlsplit(url)
    if (
        url not in CERTIFICATE_SOURCE_URLS
        or parsed_url.scheme != "https"
        or parsed_url.hostname != CERTIFICATE_HOST
    ):
        raise ValueError("certificate URL is not an approved official source")

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Ruthenium certificate fetcher/1"},
    )
    if opener is None:
        opener = urllib.request.urlopen
    with opener(request, timeout=timeout) as response:
        final_url = response.geturl()
        if final_url != url:
            raise ValueError("certificate download redirected away from pinned URL")
        payload = response.read(MAX_DOWNLOAD_BYTES + 1)

    if len(payload) > MAX_DOWNLOAD_BYTES:
        raise ValueError("certificate download exceeds size limit")
    try:
        pem = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("certificate download is not ASCII PEM") from error
    return canonical_pem(decode_and_verify_pem(pem))


def write_atomically(output: Path, payload: bytes) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        dir=output.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as temporary_file:
            temporary_file.write(payload)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, output)
    finally:
        temporary_path.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--url", default=CERTIFICATE_URL)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args()

    payload = download_certificate(args.url, args.timeout)
    write_atomically(args.output.resolve(), payload)
    print(f"downloaded {CERTIFICATE_URL}")
    print(f"verified DER SHA-256 {EXPECTED_DER_SHA256}")
    print(f"wrote {args.output.resolve()}")


if __name__ == "__main__":
    main()
