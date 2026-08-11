#!/usr/bin/env python3
"""Create and verify the sanitized, deterministic public source snapshot."""

from __future__ import annotations

import argparse
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET  # nosec B405 -- DTDs are rejected pre-parse.
import zlib


GIT_PATH = Path("/usr/bin/git")
ARCHIVE_PREFIX = "ruthenium-browser"
MANIFEST_PATH = ".public-files"
NORMALIZED_MTIME = 0
MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_TOTAL_SIZE = 50 * 1024 * 1024
ALLOWED_MODES = {"100644": 0o644, "100755": 0o755}
ALLOWED_PUBLIC_PEMS = {
    "certificates/russian_trusted_root_ca.pem",
    "signing/ruthenium-release-cert.pem",
}
ALLOWED_PUBLIC_EMAILS = {"ruthenium-project@localhost.invalid"}
FORBIDDEN_FILE_SUFFIXES = {
    ".env",
    ".jks",
    ".key",
    ".keystore",
    ".mobileprovision",
    ".p12",
    ".pfx",
}
FORBIDDEN_PNG_CHUNKS = {"eXIf", "iCCP", "iTXt", "tEXt", "tIME", "zTXt"}
FORBIDDEN_UNICODE = {
    "\u061c",
    "\u200b",
    "\u200c",
    "\u200d",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2060",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
    "\ufeff",
}
DENIED_IDENTIFIER_SHA256 = {
    "447f0b63cde5970d735f39aea353318ec00e3f9f806838103e41c32ec9e3df86",
}
TOKEN_RE = re.compile(r"github_pat_[A-Za-z0-9_]{30,}")
EMAIL_RE = re.compile(r"(?<![A-Za-z0-9_.+-])[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IPV4_RE = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
ABSOLUTE_HOME_RE = re.compile(r"/(?:Users|home|root|srv)/[A-Za-z0-9._/-]+")
PRIVATE_GITLAB_RE = re.compile(r"https?://gitlab\.[^/\s]+/[^/\s]+/", re.IGNORECASE)
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9_.-]{3,}")
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10." + "0.0.0/8",
        "172." + "16.0.0/12",
        "192." + "168.0.0/16",
    )
)


class SnapshotError(RuntimeError):
    """Raised when the public snapshot boundary is violated."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}."
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def run_git(repository: Path, *arguments: str) -> bytes:
    if not GIT_PATH.is_file():
        raise SnapshotError(f"required Git executable is missing: {GIT_PATH}")
    result = subprocess.run(
        [str(GIT_PATH), "-C", str(repository), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout


def validate_path(path: str) -> None:
    try:
        path.encode("ascii", "strict")
    except UnicodeEncodeError as error:
        raise SnapshotError(f"non-ASCII public path is forbidden: {path!r}") from error
    candidate = PurePosixPath(path)
    if not path or candidate.is_absolute() or str(candidate) != path:
        raise SnapshotError(f"invalid public path: {path!r}")
    if any(part in {"", ".", "..", ".git"} for part in candidate.parts):
        raise SnapshotError(f"unsafe public path: {path!r}")
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        raise SnapshotError(f"control character in public path: {path!r}")
    suffix = candidate.suffix.lower()
    if suffix in FORBIDDEN_FILE_SUFFIXES:
        raise SnapshotError(f"forbidden file type in public snapshot: {path}")
    if suffix == ".pem" and path not in ALLOWED_PUBLIC_PEMS:
        raise SnapshotError(f"unapproved PEM file in public snapshot: {path}")


def parse_manifest(data: bytes) -> list[str]:
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise SnapshotError("public manifest must be UTF-8") from error
    if not text.endswith("\n") or text.endswith("\n\n"):
        raise SnapshotError("public manifest must end with exactly one newline")
    paths: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line or line.startswith("#"):
            continue
        if line != line.strip():
            raise SnapshotError(f"manifest whitespace at line {line_number}")
        validate_path(line)
        paths.append(line)
    if not paths:
        raise SnapshotError("public manifest is empty")
    if paths != sorted(paths):
        raise SnapshotError("public manifest must be bytewise sorted")
    if len(paths) != len(set(paths)):
        raise SnapshotError("public manifest contains duplicate paths")
    if MANIFEST_PATH not in paths:
        raise SnapshotError(f"public manifest must include {MANIFEST_PATH}")
    return paths


def read_git_tree(repository: Path, revision: str) -> dict[str, tuple[str, bytes]]:
    commit = run_git(repository, "rev-parse", "--verify", f"{revision}^{{commit}}")
    if not re.fullmatch(rb"[0-9a-f]{40,64}\n", commit):
        raise SnapshotError("Git resolved an unexpected commit identifier")
    listing = run_git(repository, "ls-tree", "-r", "-z", "--full-tree", revision)
    tree: dict[str, tuple[str, bytes]] = {}
    for record in listing.split(b"\0"):
        if not record:
            continue
        metadata, encoded_path = record.split(b"\t", 1)
        mode_data, object_type, object_id = metadata.split(b" ", 2)
        path = encoded_path.decode("utf-8", "strict")
        validate_path(path)
        mode = mode_data.decode("ascii")
        if object_type != b"blob" or mode not in ALLOWED_MODES:
            raise SnapshotError(f"only regular files are publishable: {path} ({mode})")
        blob = run_git(repository, "cat-file", "blob", object_id.decode("ascii"))
        tree[path] = (mode, blob)
    return tree


def scan_png(path: str, data: bytes) -> None:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise SnapshotError(f"invalid PNG signature: {path}")
    offset = 8
    chunks: list[str] = []
    saw_iend = False
    while offset < len(data):
        if offset + 12 > len(data):
            raise SnapshotError(f"truncated PNG chunk: {path}")
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        chunk_end = offset + 12 + length
        if chunk_end > len(data):
            raise SnapshotError(f"invalid PNG chunk length: {path}")
        payload = data[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", data[offset + 8 + length : chunk_end])[0]
        actual_crc = zlib.crc32(chunk_type)
        actual_crc = zlib.crc32(payload, actual_crc) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise SnapshotError(f"invalid PNG CRC: {path}")
        try:
            name = chunk_type.decode("ascii")
        except UnicodeDecodeError as error:
            raise SnapshotError(f"invalid PNG chunk name: {path}") from error
        chunks.append(name)
        offset = chunk_end
        if name == "IEND":
            saw_iend = True
            break
    if not saw_iend or offset != len(data):
        raise SnapshotError(f"invalid PNG termination: {path}")
    forbidden = FORBIDDEN_PNG_CHUNKS.intersection(chunks)
    if forbidden:
        raise SnapshotError(f"forbidden PNG metadata in {path}: {sorted(forbidden)}")


def scan_svg(path: str, text: str) -> None:
    lowered = text.lower()
    markers = (
        "<script",
        "javascript:",
        "<foreignobject",
        "<!doctype",
        "<!entity",
    )
    if any(marker in lowered for marker in markers):
        raise SnapshotError(f"active content in SVG: {path}")
    if any(marker in lowered for marker in ("creator", "author", "generator")):
        raise SnapshotError(f"identity or generator metadata in SVG: {path}")
    try:
        # Input is size-bounded and any DTD/entity declaration was rejected above.
        root = ET.fromstring(text)  # nosec B314
    except ET.ParseError as error:
        raise SnapshotError(f"invalid SVG XML: {path}") from error
    for element in root.iter():
        local_tag = element.tag.rsplit("}", 1)[-1].lower()
        if local_tag in {"script", "foreignobject"}:
            raise SnapshotError(f"active SVG element in {path}")
        for name, value in element.attrib.items():
            local_name = name.rsplit("}", 1)[-1].lower()
            if local_name == "href" and value.lower().startswith(("http://", "https://")):
                raise SnapshotError(f"external SVG reference in {path}")


def scan_text(path: str, data: bytes) -> None:
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise SnapshotError(f"non-UTF-8 public text file: {path}") from error
    if "\r" in text:
        raise SnapshotError(f"carriage return in public text file: {path}")
    if any(character in text for character in FORBIDDEN_UNICODE):
        raise SnapshotError(f"hidden or bidirectional Unicode in {path}")
    if text and (not text.endswith("\n") or text.endswith("\n\n")):
        raise SnapshotError(f"public text must end with exactly one newline: {path}")
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line.rstrip(" \t") != line:
            raise SnapshotError(f"trailing whitespace in {path}:{line_number}")
    if TOKEN_RE.search(text):
        raise SnapshotError(f"GitHub token-like value in {path}")
    private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"
    if private_key_marker in text:
        raise SnapshotError(f"private key material in {path}")
    for email_match in EMAIL_RE.finditer(text):
        if email_match.group(0) not in ALLOWED_PUBLIC_EMAILS:
            raise SnapshotError(f"email address in public source file: {path}")
    if ABSOLUTE_HOME_RE.search(text):
        raise SnapshotError(f"absolute user or service path in {path}")
    if PRIVATE_GITLAB_RE.search(text):
        raise SnapshotError(f"private GitLab URL in {path}")
    for match in IPV4_RE.finditer(text):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if any(address in network for network in RFC1918_NETWORKS):
            raise SnapshotError(f"private IPv4 address in {path}")
    for identifier in IDENTIFIER_RE.findall(text.lower()):
        digest = hashlib.sha256(identifier.encode("utf-8")).hexdigest()
        if digest in DENIED_IDENTIFIER_SHA256:
            raise SnapshotError(f"denied private identifier in {path}")
    if path.endswith(".svg"):
        scan_svg(path, text)


def scan_blob(path: str, data: bytes) -> None:
    if len(data) > MAX_FILE_SIZE:
        raise SnapshotError(f"public file exceeds size limit: {path}")
    if path.endswith(".png"):
        scan_png(path, data)
        return
    scan_text(path, data)


def validate_entries(entries: dict[str, tuple[str, bytes]]) -> list[str]:
    if MANIFEST_PATH not in entries:
        raise SnapshotError(f"tracked tree is missing {MANIFEST_PATH}")
    manifest = parse_manifest(entries[MANIFEST_PATH][1])
    tracked = sorted(entries)
    if manifest != tracked:
        missing = sorted(set(tracked).difference(manifest))
        stale = sorted(set(manifest).difference(tracked))
        raise SnapshotError(
            f"manifest/tree mismatch; unlisted tracked={missing}, missing tracked={stale}"
        )
    total_size = sum(len(data) for _, data in entries.values())
    if total_size > MAX_TOTAL_SIZE:
        raise SnapshotError("public snapshot exceeds total size limit")
    for path in manifest:
        scan_blob(path, entries[path][1])
    return manifest


def directory_names(paths: list[str]) -> list[str]:
    directories = {ARCHIVE_PREFIX}
    for path in paths:
        parent = PurePosixPath(path).parent
        while str(parent) != ".":
            directories.add(f"{ARCHIVE_PREFIX}/{parent}")
            parent = parent.parent
    return sorted(directories)


def normalized_tar_info(name: str, mode: int, *, directory: bool) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = NORMALIZED_MTIME
    if directory:
        info.type = tarfile.DIRTYPE
        info.size = 0
    return info


def create_archive(
    repository: Path,
    revision: str,
    output_path: Path,
    report_path: Path,
) -> dict[str, object]:
    entries = read_git_tree(repository.resolve(), revision)
    manifest = validate_entries(entries)
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output_path.parent, prefix=f".{output_path.name}."
    )
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    try:
        with tarfile.open(temporary_path, "w", format=tarfile.USTAR_FORMAT) as archive:
            for directory in directory_names(manifest):
                archive.addfile(normalized_tar_info(directory, 0o755, directory=True))
            for path in manifest:
                mode, data = entries[path]
                info = normalized_tar_info(
                    f"{ARCHIVE_PREFIX}/{path}",
                    ALLOWED_MODES[mode],
                    directory=False,
                )
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, output_path)
    finally:
        temporary_path.unlink(missing_ok=True)
    archive_sha256 = sha256_bytes(output_path.read_bytes())
    report: dict[str, object] = {
        "archive_sha256": archive_sha256,
        "file_count": len(manifest),
        "format": 1,
        "normalized_mtime": NORMALIZED_MTIME,
        "prefix": ARCHIVE_PREFIX,
        "files": [
            {
                "mode": entries[path][0],
                "path": path,
                "sha256": sha256_bytes(entries[path][1]),
                "size": len(entries[path][1]),
            }
            for path in manifest
        ],
    }
    atomic_write(
        report_path.resolve(),
        (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return report


def verify_archive(archive_path: Path, expected_sha256: str) -> dict[str, object]:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise SnapshotError("expected archive SHA-256 must be lowercase hexadecimal")
    archive_data = archive_path.read_bytes()
    actual_sha256 = sha256_bytes(archive_data)
    if actual_sha256 != expected_sha256:
        raise SnapshotError(
            f"snapshot SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
        )
    entries: dict[str, tuple[str, bytes]] = {}
    directory_members: list[str] = []
    with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:") as archive:
        for member in archive.getmembers():
            if member.uid != 0 or member.gid != 0 or member.mtime != NORMALIZED_MTIME:
                raise SnapshotError(f"non-normalized tar metadata: {member.name}")
            if member.isdir():
                if member.mode != 0o755:
                    raise SnapshotError(f"non-normalized directory mode: {member.name}")
                directory_members.append(member.name)
                continue
            if not member.isfile() or member.mode not in {0o644, 0o755}:
                raise SnapshotError(f"unsafe tar member: {member.name}")
            prefix = f"{ARCHIVE_PREFIX}/"
            if not member.name.startswith(prefix):
                raise SnapshotError(f"tar member outside prefix: {member.name}")
            relative_path = member.name[len(prefix) :]
            validate_path(relative_path)
            extracted = archive.extractfile(member)
            if extracted is None:
                raise SnapshotError(f"cannot read tar member: {member.name}")
            mode = "100755" if member.mode == 0o755 else "100644"
            entries[relative_path] = (mode, extracted.read())
    manifest = validate_entries(entries)
    expected_directories = directory_names(manifest)
    if directory_members != expected_directories:
        raise SnapshotError("tar directory set or order is not deterministic")
    expected_files = [f"{ARCHIVE_PREFIX}/{path}" for path in manifest]
    with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:") as archive:
        actual_files = [member.name for member in archive if member.isfile()]
    if actual_files != expected_files:
        raise SnapshotError("tar file set or order does not match the manifest")
    return {
        "archive_sha256": actual_sha256,
        "file_count": len(manifest),
        "format": 1,
        "normalized_mtime": NORMALIZED_MTIME,
        "prefix": ARCHIVE_PREFIX,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--repository", type=Path, required=True)
    create.add_argument("--revision", required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--report", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--expected-sha256", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "create":
        report = create_archive(
            args.repository, args.revision, args.output, args.report
        )
    else:
        report = verify_archive(args.archive, args.expected_sha256)
    summary = {
        key: report[key]
        for key in (
            "archive_sha256",
            "file_count",
            "format",
            "normalized_mtime",
            "prefix",
        )
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
