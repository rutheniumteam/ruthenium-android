#!/usr/bin/env python3
"""Validate Android build artifacts and prepare a public release bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

try:
    from . import release_identity
except ImportError:
    import release_identity  # type: ignore[no-redef]


SCHEMA_VERSION = 1
PRODUCT = "Ruthenium"
MINISTRY_CA_SOURCE = (
    "https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt"
)
ABI_TARGETS = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "x86_64": "x64",
}
CONTENT_TYPES = {
    ".apk": "application/vnd.android.package-archive",
    ".json": "application/json",
    ".pem": "application/x-pem-file",
    ".sha256": "text/plain; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
}
OPENSSL_PATH = Path("/usr/bin/openssl")
MAX_APK_SIZE = 2 * 1024 * 1024 * 1024
MAX_TEXT_SIZE = 5 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}")
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){3}")
APPLICATION_ID_RE = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")


class ReleaseBundleError(RuntimeError):
    """Raised when an artifact cannot cross the public release boundary."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_regular_file(path: Path, maximum_size: int) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ReleaseBundleError(f"required artifact is missing: {path.name}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ReleaseBundleError(f"artifact must be a regular file: {path.name}")
    if metadata.st_size <= 0 or metadata.st_size > maximum_size:
        raise ReleaseBundleError(
            f"artifact has an invalid size: {path.name} ({metadata.st_size})"
        )


def read_text(path: Path) -> str:
    require_regular_file(path, MAX_TEXT_SIZE)
    try:
        value = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise ReleaseBundleError(f"artifact is not UTF-8 text: {path.name}") from error
    if not value.endswith("\n") or "\x00" in value:
        raise ReleaseBundleError(f"artifact has invalid text framing: {path.name}")
    return value


def normalize_certificate_fingerprint(value: str) -> str:
    normalized = value.replace(":", "").lower()
    if not SHA256_RE.fullmatch(normalized):
        raise ReleaseBundleError("invalid signing certificate SHA-256")
    return normalized


def display_certificate_fingerprint(value: str) -> str:
    normalized = normalize_certificate_fingerprint(value)
    return ":".join(
        normalized[index : index + 2].upper() for index in range(0, 64, 2)
    )


def certificate_fingerprint(path: Path) -> str:
    require_regular_file(path, MAX_TEXT_SIZE)
    if not OPENSSL_PATH.is_file():
        raise ReleaseBundleError(f"required executable is missing: {OPENSSL_PATH}")
    result = subprocess.run(
        [str(OPENSSL_PATH), "x509", "-in", str(path), "-outform", "DER"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return hashlib.sha256(result.stdout).hexdigest()


def validate_apk(path: Path, expected_abi: str) -> None:
    require_regular_file(path, MAX_APK_SIZE)
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if not names or len(names) != len(set(names)):
                raise ReleaseBundleError("APK is empty or contains duplicate entries")
            architectures: set[str] = set()
            for name in names:
                if "\x00" in name:
                    raise ReleaseBundleError("APK contains a NUL in an entry name")
                candidate = PurePosixPath(name)
                if candidate.is_absolute() or ".." in candidate.parts:
                    raise ReleaseBundleError(f"APK contains an unsafe entry: {name!r}")
                if len(candidate.parts) >= 3 and candidate.parts[0] == "lib":
                    architectures.add(candidate.parts[1])
            if architectures != {expected_abi}:
                raise ReleaseBundleError(
                    f"APK ABI mismatch: expected {expected_abi}, found {sorted(architectures)}"
                )
            corrupt_entry = archive.testzip()
            if corrupt_entry is not None:
                raise ReleaseBundleError(f"APK CRC check failed: {corrupt_entry}")
    except zipfile.BadZipFile as error:
        raise ReleaseBundleError("APK is not a valid ZIP archive") from error


def expected_build_info(
    *,
    version: str,
    revision: str,
    release_id: str,
    abi: str,
    target_cpu: str,
    application_id: str,
    ministry_ca_der_sha256: str,
    signing_fingerprint: str,
) -> str:
    return (
        f"Product {PRODUCT}\n"
        f"Application ID {application_id}\n"
        f"Chromium {version}\n"
        f"Revision {revision}\n"
        f"Ruthenium release {release_id}\n"
        f"Architecture {abi}\n"
        f"Chromium target CPU {target_cpu}\n"
        "Scoped CA DNS names .ru,.xn--p1ai\n"
        f"Ministry CA source {MINISTRY_CA_SOURCE}\n"
        f"Ministry CA DER SHA-256 {ministry_ca_der_sha256}\n"
        "Signing certificate SHA-256 "
        f"{display_certificate_fingerprint(signing_fingerprint)}\n"
    )


def copy_regular(source: Path, destination: Path) -> None:
    require_regular_file(
        source, MAX_APK_SIZE if source.suffix == ".apk" else MAX_TEXT_SIZE
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent, prefix=f".{destination.name}."
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output, 1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, destination)
    finally:
        temporary_path.unlink(missing_ok=True)


def write_json(path: Path, value: object) -> None:
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}."
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def create_bundle(
    *,
    artifacts: Path,
    output: Path,
    version: str,
    revision: str,
    release_id: str,
    abi: str,
    target_cpu: str,
    application_id: str,
    ministry_ca_der_sha256: str,
    signing_fingerprint: str,
    source_snapshot_sha256: str,
) -> dict[str, object]:
    if not VERSION_RE.fullmatch(version):
        raise ReleaseBundleError("invalid Chromium version")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ReleaseBundleError("invalid Chromium revision")
    if not release_identity.RELEASE_ID_RE.fullmatch(release_id):
        raise ReleaseBundleError("invalid release identity")
    if not release_id.startswith(f"android-{version}-"):
        raise ReleaseBundleError("release identity does not name this Chromium version")
    if ABI_TARGETS.get(abi) != target_cpu:
        raise ReleaseBundleError("Android ABI and Chromium target CPU do not match")
    if not APPLICATION_ID_RE.fullmatch(application_id):
        raise ReleaseBundleError("invalid Android application ID")
    if not SHA256_RE.fullmatch(ministry_ca_der_sha256):
        raise ReleaseBundleError("invalid Ministry CA DER SHA-256")
    signing_sha256 = normalize_certificate_fingerprint(signing_fingerprint)
    if not SHA256_RE.fullmatch(source_snapshot_sha256):
        raise ReleaseBundleError("invalid public source snapshot SHA-256")

    source_names = {
        "Chromium-LICENSE.txt",
        f"Ruthenium-{version}-{abi}.apk",
        f"Ruthenium-{version}-{abi}.apk.sha256",
        "aapt2-badging.txt",
        "apk-abis.txt",
        "apksigner-verification.txt",
        "build-info.txt",
        "ruthenium-release-cert.pem",
    }
    actual_names = {
        path.name
        for path in artifacts.iterdir()
        if path.name not in {".", ".."}
    }
    if actual_names != source_names:
        missing = sorted(source_names - actual_names)
        unexpected = sorted(actual_names - source_names)
        raise ReleaseBundleError(
            f"artifact set mismatch; missing={missing}, unexpected={unexpected}"
        )

    apk_name = f"Ruthenium-{version}-{abi}.apk"
    apk_path = artifacts / apk_name
    apk_sha256 = sha256_file(apk_path)
    checksum_text = read_text(artifacts / f"{apk_name}.sha256")
    if checksum_text != f"{apk_sha256}  {apk_name}\n":
        raise ReleaseBundleError("APK checksum file does not match the APK")
    validate_apk(apk_path, abi)

    if read_text(artifacts / "apk-abis.txt") != f"{abi}\n":
        raise ReleaseBundleError("recorded APK ABI does not match the release ABI")
    badging = read_text(artifacts / "aapt2-badging.txt")
    if f"package: name='{application_id}'" not in badging:
        raise ReleaseBundleError("aapt2 output does not contain the application ID")
    if "application-label:'Ruthenium'" not in badging:
        raise ReleaseBundleError("aapt2 output does not contain the application label")
    signer_output = read_text(artifacts / "apksigner-verification.txt")
    if signing_sha256 not in signer_output.replace(":", "").lower():
        raise ReleaseBundleError("apksigner output does not contain the signing key")
    certificate_path = artifacts / "ruthenium-release-cert.pem"
    if certificate_fingerprint(certificate_path) != signing_sha256:
        raise ReleaseBundleError("published certificate does not match the signing key")

    build_info = expected_build_info(
        version=version,
        revision=revision,
        release_id=release_id,
        abi=abi,
        target_cpu=target_cpu,
        application_id=application_id,
        ministry_ca_der_sha256=ministry_ca_der_sha256,
        signing_fingerprint=signing_fingerprint,
    )
    if read_text(artifacts / "build-info.txt") != build_info:
        raise ReleaseBundleError("build-info.txt does not exactly describe this build")

    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    public_build_info = f"Ruthenium-{version}-{abi}-build-info.txt"
    public_aapt2 = f"Ruthenium-{version}-{abi}-aapt2-badging.txt"
    public_abis = f"Ruthenium-{version}-{abi}-apk-abis.txt"
    public_apksigner = f"Ruthenium-{version}-{abi}-apksigner-verification.txt"
    sources = {
        apk_name: apk_path,
        f"{apk_name}.sha256": artifacts / f"{apk_name}.sha256",
        public_aapt2: artifacts / "aapt2-badging.txt",
        public_abis: artifacts / "apk-abis.txt",
        public_apksigner: artifacts / "apksigner-verification.txt",
        public_build_info: artifacts / "build-info.txt",
        "Chromium-LICENSE.txt": artifacts / "Chromium-LICENSE.txt",
        "ruthenium-release-cert.pem": certificate_path,
    }
    assets: list[dict[str, object]] = []
    for name, source in sorted(sources.items()):
        destination = output / name
        copy_regular(source, destination)
        suffix = ".sha256" if name.endswith(".sha256") else destination.suffix
        assets.append(
            {
                "content_type": CONTENT_TYPES[suffix],
                "name": name,
                "sha256": sha256_file(destination),
                "size": destination.stat().st_size,
            }
        )

    bundle = {
        "abi": abi,
        "application_id": application_id,
        "assets": assets,
        "chromium_revision": revision,
        "chromium_target_cpu": target_cpu,
        "chromium_version": version,
        "ministry_ca_der_sha256": ministry_ca_der_sha256,
        "product": PRODUCT,
        "release_tag": release_id,
        "schema_version": SCHEMA_VERSION,
        "signing_certificate_sha256": signing_sha256,
        "source_snapshot_sha256": source_snapshot_sha256,
    }
    write_json(output / "bundle.json", bundle)
    verify_bundle(output)
    return bundle


def verify_bundle(bundle_directory: Path) -> dict[str, object]:
    manifest_path = bundle_directory / "bundle.json"
    manifest_text = read_text(manifest_path)
    try:
        manifest = json.loads(manifest_text)
    except json.JSONDecodeError as error:
        raise ReleaseBundleError("bundle.json is not valid JSON") from error
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION:
        raise ReleaseBundleError("unsupported release bundle schema")
    if set(manifest) != {
        "abi",
        "application_id",
        "assets",
        "chromium_revision",
        "chromium_target_cpu",
        "chromium_version",
        "ministry_ca_der_sha256",
        "product",
        "release_tag",
        "schema_version",
        "signing_certificate_sha256",
        "source_snapshot_sha256",
    }:
        raise ReleaseBundleError("bundle.json contains unexpected fields")
    canonical = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if manifest_text != canonical:
        raise ReleaseBundleError("bundle.json is not canonical JSON")

    scalar_patterns = {
        "abi": r"(?:arm64-v8a|armeabi-v7a|x86_64)",
        "application_id": APPLICATION_ID_RE.pattern,
        "chromium_revision": r"[0-9a-f]{40}",
        "chromium_target_cpu": r"(?:arm64|arm|x64)",
        "chromium_version": VERSION_RE.pattern,
        "ministry_ca_der_sha256": r"[0-9a-f]{64}",
        "product": re.escape(PRODUCT),
        "release_tag": release_identity.RELEASE_ID_RE.pattern,
        "signing_certificate_sha256": r"[0-9a-f]{64}",
        "source_snapshot_sha256": r"[0-9a-f]{64}",
    }
    for key, pattern in scalar_patterns.items():
        value = manifest.get(key)
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ReleaseBundleError(f"invalid bundle field: {key}")
    if not str(manifest["release_tag"]).startswith(
        f"android-{manifest['chromium_version']}-"
    ):
        raise ReleaseBundleError("release tag does not name the bundled Chromium version")
    if ABI_TARGETS.get(str(manifest["abi"])) != manifest["chromium_target_cpu"]:
        raise ReleaseBundleError("bundle ABI and target CPU do not match")

    assets = manifest.get("assets")
    if not isinstance(assets, list) or not assets:
        raise ReleaseBundleError("release bundle contains no assets")
    version = str(manifest["chromium_version"])
    abi = str(manifest["abi"])
    apk_name = f"Ruthenium-{version}-{abi}.apk"
    expected_asset_names = {
        "Chromium-LICENSE.txt",
        apk_name,
        f"{apk_name}.sha256",
        f"Ruthenium-{version}-{abi}-aapt2-badging.txt",
        f"Ruthenium-{version}-{abi}-apk-abis.txt",
        f"Ruthenium-{version}-{abi}-apksigner-verification.txt",
        f"Ruthenium-{version}-{abi}-build-info.txt",
        "ruthenium-release-cert.pem",
    }
    expected_names = {"bundle.json"}
    seen_names: set[str] = set()
    for asset in assets:
        if not isinstance(asset, dict) or set(asset) != {
            "content_type",
            "name",
            "sha256",
            "size",
        }:
            raise ReleaseBundleError("invalid release asset record")
        name = asset["name"]
        if (
            not isinstance(name, str)
            or not name
            or PurePosixPath(name).name != name
            or not name.isascii()
            or name in seen_names
        ):
            raise ReleaseBundleError("invalid or duplicate release asset name")
        content_type = asset["content_type"]
        suffix = ".sha256" if name.endswith(".sha256") else PurePosixPath(name).suffix
        if CONTENT_TYPES.get(suffix) != content_type:
            raise ReleaseBundleError(f"invalid content type for release asset: {name}")
        expected_sha256 = asset["sha256"]
        expected_size = asset["size"]
        if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(
            expected_sha256
        ):
            raise ReleaseBundleError(f"invalid release asset SHA-256: {name}")
        if not isinstance(expected_size, int) or expected_size <= 0:
            raise ReleaseBundleError(f"invalid release asset size: {name}")
        path = bundle_directory / name
        maximum = MAX_APK_SIZE if name.endswith(".apk") else MAX_TEXT_SIZE
        require_regular_file(path, maximum)
        if path.stat().st_size != expected_size or sha256_file(path) != expected_sha256:
            raise ReleaseBundleError(f"release asset does not match manifest: {name}")
        seen_names.add(name)
        expected_names.add(name)

    if seen_names != expected_asset_names:
        raise ReleaseBundleError("release bundle has an unexpected public asset set")
    if [asset["name"] for asset in assets] != sorted(expected_asset_names):
        raise ReleaseBundleError("release assets are not in canonical order")

    actual_names = {path.name for path in bundle_directory.iterdir()}
    if actual_names != expected_names:
        raise ReleaseBundleError("release bundle contains unmanifested files")

    apk_path = bundle_directory / apk_name
    apk_sha256 = sha256_file(apk_path)
    checksum = read_text(bundle_directory / f"{apk_name}.sha256")
    if checksum != f"{apk_sha256}  {apk_name}\n":
        raise ReleaseBundleError("bundled APK checksum does not match the APK")
    validate_apk(apk_path, abi)
    abi_record = bundle_directory / f"Ruthenium-{version}-{abi}-apk-abis.txt"
    if read_text(abi_record) != f"{abi}\n":
        raise ReleaseBundleError("bundled ABI evidence does not match the APK")
    badging = read_text(
        bundle_directory / f"Ruthenium-{version}-{abi}-aapt2-badging.txt"
    )
    if f"package: name='{manifest['application_id']}'" not in badging:
        raise ReleaseBundleError("bundled aapt2 evidence has a different application ID")
    if "application-label:'Ruthenium'" not in badging:
        raise ReleaseBundleError("bundled aapt2 evidence has a different application label")
    signer_output = read_text(
        bundle_directory
        / f"Ruthenium-{version}-{abi}-apksigner-verification.txt"
    )
    signing_sha256 = str(manifest["signing_certificate_sha256"])
    if signing_sha256 not in signer_output.replace(":", "").lower():
        raise ReleaseBundleError("bundled apksigner evidence has a different certificate")
    certificate = bundle_directory / "ruthenium-release-cert.pem"
    if certificate_fingerprint(certificate) != signing_sha256:
        raise ReleaseBundleError("bundled signing certificate fingerprint mismatch")
    build_info = read_text(
        bundle_directory / f"Ruthenium-{version}-{abi}-build-info.txt"
    )
    expected_info = expected_build_info(
        version=version,
        revision=str(manifest["chromium_revision"]),
        release_id=str(manifest["release_tag"]),
        abi=abi,
        target_cpu=str(manifest["chromium_target_cpu"]),
        application_id=str(manifest["application_id"]),
        ministry_ca_der_sha256=str(manifest["ministry_ca_der_sha256"]),
        signing_fingerprint=signing_sha256,
    )
    if build_info != expected_info:
        raise ReleaseBundleError("bundled build information is inconsistent")
    return manifest


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    subparsers = value.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--artifacts", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--version", required=True)
    create.add_argument("--revision", required=True)
    create.add_argument("--release-id", required=True)
    create.add_argument("--abi", choices=sorted(ABI_TARGETS), required=True)
    create.add_argument("--target-cpu", choices=sorted(set(ABI_TARGETS.values())), required=True)
    create.add_argument("--application-id", required=True)
    create.add_argument("--ministry-ca-der-sha256", required=True)
    create.add_argument("--signing-certificate-sha256", required=True)
    create.add_argument("--source-snapshot-sha256", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    return value


def main() -> int:
    arguments = parser().parse_args()
    if arguments.command == "verify":
        manifest = verify_bundle(arguments.bundle)
    else:
        manifest = create_bundle(
            artifacts=arguments.artifacts,
            output=arguments.output,
            version=arguments.version,
            revision=arguments.revision,
            release_id=arguments.release_id,
            abi=arguments.abi,
            target_cpu=arguments.target_cpu,
            application_id=arguments.application_id,
            ministry_ca_der_sha256=arguments.ministry_ca_der_sha256,
            signing_fingerprint=arguments.signing_certificate_sha256,
            source_snapshot_sha256=arguments.source_snapshot_sha256,
        )
    print(
        json.dumps(
            {
                "abi": manifest["abi"],
                "asset_count": len(manifest["assets"]),
                "release_tag": manifest["release_tag"],
                "status": "verified",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ReleaseBundleError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"release bundle error: {error}") from error
