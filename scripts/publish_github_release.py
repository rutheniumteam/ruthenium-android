#!/usr/bin/env python3
"""Publish one verified ABI bundle as an immutable GitHub Release asset set."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import tempfile
from typing import Any
from urllib.parse import quote, urlencode

if __package__:
    from . import prepare_github_release
else:
    import prepare_github_release


PUBLISHER_USER = "ruthenium-publisher"
GITHUB_REPOSITORY = "rutheniumteam/ruthenium-android"
API_ROOT = f"https://api.github.com/repos/{GITHUB_REPOSITORY}"
UPLOAD_ROOT = f"https://uploads.github.com/repos/{GITHUB_REPOSITORY}/releases/"
WITH_TOR_PATH = Path("/usr/local/bin/ruthenium-with-tor")
CURL_PATH = Path("/usr/bin/curl")
# A single asset download is a multi-hundred-megabyte stream that runs for
# roughly an hour over Tor, which is long enough for the circuit to break. Each
# retry goes through with_tor.sh again and therefore through a new circuit; the
# SHA-256 check on the assembled file still has to pass, so resuming a partial
# transfer cannot smuggle in different bytes.
DOWNLOAD_ATTEMPTS = 4
UPLOAD_ATTEMPTS = 3
CURL_RANGE_NOT_SUPPORTED = 33
GITHUB_API_VERSION = "2026-03-10"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
GIT_OBJECT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
TOR_PROXY_RE = re.compile(
    r"socks5h://([0-9a-f-]+):\1@127\.0\.0\.1:9050"
)


class ReleasePublicationError(RuntimeError):
    """Raised when GitHub publication cannot be proven safe and complete."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_private_json(directory: Path, value: object) -> Path:
    descriptor, name = tempfile.mkstemp(dir=directory, prefix="request.", suffix=".json")
    path = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(path, 0o600)
        return path
    except Exception:
        path.unlink(missing_ok=True)
        raise


class GitHub:
    def __init__(self, auth_config: Path, workspace: Path) -> None:
        self.auth_config = auth_config
        self.workspace = workspace

    def request(
        self,
        method: str,
        url: str,
        *,
        body: object | None = None,
        upload: Path | None = None,
        content_type: str | None = None,
    ) -> tuple[int, bytes]:
        if not (url.startswith(f"{API_ROOT}/") or url.startswith(UPLOAD_ROOT)):
            raise ReleasePublicationError(f"refusing unexpected GitHub URL: {url}")
        response_fd, response_name = tempfile.mkstemp(
            dir=self.workspace, prefix="response.", suffix=".json"
        )
        os.close(response_fd)
        response_path = Path(response_name)
        request_path: Path | None = None
        command = [
            str(CURL_PATH),
            "--disable",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "30",
            "--max-time",
            "10800" if upload is not None else "120",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--config",
            str(self.auth_config),
            "--header",
            "Accept: application/vnd.github+json",
            "--header",
            f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
            "--request",
            method,
            "--output",
            str(response_path),
            "--write-out",
            "%{http_code}",
        ]
        try:
            if body is not None:
                request_path = write_private_json(self.workspace, body)
                command.extend(
                    [
                        "--header",
                        "Content-Type: application/json",
                        "--data-binary",
                        f"@{request_path}",
                    ]
                )
            if upload is not None:
                if body is not None or content_type is None:
                    raise ReleasePublicationError("invalid asset upload request")
                command.extend(
                    [
                        "--header",
                        f"Content-Type: {content_type}",
                        "--data-binary",
                        f"@{upload}",
                    ]
                )
            command.append(url)
            result = subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            status_text = result.stdout.decode("ascii", "strict")
            if not re.fullmatch(r"[0-9]{3}", status_text):
                raise ReleasePublicationError("curl returned an invalid HTTP status")
            return int(status_text), response_path.read_bytes()
        finally:
            response_path.unlink(missing_ok=True)
            if request_path is not None:
                request_path.unlink(missing_ok=True)

    def json(
        self,
        method: str,
        url: str,
        *,
        expected: set[int],
        body: object | None = None,
    ) -> tuple[int, Any]:
        status, data = self.request(method, url, body=body)
        if status not in expected:
            message = ""
            try:
                parsed = json.loads(data)
                if isinstance(parsed, dict) and isinstance(parsed.get("message"), str):
                    message = f": {parsed['message']}"
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
            raise ReleasePublicationError(
                f"GitHub API returned HTTP {status} for {method} {url}{message}"
            )
        try:
            return status, json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReleasePublicationError("GitHub returned invalid JSON") from error


def require_publication_boundary(bundle: Path, auth_config: Path) -> None:
    if os.environ.get("RUTHENIUM_TOR_VERIFIED") != "1":
        raise ReleasePublicationError("publication requires scripts/with_tor.sh")
    if pwd.getpwuid(os.getuid()).pw_name != PUBLISHER_USER:
        raise ReleasePublicationError("publication requires the fail-closed publisher user")
    if not TOR_PROXY_RE.fullmatch(os.environ.get("ALL_PROXY", "")):
        raise ReleasePublicationError("publication requires the fixed Tor SOCKS endpoint")
    for required in (WITH_TOR_PATH, CURL_PATH):
        if not required.is_file():
            raise ReleasePublicationError(f"required executable is missing: {required}")
    if not bundle.is_dir() or bundle.is_symlink():
        raise ReleasePublicationError("release bundle must be a real directory")
    if bundle.stat().st_mode & 0o777 != 0o700:
        raise ReleasePublicationError("release bundle directory must have mode 0700")
    for path in (bundle, auth_config, *bundle.iterdir()):
        metadata = path.lstat()
        if pwd.getpwuid(metadata.st_uid).pw_name != PUBLISHER_USER:
            raise ReleasePublicationError(f"publisher does not own required input: {path}")
        if path != bundle and (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o777 != 0o600
        ):
            raise ReleasePublicationError(
                f"publisher input must be a regular mode-0600 file: {path}"
            )
    if not stat.S_ISREG(auth_config.lstat().st_mode):
        raise ReleasePublicationError("GitHub authentication config must be a file")
    if auth_config.lstat().st_mode & 0o777 != 0o600:
        raise ReleasePublicationError("GitHub authentication config must have mode 0600")


def run_preflight(auth_config: Path, script_directory: Path) -> None:
    subprocess.run(
        [str(script_directory / "github_preflight.sh"), str(auth_config)],
        check=True,
    )


def github_main(github: GitHub, source_snapshot_sha256: str) -> tuple[str, str]:
    _, commit = github.json("GET", f"{API_ROOT}/commits/main", expected={200})
    try:
        commit_sha = commit["sha"]
        tree_sha = commit["commit"]["tree"]["sha"]
        message = commit["commit"]["message"]
    except (KeyError, TypeError) as error:
        raise ReleasePublicationError("GitHub returned malformed main commit data") from error
    if not GIT_OBJECT_RE.fullmatch(commit_sha) or not GIT_OBJECT_RE.fullmatch(tree_sha):
        raise ReleasePublicationError("GitHub returned malformed Git object identifiers")
    marker = f"Snapshot-SHA256: {source_snapshot_sha256}"
    if marker not in message.splitlines():
        raise ReleasePublicationError(
            "public main does not match the release source snapshot"
        )
    return commit_sha, tree_sha


def find_release(github: GitHub, tag: str) -> dict[str, Any] | None:
    status, release = github.json(
        "GET",
        f"{API_ROOT}/releases/tags/{quote(tag, safe='')}",
        expected={200, 404},
    )
    if status == 200:
        if not isinstance(release, dict):
            raise ReleasePublicationError("GitHub returned malformed release data")
        return release
    _, releases = github.json("GET", f"{API_ROOT}/releases?per_page=100", expected={200})
    if not isinstance(releases, list):
        raise ReleasePublicationError("GitHub returned malformed release list")
    matches = [item for item in releases if item.get("tag_name") == tag]
    if len(matches) > 1:
        raise ReleasePublicationError("GitHub returned duplicate releases for one tag")
    return matches[0] if matches else None


def create_release(
    github: GitHub,
    manifest: dict[str, Any],
    source_commit: str,
) -> dict[str, Any]:
    tag = manifest["release_tag"]
    body = release_body(manifest)
    _, release = github.json(
        "POST",
        f"{API_ROOT}/releases",
        expected={201},
        body={
            "body": body,
            "draft": True,
            "generate_release_notes": False,
            "name": release_title(manifest),
            "prerelease": False,
            "tag_name": tag,
            "target_commitish": source_commit,
        },
    )
    if not isinstance(release, dict):
        raise ReleasePublicationError("GitHub returned malformed created release")
    print(f"Created draft release {tag}")
    return release


def release_title(manifest: dict[str, Any]) -> str:
    """The single definition of a release title, written and checked alike."""
    ca_digest = str(manifest["ministry_ca_der_sha256"])[
        : prepare_github_release.release_identity.CA_DIGEST_LENGTH
    ]
    return f"Ruthenium {manifest['chromium_version']} (CA {ca_digest})"


def release_body(manifest: dict[str, Any]) -> str:
    """The release notes, a function of the release identity and nothing else.

    They deliberately name no public source commit. The tag already carries a
    digest over every input that produces these binaries, and each of those
    inputs is published, so a checkout that reproduces the digest reproduces the
    release. Naming one commit instead would pin the notes to a snapshot that
    moves on every unrelated push and would lock later architectures out of the
    release their siblings are already in.
    """
    version = manifest["chromium_version"]
    return (
        f"Ruthenium for Android, based on Chromium {version}.\n\n"
        "Each APK is specific to the Android ABI in its filename. SHA-256 "
        "checksums, build metadata, the public signing certificate, and "
        "machine-readable provenance are attached to this release.\n\n"
        f"Release identity: `{manifest['release_tag']}`\n"
        f"Chromium revision: `{manifest['chromium_revision']}`\n"
        f"Ministry CA DER SHA-256: `{manifest['ministry_ca_der_sha256']}`\n"
    )


def validate_release(
    release: dict[str, Any],
    manifest: dict[str, Any],
) -> None:
    if release.get("tag_name") != manifest["release_tag"]:
        raise ReleasePublicationError("existing release has an unexpected tag")
    if release.get("name") != release_title(manifest):
        raise ReleasePublicationError("existing release has an unexpected title")
    if release.get("body") != release_body(manifest):
        raise ReleasePublicationError("existing release has unexpected release notes")
    if release.get("prerelease") is not False:
        raise ReleasePublicationError("existing release unexpectedly is a prerelease")
    release_id = release.get("id")
    if not isinstance(release_id, int) or release_id <= 0:
        raise ReleasePublicationError("release has an invalid identifier")
    upload_url = release.get("upload_url")
    expected_prefix = f"{UPLOAD_ROOT}{release_id}/assets"
    if not isinstance(upload_url, str) or not upload_url.startswith(expected_prefix):
        raise ReleasePublicationError("release has an unexpected upload URL")


def release_assets(github: GitHub, release_id: int) -> list[dict[str, Any]]:
    _, assets = github.json(
        "GET", f"{API_ROOT}/releases/{release_id}/assets?per_page=100", expected={200}
    )
    if not isinstance(assets, list):
        raise ReleasePublicationError("GitHub returned malformed release assets")
    return assets


def allowed_release_asset_names(version: str) -> set[str]:
    names = {"Chromium-LICENSE.txt", "ruthenium-release-cert.pem"}
    for abi in prepare_github_release.ABI_TARGETS:
        prefix = f"Ruthenium-{version}-{abi}"
        names.update(
            {
                f"{prefix}.apk",
                f"{prefix}.apk.sha256",
                f"{prefix}-aapt2-badging.txt",
                f"{prefix}-apk-abis.txt",
                f"{prefix}-apksigner-verification.txt",
                f"{prefix}-build-info.txt",
                f"{prefix}-provenance.json",
            }
        )
    return names


def validate_asset_namespace(assets: list[dict[str, Any]], version: str) -> None:
    names = [asset.get("name") for asset in assets]
    if any(not isinstance(name, str) for name in names):
        raise ReleasePublicationError("GitHub returned an invalid release asset name")
    if len(names) != len(set(names)):
        raise ReleasePublicationError("GitHub release contains duplicate asset names")
    unexpected = set(names) - allowed_release_asset_names(version)
    if unexpected:
        raise ReleasePublicationError(
            f"GitHub release contains unexpected assets: {sorted(unexpected)}"
        )


def download_in_new_circuit(
    *,
    url: str,
    output: Path,
    auth_config: Path | None,
) -> None:
    allowed_prefixes = (
        "https://api.github.com/repos/rutheniumteam/ruthenium-android/releases/assets/",
        "https://github.com/rutheniumteam/ruthenium-android/releases/download/",
    )
    if not url.startswith(allowed_prefixes):
        raise ReleasePublicationError(f"refusing unexpected download URL: {url}")
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        resuming = output.exists() and output.stat().st_size > 0
        command = [
            str(WITH_TOR_PATH),
            str(CURL_PATH),
            "--disable",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--connect-timeout",
            "30",
            "--max-time",
            "10800",
            "--proto",
            "=https",
        ]
        if resuming:
            command.extend(["--continue-at", "-"])
        if auth_config is not None:
            command.extend(
                [
                    "--config",
                    str(auth_config),
                    "--header",
                    "Accept: application/octet-stream",
                    "--header",
                    f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
                ]
            )
        command.extend(["--output", str(output), url])
        result = subprocess.run(command)
        if result.returncode == 0:
            return
        if attempt == DOWNLOAD_ATTEMPTS:
            raise ReleasePublicationError(
                f"asset download failed after {DOWNLOAD_ATTEMPTS} attempts "
                f"(curl exit {result.returncode})"
            )
        if resuming and result.returncode == CURL_RANGE_NOT_SUPPORTED:
            output.unlink(missing_ok=True)
        print(
            f"Download attempt {attempt}/{DOWNLOAD_ATTEMPTS} failed with curl "
            f"exit {result.returncode}; retrying in a new circuit",
            flush=True,
        )


def asset_sha256(asset: dict[str, Any]) -> str | None:
    """Return the SHA-256 GitHub reports for an asset, or None when absent."""
    digest = asset.get("digest")
    if digest is None:
        return None
    if not isinstance(digest, str):
        raise ReleasePublicationError("GitHub asset has a malformed digest")
    algorithm, _, value = digest.partition(":")
    if algorithm != "sha256" or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ReleasePublicationError(f"unsupported GitHub asset digest: {digest}")
    return value


def validate_metadata(
    asset: dict[str, Any],
    expected_sha256: str,
    expected_size: int,
) -> bool:
    """Check what GitHub reports about an asset without transferring it.

    Returns True only when GitHub confirmed the content with a digest. A
    missing digest returns False so the caller falls back to a full download;
    it is never treated as a passing check.
    """
    if asset.get("size") != expected_size or asset.get("state") != "uploaded":
        raise ReleasePublicationError("GitHub asset metadata does not match local file")
    reported = asset_sha256(asset)
    if reported is None:
        return False
    if reported != expected_sha256:
        raise ReleasePublicationError("GitHub asset digest does not match local file")
    return True


def validate_download(
    asset: dict[str, Any],
    expected_sha256: str,
    expected_size: int,
    workspace: Path,
    auth_config: Path | None,
) -> None:
    asset_id = asset.get("id")
    if not isinstance(asset_id, int) or asset_id <= 0:
        raise ReleasePublicationError("GitHub asset has an invalid identifier")
    if asset.get("size") != expected_size or asset.get("state") != "uploaded":
        raise ReleasePublicationError("GitHub asset metadata does not match local file")
    url = asset.get("url") if auth_config is not None else asset.get("browser_download_url")
    if not isinstance(url, str):
        raise ReleasePublicationError("GitHub asset has no valid download URL")
    destination = workspace / f"download-{asset_id}"
    try:
        download_in_new_circuit(url=url, output=destination, auth_config=auth_config)
        if destination.stat().st_size != expected_size:
            raise ReleasePublicationError("downloaded GitHub asset size mismatch")
        if sha256_file(destination) != expected_sha256:
            raise ReleasePublicationError("downloaded GitHub asset SHA-256 mismatch")
    finally:
        destination.unlink(missing_ok=True)


def confirm_asset(
    *,
    github: GitHub,
    asset: dict[str, Any],
    expected_sha256: str,
    expected_size: int,
    workspace: Path,
    auth_config: Path,
) -> dict[str, Any]:
    """Gate one asset before the release leaves draft state.

    Draft assets are not reachable without a token, so the anonymous
    byte-for-byte check in independent_release_check() can only run once the
    release is public. This is the cheap gate that runs before that: it trusts
    the digest GitHub reports only to fail fast, and falls back to a full
    authenticated download whenever the digest is unavailable.
    """
    if validate_metadata(asset, expected_sha256, expected_size):
        return asset
    asset_id = asset.get("id")
    if not isinstance(asset_id, int) or asset_id <= 0:
        raise ReleasePublicationError("GitHub asset has an invalid identifier")
    _, refreshed = github.json(
        "GET", f"{API_ROOT}/releases/assets/{asset_id}", expected={200}
    )
    if not isinstance(refreshed, dict):
        raise ReleasePublicationError("GitHub returned a malformed release asset")
    if refreshed.get("id") != asset_id:
        raise ReleasePublicationError("GitHub returned a different release asset")
    if validate_metadata(refreshed, expected_sha256, expected_size):
        return refreshed
    validate_download(refreshed, expected_sha256, expected_size, workspace, auth_config)
    return refreshed


def ensure_asset(
    *,
    github: GitHub,
    release: dict[str, Any],
    path: Path,
    name: str,
    content_type: str,
    expected_sha256: str,
    expected_size: int,
    workspace: Path,
    auth_config: Path,
) -> dict[str, Any]:
    release_id = release["id"]
    matches = [asset for asset in release_assets(github, release_id) if asset.get("name") == name]
    if len(matches) > 1:
        raise ReleasePublicationError(f"duplicate GitHub release asset: {name}")
    if matches:
        asset = confirm_asset(
            github=github,
            asset=matches[0],
            expected_sha256=expected_sha256,
            expected_size=expected_size,
            workspace=workspace,
            auth_config=auth_config,
        )
        print(f"Release asset is already identical: {name}")
        return asset

    upload_url = str(release["upload_url"]).split("{", 1)[0]
    url = f"{upload_url}?{urlencode({'name': name})}"
    asset: dict[str, Any] | None = None
    for attempt in range(1, UPLOAD_ATTEMPTS + 1):
        try:
            status, response = github.request(
                "POST", url, upload=path, content_type=content_type
            )
        except subprocess.CalledProcessError as error:
            if attempt == UPLOAD_ATTEMPTS:
                raise ReleasePublicationError(
                    f"uploading {name} failed after {UPLOAD_ATTEMPTS} attempts "
                    f"(curl exit {error.returncode})"
                ) from error
            # The stream can die after GitHub already stored the asset, and a
            # blind repost would then either duplicate it or be rejected. Look
            # before uploading again.
            landed = [
                candidate
                for candidate in release_assets(github, release_id)
                if candidate.get("name") == name
            ]
            if landed:
                asset = landed[0]
                break
            print(
                f"Upload attempt {attempt}/{UPLOAD_ATTEMPTS} of {name} failed with "
                f"curl exit {error.returncode}; retrying",
                flush=True,
            )
            continue
        if status != 201:
            raise ReleasePublicationError(
                f"GitHub returned HTTP {status} while uploading {name}"
            )
        try:
            asset = json.loads(response)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReleasePublicationError(
                "GitHub returned invalid upload JSON"
            ) from error
        break

    if not isinstance(asset, dict):
        raise ReleasePublicationError(f"GitHub returned no asset for {name}")
    if asset.get("name") != name:
        raise ReleasePublicationError("GitHub created an asset with an unexpected name")
    asset = confirm_asset(
        github=github,
        asset=asset,
        expected_sha256=expected_sha256,
        expected_size=expected_size,
        workspace=workspace,
        auth_config=auth_config,
    )
    print(f"Uploaded and verified release asset: {name}")
    return asset


def provenance(manifest: dict[str, Any]) -> tuple[str, bytes]:
    """Record what produced these bytes, without naming a moving snapshot.

    Provenance stays a function of the release inputs so republishing an
    unchanged architecture reproduces it byte for byte. The public source is
    reachable through the release identity, which is a digest over the published
    files that determine the build.
    """
    value = {
        **{
            key: value
            for key, value in manifest.items()
            if key not in {"schema_version", "source_snapshot_sha256"}
        },
        "schema": "https://ruthenium.app/schemas/android-release-provenance-v1",
        "schema_version": 1,
    }
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    name = (
        f"Ruthenium-{manifest['chromium_version']}-{manifest['abi']}-provenance.json"
    )
    return name, data


def independent_release_check(
    github: GitHub,
    release: dict[str, Any],
    manifest: dict[str, Any],
    expected_assets: dict[str, tuple[str, int]],
    workspace: Path,
) -> None:
    release_id = release["id"]
    _, refreshed = github.json("GET", f"{API_ROOT}/releases/{release_id}", expected={200})
    if refreshed.get("draft") is not False:
        raise ReleasePublicationError("release did not become public")
    assets = release_assets(github, release_id)
    validate_asset_namespace(assets, str(manifest["chromium_version"]))
    for name, (expected_sha256, expected_size) in expected_assets.items():
        matches = [asset for asset in assets if asset.get("name") == name]
        if len(matches) != 1:
            raise ReleasePublicationError(f"published release asset is missing: {name}")
        validate_download(
            matches[0], expected_sha256, expected_size, workspace, auth_config=None
        )


def publish(bundle_directory: Path, auth_config: Path) -> dict[str, str]:
    require_publication_boundary(bundle_directory, auth_config)
    manifest = prepare_github_release.verify_bundle(bundle_directory)
    script_directory = Path(__file__).resolve().parent
    run_preflight(auth_config, script_directory)

    with tempfile.TemporaryDirectory(
        dir=Path("/srv/" "ruthenium-publisher"), prefix=".github-release."
    ) as temporary_directory:
        workspace = Path(temporary_directory)
        github = GitHub(auth_config, workspace)
        source_commit, source_tree = github_main(
            github, str(manifest["source_snapshot_sha256"])
        )
        release = find_release(github, str(manifest["release_tag"]))
        if release is None:
            release = create_release(github, manifest, source_commit)
        validate_release(release, manifest)
        validate_asset_namespace(
            release_assets(github, release["id"]),
            str(manifest["chromium_version"]),
        )

        expected_assets: dict[str, tuple[str, int]] = {}
        for record in manifest["assets"]:
            name = record["name"]
            ensure_asset(
                github=github,
                release=release,
                path=bundle_directory / name,
                name=name,
                content_type=record["content_type"],
                expected_sha256=record["sha256"],
                expected_size=record["size"],
                workspace=workspace,
                auth_config=auth_config,
            )
            expected_assets[name] = (record["sha256"], record["size"])

        provenance_name, provenance_data = provenance(manifest)
        provenance_path = workspace / provenance_name
        provenance_path.write_bytes(provenance_data)
        os.chmod(provenance_path, 0o600)
        provenance_sha256 = hashlib.sha256(provenance_data).hexdigest()
        ensure_asset(
            github=github,
            release=release,
            path=provenance_path,
            name=provenance_name,
            content_type="application/json",
            expected_sha256=provenance_sha256,
            expected_size=len(provenance_data),
            workspace=workspace,
            auth_config=auth_config,
        )
        expected_assets[provenance_name] = (
            provenance_sha256,
            len(provenance_data),
        )

        if release.get("draft") is True:
            _, release = github.json(
                "PATCH",
                f"{API_ROOT}/releases/{release['id']}",
                expected={200},
                body={"draft": False},
            )
            print(f"Published GitHub release {manifest['release_tag']}")

        independent_release_check(
            github, release, manifest, expected_assets, workspace
        )
        return {
            "abi": str(manifest["abi"]),
            "public_source_commit": source_commit,
            "public_source_tree": source_tree,
            "release_tag": str(manifest["release_tag"]),
            "verification": "PASS",
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--auth-config", type=Path, required=True)
    arguments = parser.parse_args()
    result = publish(arguments.bundle, arguments.auth_config)
    for key, value in sorted(result.items()):
        print(f"RELEASE_{key.upper()}={value}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        ReleasePublicationError,
        prepare_github_release.ReleaseBundleError,
        subprocess.CalledProcessError,
    ) as error:
        raise SystemExit(f"GitHub release publication failed: {error}") from error
