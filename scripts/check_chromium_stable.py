#!/usr/bin/env python3
"""Select the newest Android Stable Chromium release and update the CI lock."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any


MAX_RESPONSE_SIZE = 1024 * 1024
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){3}")
REVISION_RE = re.compile(r"[0-9a-f]{40}")


class StableReleaseError(RuntimeError):
    """Raised when ChromiumDash or the checked-in release lock is inconsistent."""


def version_tuple(value: str) -> tuple[int, int, int, int]:
    if not VERSION_RE.fullmatch(value):
        raise StableReleaseError(f"invalid Chromium version: {value!r}")
    return tuple(int(component) for component in value.split("."))  # type: ignore[return-value]


def parse_response(data: bytes) -> list[dict[str, Any]]:
    if not data or len(data) > MAX_RESPONSE_SIZE:
        raise StableReleaseError("ChromiumDash response has an invalid size")
    try:
        value = json.loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StableReleaseError("ChromiumDash response is not valid UTF-8 JSON") from error
    if not isinstance(value, list) or not value:
        raise StableReleaseError("ChromiumDash returned no releases")
    releases: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise StableReleaseError("ChromiumDash returned a malformed release")
        if item.get("channel") != "Stable" or item.get("platform") != "Android":
            continue
        version = item.get("version")
        milestone = item.get("milestone")
        hashes = item.get("hashes")
        if not isinstance(version, str):
            raise StableReleaseError("stable Android release has no version")
        parsed_version = version_tuple(version)
        if type(milestone) is not int or milestone != parsed_version[0]:
            raise StableReleaseError("stable Android release has an invalid milestone")
        if not isinstance(hashes, dict):
            raise StableReleaseError("stable Android release has no revision map")
        revision = hashes.get("chromium")
        if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
            raise StableReleaseError("stable Android release has an invalid revision")
        releases.append(
            {
                "branch": str(parsed_version[2]),
                "milestone": milestone,
                "revision": revision,
                "version": version,
                "version_tuple": parsed_version,
            }
        )
    if not releases:
        raise StableReleaseError("ChromiumDash returned no Android Stable releases")
    return releases


def select_release(
    data: bytes, current_version: str, current_revision: str
) -> dict[str, Any]:
    current_tuple = version_tuple(current_version)
    if not REVISION_RE.fullmatch(current_revision):
        raise StableReleaseError("current Chromium revision is invalid")
    releases = parse_response(data)
    newest_tuple = max(release["version_tuple"] for release in releases)
    newest = [
        release for release in releases if release["version_tuple"] == newest_tuple
    ]
    identities = {(release["version"], release["revision"]) for release in newest}
    if len(identities) != 1:
        raise StableReleaseError("ChromiumDash disagrees about the newest release")
    selected = newest[0]
    if newest_tuple < current_tuple:
        raise StableReleaseError(
            "ChromiumDash newest release is older than the checked-in release"
        )
    if newest_tuple == current_tuple:
        if selected["revision"] != current_revision:
            raise StableReleaseError(
                "checked-in version and ChromiumDash resolve to different revisions"
            )
        status = "current"
    else:
        status = "update"
    return {
        "branch": selected["branch"],
        "current_revision": current_revision,
        "current_version": current_version,
        "milestone": selected["milestone"],
        "revision": selected["revision"],
        "status": status,
        "version": selected["version"],
    }


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def atomic_write(path: Path, data: bytes, mode: int | None = None) -> None:
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


def update_repository(
    pipeline_path: Path, readme_path: Path, selection: dict[str, Any]
) -> None:
    if selection.get("status") != "update":
        raise StableReleaseError("refusing to rewrite CI without a newer release")
    values = {
        "CHROMIUM_VERSION": selection.get("version"),
        "CHROMIUM_REVISION": selection.get("revision"),
        "CHROMIUM_BRANCH": selection.get("branch"),
    }
    if (
        not isinstance(values["CHROMIUM_VERSION"], str)
        or not VERSION_RE.fullmatch(values["CHROMIUM_VERSION"])
        or not isinstance(values["CHROMIUM_REVISION"], str)
        or not REVISION_RE.fullmatch(values["CHROMIUM_REVISION"])
        or not isinstance(values["CHROMIUM_BRANCH"], str)
        or not re.fullmatch(r"[0-9]+", values["CHROMIUM_BRANCH"])
    ):
        raise StableReleaseError("selection contains invalid update values")
    try:
        content = pipeline_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise StableReleaseError("CI configuration is not UTF-8") from error
    for key, new_value in values.items():
        pattern = re.compile(rf'^(  {re.escape(key)}: ")([^"]+)(")$', re.MULTILINE)
        matches = list(pattern.finditer(content))
        if len(matches) != 1:
            raise StableReleaseError(f"CI release lock field is not unique: {key}")
        old_value = matches[0].group(2)
        if key == "CHROMIUM_VERSION" and old_value != selection.get("current_version"):
            raise StableReleaseError("checked-in Chromium version changed during update")
        if key == "CHROMIUM_REVISION" and old_value != selection.get(
            "current_revision"
        ):
            raise StableReleaseError("checked-in Chromium revision changed during update")
        content = pattern.sub(rf"\g<1>{new_value}\g<3>", content, count=1)
    atomic_write(pipeline_path, content.encode("utf-8"))

    try:
        readme = readme_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise StableReleaseError("README is not UTF-8") from error
    old_version = str(selection["current_version"])
    old_revision = str(selection["current_revision"])
    new_version = str(selection["version"])
    new_revision = str(selection["revision"])
    old_pin = (
        f"The build is pinned to Android Stable Chromium `{old_version}`, revision\n"
        f"`{old_revision}`."
    )
    new_pin = (
        f"The build is pinned to Android Stable Chromium `{new_version}`, revision\n"
        f"`{new_revision}`."
    )
    old_artifact = f"`artifacts/Ruthenium-{old_version}-arm64-v8a.apk`"
    new_artifact = f"`artifacts/Ruthenium-{new_version}-arm64-v8a.apk`"
    if readme.count(old_pin) != 1 or readme.count(old_artifact) != 1:
        raise StableReleaseError("README release lock is not unique")
    readme = readme.replace(old_pin, new_pin).replace(old_artifact, new_artifact)
    atomic_write(readme_path, readme.encode("utf-8"))


def load_selection(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if not data or len(data) > MAX_RESPONSE_SIZE:
        raise StableReleaseError("selection file has an invalid size")
    try:
        value = json.loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StableReleaseError("selection file is invalid") from error
    if not isinstance(value, dict) or canonical_json(value) != data:
        raise StableReleaseError("selection file is not canonical JSON")
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    select = commands.add_parser("select")
    select.add_argument("--input", type=Path, required=True)
    select.add_argument("--output", type=Path, required=True)
    select.add_argument("--current-version", required=True)
    select.add_argument("--current-revision", required=True)
    update = commands.add_parser("update-ci")
    update.add_argument("--selection", type=Path, required=True)
    update.add_argument("--pipeline", type=Path, required=True)
    update.add_argument("--readme", type=Path, required=True)
    return value


def main() -> int:
    arguments = parser().parse_args()
    if arguments.command == "select":
        selection = select_release(
            arguments.input.read_bytes(),
            arguments.current_version,
            arguments.current_revision,
        )
        atomic_write(arguments.output, canonical_json(selection), mode=0o600)
        print(json.dumps(selection, sort_keys=True))
    else:
        selection = load_selection(arguments.selection)
        update_repository(arguments.pipeline, arguments.readme, selection)
        print(
            json.dumps(
                {
                    "revision": selection["revision"],
                    "status": "updated",
                    "version": selection["version"],
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, StableReleaseError) as error:
        raise SystemExit(f"stable release check failed: {error}") from error
