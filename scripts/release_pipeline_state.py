#!/usr/bin/env python3
"""Keep automated Ruthenium releases single-flight and retryable."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any
from urllib.parse import quote, urlencode, urlparse


try:
    from scripts import release_identity
except ImportError:
    # CI runs this as `python3 scripts/release_pipeline_state.py`, which puts
    # scripts/ on sys.path instead of the repository root.
    import release_identity  # type: ignore[no-redef]


VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){3}")
REVISION_RE = re.compile(r"[0-9a-f]{40}")
RELEASE_ID_RE = release_identity.RELEASE_ID_RE
ACTIVE_PIPELINE_STATES = {
    "canceling",
    "created",
    "manual",
    "waiting_for_resource",
    "waiting_for_callback",
    "preparing",
    "pending",
    "running",
    "scheduled",
}
TERMINAL_PIPELINE_STATES = {"canceled", "failed"}
REQUIRED_RELEASE_JOBS = {
    "build_arm64",
    "build_armv7",
    "build_x86_64",
    "publish_github_snapshot",
    "publish_github_release_arm64",
    "publish_github_release_armv7",
    "publish_github_release_x86_64",
}
MAX_API_RESPONSE_SIZE = 8 * 1024 * 1024


class ReleaseStateError(RuntimeError):
    """Raised when the private GitLab release ledger is inconsistent."""


def release_id_from_sources(sources: dict[Path, bytes]) -> str:
    try:
        return release_identity.release_id(release_identity.release_inputs(sources))
    except release_identity.ReleaseIdentityError as error:
        raise ReleaseStateError(str(error)) from error


def marker_tag(value: str) -> str:
    if not RELEASE_ID_RE.fullmatch(value):
        raise ReleaseStateError("invalid release identity for marker")
    return f"ruthenium-published/{value}"


def validate_marker(value: object, expected_release_id: str) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("name") != marker_tag(
        expected_release_id
    ):
        raise ReleaseStateError("GitLab returned an invalid release marker")
    commit = value.get("commit")
    if (
        not isinstance(commit, dict)
        or not isinstance(commit.get("id"), str)
        or not REVISION_RE.fullmatch(commit["id"])
    ):
        raise ReleaseStateError("GitLab release marker has an invalid commit")
    return value


def task_variables(value: object) -> dict[str, str]:
    if not isinstance(value, list):
        raise ReleaseStateError("GitLab returned malformed pipeline variables")
    variables: dict[str, str] = {}
    for record in value:
        if not isinstance(record, dict):
            raise ReleaseStateError("GitLab returned malformed pipeline variable")
        key = record.get("key")
        item = record.get("value")
        if not isinstance(key, str) or not isinstance(item, str) or key in variables:
            raise ReleaseStateError("GitLab returned invalid pipeline variables")
        variables[key] = item
    return variables


def latest_job_states(value: object) -> dict[str, str]:
    if not isinstance(value, list):
        raise ReleaseStateError("GitLab returned malformed pipeline jobs")
    latest: dict[str, tuple[int, str]] = {}
    for job in value:
        if not isinstance(job, dict):
            raise ReleaseStateError("GitLab returned malformed pipeline job")
        identifier = job.get("id")
        name = job.get("name")
        status = job.get("status")
        if type(identifier) is not int or not isinstance(name, str) or not isinstance(
            status, str
        ):
            raise ReleaseStateError("GitLab returned invalid pipeline job metadata")
        if name not in latest or identifier > latest[name][0]:
            latest[name] = (identifier, status)
    return {name: status for name, (_, status) in latest.items()}


def required_release_jobs_succeeded(value: object) -> bool:
    states = latest_job_states(value)
    return all(states.get(name) == "success" for name in REQUIRED_RELEASE_JOBS)


class GitLab:
    def __init__(self, api_url: str, project_id: int, curl_config: Path) -> None:
        parsed = urlparse(api_url)
        if not parsed.hostname or parsed.query or parsed.fragment:
            raise ReleaseStateError("GitLab API URL must be a plain HTTP(S) URL")
        if parsed.scheme == "https":
            self.curl_protocol = "=https"
        elif parsed.scheme == "http":
            try:
                address = ipaddress.ip_address(parsed.hostname)
            except ValueError as error:
                raise ReleaseStateError(
                    "plain HTTP GitLab API requires a literal private address"
                ) from error
            if not (address.is_private or address.is_loopback):
                raise ReleaseStateError(
                    "plain HTTP GitLab API requires a private or loopback address"
                )
            self.curl_protocol = "=http"
        else:
            raise ReleaseStateError("GitLab API URL must use HTTP or HTTPS")
        if not parsed.path.rstrip("/").endswith("/api/v4"):
            raise ReleaseStateError("GitLab API URL must end in /api/v4")
        if project_id <= 0:
            raise ReleaseStateError("invalid GitLab project ID")
        metadata = curl_config.stat()
        if not curl_config.is_file() or metadata.st_mode & 0o777 != 0o600:
            raise ReleaseStateError("GitLab curl config must be a mode-0600 file")
        self.api_url = api_url.rstrip("/")
        self.project_root = f"{self.api_url}/projects/{project_id}"
        self.curl_config = curl_config

    def request(
        self,
        method: str,
        path: str,
        *,
        expected: set[int],
        body: object | None = None,
    ) -> tuple[int, bytes]:
        if method not in {"GET", "POST", "PUT"}:
            raise ReleaseStateError(f"unsupported GitLab method: {method}")
        if not path.startswith("/") or "\n" in path or "\r" in path:
            raise ReleaseStateError("invalid GitLab API path")
        url = f"{self.project_root}{path}"
        descriptor, response_name = tempfile.mkstemp(prefix="ruthenium-gitlab-response.")
        os.close(descriptor)
        response_path = Path(response_name)
        request_path: Path | None = None
        command = [
            "/usr/bin/curl",
            "--disable",
            "--silent",
            "--show-error",
            "--proto",
            self.curl_protocol,
            "--connect-timeout",
            "15",
            "--max-time",
            "120",
            "--max-filesize",
            str(MAX_API_RESPONSE_SIZE),
            "--config",
            str(self.curl_config),
            "--request",
            method,
            "--output",
            str(response_path),
            "--write-out",
            "%{http_code}",
        ]
        try:
            if body is not None:
                descriptor, request_name = tempfile.mkstemp(
                    prefix="ruthenium-gitlab-request.", suffix=".json"
                )
                request_path = Path(request_name)
                with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                    json.dump(body, output, sort_keys=True, separators=(",", ":"))
                    output.write("\n")
                os.chmod(request_path, 0o600)
                command.extend(
                    [
                        "--header",
                        "Content-Type: application/json",
                        "--data-binary",
                        f"@{request_path}",
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
                raise ReleaseStateError("curl returned an invalid GitLab status")
            status = int(status_text)
            data = response_path.read_bytes()
            if len(data) > MAX_API_RESPONSE_SIZE:
                raise ReleaseStateError("GitLab response exceeded the size limit")
            if status not in expected:
                raise ReleaseStateError(
                    f"GitLab returned HTTP {status} for {method} {path}"
                )
            return status, data
        finally:
            response_path.unlink(missing_ok=True)
            if request_path is not None:
                request_path.unlink(missing_ok=True)

    def json(
        self,
        method: str,
        path: str,
        *,
        expected: set[int],
        body: object | None = None,
    ) -> tuple[int, Any]:
        status, data = self.request(method, path, expected=expected, body=body)
        try:
            return status, json.loads(data.decode("utf-8", "strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReleaseStateError("GitLab returned malformed JSON") from error


def pipeline_release_id(client: GitLab, pipeline: dict[str, Any]) -> str | None:
    pipeline_id = pipeline.get("id")
    sha = pipeline.get("sha")
    if type(pipeline_id) is not int or not isinstance(sha, str) or not REVISION_RE.fullmatch(
        sha
    ):
        raise ReleaseStateError("GitLab returned invalid pipeline metadata")
    _, raw_variables = client.json(
        "GET", f"/pipelines/{pipeline_id}/variables", expected={200}
    )
    variables = task_variables(raw_variables)
    if variables.get("RUTHENIUM_SCHEDULE_TASK") != "release_update":
        return None
    declared = variables.get("RUTHENIUM_RELEASE_ID")
    if declared is not None:
        if not RELEASE_ID_RE.fullmatch(declared):
            # A pipeline from an older identity scheme names a release that no
            # longer exists under this one. It is not a candidate, and it must
            # not abort the scan for the release we are actually looking for.
            return None
        return declared
    sources: dict[Path, bytes] = {}
    for path in release_identity.INPUT_RELATIVE_PATHS:
        encoded_file = quote(path.as_posix(), safe="")
        _, data = client.request(
            "GET",
            f"/repository/files/{encoded_file}/raw?{urlencode({'ref': sha})}",
            expected={200},
        )
        sources[path] = data
    return release_id_from_sources(sources)


def release_pipelines(client: GitLab, ref: str) -> list[dict[str, Any]]:
    pipelines: list[dict[str, Any]] = []
    for page in range(1, 21):
        _, response = client.json(
            "GET",
            "/pipelines?"
            + urlencode(
                {
                    "ref": ref,
                    "source": "api",
                    "per_page": "100",
                    "page": str(page),
                    "order_by": "id",
                    "sort": "desc",
                }
            ),
            expected={200},
        )
        if not isinstance(response, list):
            raise ReleaseStateError("GitLab returned malformed pipeline list")
        if any(not isinstance(item, dict) for item in response):
            raise ReleaseStateError("GitLab returned malformed pipeline")
        pipelines.extend(response)
        if len(response) < 100:
            return pipelines
    raise ReleaseStateError("GitLab release pipeline history exceeded 2000 entries")


def inspect_release(
    client: GitLab,
    *,
    ref: str,
    expected_release_id: str,
    current_pipeline_id: int,
) -> dict[str, Any]:
    if not ref or len(ref) > 255 or any(character.isspace() for character in ref):
        raise ReleaseStateError("invalid GitLab ref")
    if not RELEASE_ID_RE.fullmatch(expected_release_id):
        raise ReleaseStateError("invalid expected release identity")
    encoded_tag = quote(marker_tag(expected_release_id), safe="")
    marker_status, marker = client.json(
        "GET", f"/repository/tags/{encoded_tag}", expected={200, 404}
    )
    if marker_status == 200:
        validate_marker(marker, expected_release_id)
        return {
            "decision": "complete",
            "marker": marker_tag(expected_release_id),
            "pipeline_id": None,
            "release_id": expected_release_id,
        }

    pipelines = release_pipelines(client, ref)
    candidates: list[dict[str, Any]] = []
    for pipeline in pipelines:
        pipeline_id = pipeline.get("id")
        if pipeline_id == current_pipeline_id:
            continue
        if pipeline.get("ref") != ref or pipeline.get("source") != "api":
            continue
        if pipeline_release_id(client, pipeline) != expected_release_id:
            continue
        status = pipeline.get("status")
        if not isinstance(status, str):
            raise ReleaseStateError("GitLab returned a pipeline without status")
        candidates.append(pipeline)

    complete: list[dict[str, Any]] = []
    active: list[dict[str, Any]] = []
    terminal: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    for pipeline in candidates:
        status = str(pipeline["status"])
        if status == "success":
            _, jobs = client.json(
                "GET",
                f"/pipelines/{pipeline['id']}/jobs?per_page=100&include_retried=true",
                expected={200},
            )
            if required_release_jobs_succeeded(jobs):
                complete.append(pipeline)
            else:
                invalid.append(pipeline)
        elif status in ACTIVE_PIPELINE_STATES:
            active.append(pipeline)
        elif status in TERMINAL_PIPELINE_STATES:
            terminal.append(pipeline)
        else:
            invalid.append(pipeline)

    if complete:
        selected = max(complete, key=lambda item: int(item["id"]))
        decision = "complete_unmarked"
    elif active:
        selected = max(active, key=lambda item: int(item["id"]))
        decision = "active"
    elif terminal:
        selected = max(terminal, key=lambda item: int(item["id"]))
        decision = "retry"
    elif invalid:
        selected = max(invalid, key=lambda item: int(item["id"]))
        decision = "invalid"
    else:
        selected = None
        decision = "missing"
    return {
        "decision": decision,
        "marker": None,
        "pipeline_id": selected.get("id") if selected else None,
        "pipeline_sha": selected.get("sha") if selected else None,
        "pipeline_status": selected.get("status") if selected else None,
        "release_id": expected_release_id,
    }


def trigger_release(
    client: GitLab, *, ref: str, commit_sha: str, expected_release_id: str
) -> dict[str, Any]:
    if not REVISION_RE.fullmatch(commit_sha):
        raise ReleaseStateError("invalid expected release commit")
    if not RELEASE_ID_RE.fullmatch(expected_release_id):
        raise ReleaseStateError("invalid release identity")
    _, pipeline = client.json(
        "POST",
        "/pipeline",
        expected={201},
        body={
            "ref": ref,
            "variables": [
                {
                    "key": "RUTHENIUM_SCHEDULE_TASK",
                    "value": "release_update",
                    "variable_type": "env_var",
                },
                {
                    "key": "RUTHENIUM_RELEASE_ID",
                    "value": expected_release_id,
                    "variable_type": "env_var",
                },
            ],
        },
    )
    if (
        not isinstance(pipeline, dict)
        or pipeline.get("sha") != commit_sha
        or pipeline.get("ref") != ref
        or pipeline.get("source") != "api"
        or type(pipeline.get("id")) is not int
    ):
        raise ReleaseStateError("GitLab started an unexpected release pipeline")
    return pipeline


def retry_release(
    client: GitLab,
    *,
    ref: str,
    pipeline_id: int,
    commit_sha: str,
    expected_release_id: str,
) -> dict[str, Any]:
    if pipeline_id <= 0 or not REVISION_RE.fullmatch(commit_sha):
        raise ReleaseStateError("invalid release pipeline retry target")
    _, current = client.json("GET", f"/pipelines/{pipeline_id}", expected={200})
    if (
        not isinstance(current, dict)
        or current.get("id") != pipeline_id
        or current.get("ref") != ref
        or current.get("sha") != commit_sha
        or current.get("status") not in TERMINAL_PIPELINE_STATES
        or pipeline_release_id(client, current) != expected_release_id
    ):
        raise ReleaseStateError("refusing to retry an unexpected release pipeline")
    # GitLab answers a retry with 201 Created, not 200.
    _, retried = client.json(
        "POST", f"/pipelines/{pipeline_id}/retry", expected={200, 201}
    )
    if (
        not isinstance(retried, dict)
        or retried.get("id") != pipeline_id
        or retried.get("ref") != ref
        or retried.get("sha") != commit_sha
    ):
        raise ReleaseStateError("GitLab retried an unexpected release pipeline")
    return retried


def verify_release_pipeline_jobs(client: GitLab, pipeline_id: int, commit_sha: str) -> None:
    _, pipeline = client.json("GET", f"/pipelines/{pipeline_id}", expected={200})
    if (
        not isinstance(pipeline, dict)
        or pipeline.get("sha") != commit_sha
        or pipeline.get("status") not in {"running", "success"}
    ):
        raise ReleaseStateError("cannot mark an unexpected release pipeline")
    _, jobs = client.json(
        "GET",
        f"/pipelines/{pipeline_id}/jobs?per_page=100&include_retried=true",
        expected={200},
    )
    if not required_release_jobs_succeeded(jobs):
        raise ReleaseStateError("cannot mark release before every required job succeeds")


def mark_release(
    client: GitLab,
    *,
    pipeline_id: int,
    commit_sha: str,
    expected_release_id: str,
) -> dict[str, Any]:
    if not REVISION_RE.fullmatch(commit_sha):
        raise ReleaseStateError("invalid release commit for marker")
    if not RELEASE_ID_RE.fullmatch(expected_release_id):
        raise ReleaseStateError("invalid release identity for marker")
    verify_release_pipeline_jobs(client, pipeline_id, commit_sha)
    tag = marker_tag(expected_release_id)
    encoded_tag = quote(tag, safe="")
    status, existing = client.json(
        "GET", f"/repository/tags/{encoded_tag}", expected={200, 404}
    )
    if status == 200:
        return validate_marker(existing, expected_release_id)
    _, created = client.json(
        "POST",
        "/repository/tags",
        expected={201},
        body={
            "message": f"All ABI assets published for {expected_release_id}",
            "ref": commit_sha,
            "tag_name": tag,
        },
    )
    marker = validate_marker(created, expected_release_id)
    if marker["commit"]["id"] != commit_sha:
        raise ReleaseStateError("GitLab release marker points to an unexpected commit")
    return marker


def ensure_resource_mode(client: GitLab, key: str, mode: str) -> None:
    if key != "chromium-android-checkout" or mode != "oldest_first":
        raise ReleaseStateError("refusing unexpected resource-group configuration")
    encoded_key = quote(key, safe="")
    _, current = client.json("GET", f"/resource_groups/{encoded_key}", expected={200})
    if not isinstance(current, dict) or current.get("key") != key:
        raise ReleaseStateError("GitLab returned an invalid resource group")
    if current.get("process_mode") != mode:
        _, current = client.json(
            "PUT",
            f"/resource_groups/{encoded_key}",
            expected={200},
            body={"process_mode": mode},
        )
    if not isinstance(current, dict) or current.get("process_mode") != mode:
        raise ReleaseStateError("GitLab resource group did not enter oldest_first mode")


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def add_client_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--project-id", type=int, required=True)
    parser.add_argument("--curl-config", type=Path, required=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    identity = subparsers.add_parser("release-id")
    identity.add_argument("--root", type=Path, required=True)

    inspect = subparsers.add_parser("inspect")
    add_client_arguments(inspect)
    inspect.add_argument("--ref", required=True)
    inspect.add_argument("--release-id", required=True)
    inspect.add_argument("--current-pipeline-id", type=int, required=True)
    inspect.add_argument("--output", type=Path, required=True)

    trigger = subparsers.add_parser("trigger")
    add_client_arguments(trigger)
    trigger.add_argument("--ref", required=True)
    trigger.add_argument("--commit-sha", required=True)
    trigger.add_argument("--release-id", required=True)
    trigger.add_argument("--output", type=Path, required=True)

    retry = subparsers.add_parser("retry")
    add_client_arguments(retry)
    retry.add_argument("--ref", required=True)
    retry.add_argument("--pipeline-id", type=int, required=True)
    retry.add_argument("--commit-sha", required=True)
    retry.add_argument("--release-id", required=True)
    retry.add_argument("--output", type=Path, required=True)

    mark = subparsers.add_parser("mark")
    add_client_arguments(mark)
    mark.add_argument("--pipeline-id", type=int, required=True)
    mark.add_argument("--commit-sha", required=True)
    mark.add_argument("--release-id", required=True)
    mark.add_argument("--output", type=Path, required=True)

    resource = subparsers.add_parser("ensure-resource-mode")
    add_client_arguments(resource)
    resource.add_argument("--key", required=True)
    resource.add_argument("--mode", required=True)
    return parser.parse_args()


def client_from_args(arguments: argparse.Namespace) -> GitLab:
    return GitLab(arguments.api_url, arguments.project_id, arguments.curl_config)


def main() -> int:
    arguments = parse_args()
    if arguments.command == "release-id":
        try:
            sources = release_identity.read_sources(arguments.root)
        except release_identity.ReleaseIdentityError as error:
            raise ReleaseStateError(str(error)) from error
        print(release_id_from_sources(sources))
        return 0
    client = client_from_args(arguments)
    if arguments.command == "inspect":
        result = inspect_release(
            client,
            ref=arguments.ref,
            expected_release_id=arguments.release_id,
            current_pipeline_id=arguments.current_pipeline_id,
        )
        write_json(arguments.output, result)
        print(
            f"Release {arguments.release_id}: {result['decision']}"
            + (
                f" (pipeline {result['pipeline_id']}, {result['pipeline_status']})"
                if result["pipeline_id"] is not None
                else ""
            )
        )
    elif arguments.command == "trigger":
        result = trigger_release(
            client,
            ref=arguments.ref,
            commit_sha=arguments.commit_sha,
            expected_release_id=arguments.release_id,
        )
        write_json(arguments.output, result)
        print(f"Triggered automated release pipeline {result['id']}")
    elif arguments.command == "retry":
        result = retry_release(
            client,
            ref=arguments.ref,
            pipeline_id=arguments.pipeline_id,
            commit_sha=arguments.commit_sha,
            expected_release_id=arguments.release_id,
        )
        write_json(arguments.output, result)
        print(f"Retried automated release pipeline {result['id']} at {result['sha']}")
    elif arguments.command == "mark":
        result = mark_release(
            client,
            pipeline_id=arguments.pipeline_id,
            commit_sha=arguments.commit_sha,
            expected_release_id=arguments.release_id,
        )
        write_json(arguments.output, result)
        print(f"Recorded completed release marker {result['name']}")
    elif arguments.command == "ensure-resource-mode":
        ensure_resource_mode(client, arguments.key, arguments.mode)
        print(f"Resource group {arguments.key}: {arguments.mode}")
    else:  # pragma: no cover
        raise ReleaseStateError("unknown command")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ReleaseStateError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"release state check failed: {error}") from error
