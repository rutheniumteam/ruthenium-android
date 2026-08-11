import json
from pathlib import Path
import tempfile
import unittest

from scripts import release_identity, release_pipeline_state


VERSION = "151.0.7922.108"
REVISION = "4" * 40
SHA = "a" * 40


def release_sources(patch: bytes = b"# patch\n") -> dict[Path, bytes]:
    """The four published files that decide which release a commit builds."""
    return {
        release_identity.PIPELINE_RELATIVE_PATH: (
            "variables:\n"
            f'  CHROMIUM_VERSION: "{VERSION}"\n'
            f'  CHROMIUM_REVISION: "{REVISION}"\n'
            '  RUTHENIUM_APPLICATION_ID: "app.ruthenium.browser"\n'
            '  RUTHENIUM_SIGNING_CERT_SHA256: "'
            + ":".join(["AB"] * 32)
            + '"\n'
        ).encode(),
        release_identity.LOCK_RELATIVE_PATH: json.dumps(
            {"der_sha256": "d" * 64}
        ).encode(),
        Path("build/args.gn"): b"target_os = \"android\"\n",
        Path("scripts/patch_chromium.py"): patch,
    }


RELEASE_SOURCES = release_sources()
RELEASE_ID = release_identity.release_id(
    release_identity.release_inputs(RELEASE_SOURCES)
)


def pipeline_record(identifier: int, status: str, sha: str = SHA) -> dict[str, object]:
    return {
        "id": identifier,
        "ref": "main",
        "sha": sha,
        "source": "api",
        "status": status,
    }


def release_variables(include_identity: bool = True) -> list[dict[str, str]]:
    variables = [
        {"key": "RUTHENIUM_SCHEDULE_TASK", "value": "release_update"}
    ]
    if include_identity:
        variables.append({"key": "RUTHENIUM_RELEASE_ID", "value": RELEASE_ID})
    return variables


def successful_jobs() -> list[dict[str, object]]:
    return [
        {"id": identifier, "name": name, "status": "success"}
        for identifier, name in enumerate(
            sorted(release_pipeline_state.REQUIRED_RELEASE_JOBS), start=1
        )
    ]


class FakeGitLab:
    def __init__(
        self,
        *,
        marker: bool = False,
        pipelines: list[dict[str, object]] | None = None,
        variables: dict[int, list[dict[str, str]]] | None = None,
        jobs: dict[int, list[dict[str, object]]] | None = None,
        pipeline_files: dict[str, dict[Path, bytes]] | None = None,
    ) -> None:
        self.has_marker = marker
        self.pipelines = pipelines or []
        self.variables = variables or {}
        self.jobs = jobs or {}
        self.pipeline_files = pipeline_files or {}
        self.requests: list[tuple[str, str, object | None]] = []
        self.resource_mode = "newest_first"

    def json(self, method, path, *, expected, body=None):
        self.requests.append((method, path, body))
        if path.startswith("/repository/tags/") and method == "GET":
            if self.has_marker:
                return 200, {
                    "name": release_pipeline_state.marker_tag(RELEASE_ID),
                    "commit": {"id": SHA},
                }
            return 404, {"message": "404 Tag Not Found"}
        if path.startswith("/pipelines?"):
            return 200, self.pipelines
        if path.endswith("/variables"):
            identifier = int(path.split("/")[2])
            return 200, self.variables[identifier]
        if "/jobs?" in path:
            identifier = int(path.split("/")[2])
            return 200, self.jobs[identifier]
        if path.startswith("/pipelines/") and method == "GET":
            identifier = int(path.split("/")[2])
            pipeline = next(item for item in self.pipelines if item["id"] == identifier)
            return 200, pipeline
        if path.startswith("/pipelines/") and path.endswith("/retry"):
            identifier = int(path.split("/")[2])
            pipeline = next(item for item in self.pipelines if item["id"] == identifier)
            return 201, {**pipeline, "status": "pending"}
        if path == "/pipeline" and method == "POST":
            return 201, {
                "id": 900,
                "ref": body["ref"],
                "sha": SHA,
                "source": "api",
            }
        if path == "/repository/tags" and method == "POST":
            self.has_marker = True
            return 201, {"name": body["tag_name"], "commit": {"id": SHA}}
        if path.startswith("/resource_groups/") and method == "GET":
            return 200, {
                "key": "chromium-android-checkout",
                "process_mode": self.resource_mode,
            }
        if path.startswith("/resource_groups/") and method == "PUT":
            self.resource_mode = body["process_mode"]
            return 200, {
                "key": "chromium-android-checkout",
                "process_mode": self.resource_mode,
            }
        raise AssertionError((method, path, expected, body))

    def request(self, method, path, *, expected, body=None):
        if "/repository/files/" not in path or "/raw?" not in path:
            raise AssertionError((method, path, expected, body))
        ref = path.split("ref=", 1)[1]
        name = path.split("/repository/files/", 1)[1].split("/raw?", 1)[0]
        return 200, self.pipeline_files[ref][Path(name.replace("%2F", "/"))]


class ReleasePipelineStateTest(unittest.TestCase):
    def inspect(self, client: FakeGitLab):
        return release_pipeline_state.inspect_release(
            client,
            ref="main",
            expected_release_id=RELEASE_ID,
            current_pipeline_id=1000,
        )

    def test_release_identity_is_derived_from_the_build_inputs(self):
        self.assertEqual(
            RELEASE_ID,
            release_pipeline_state.release_id_from_sources(RELEASE_SOURCES),
        )

    def test_changing_a_build_input_names_a_different_release(self):
        other = release_pipeline_state.release_id_from_sources(
            release_sources(patch=b"# patched differently\n")
        )
        self.assertNotEqual(RELEASE_ID, other)
        self.assertTrue(other.startswith(f"android-{VERSION}-"))

    def test_pipeline_from_an_older_identity_scheme_is_skipped(self):
        """It must not abort the scan; the nightly updater runs through this."""
        candidate = pipeline_record(16, "running")
        legacy = [
            {"key": "RUTHENIUM_SCHEDULE_TASK", "value": "release_update"},
            {"key": "RUTHENIUM_RELEASE_ID", "value": f"android-{VERSION}-r1"},
        ]
        client = FakeGitLab(pipelines=[candidate], variables={16: legacy})
        self.assertEqual("missing", self.inspect(client)["decision"])

    def test_private_marker_is_durable_completion_state(self):
        client = FakeGitLab(marker=True)
        self.assertEqual("complete", self.inspect(client)["decision"])
        self.assertFalse(any(path.startswith("/pipelines?") for _, path, _ in client.requests))

    def test_active_release_blocks_a_second_pipeline(self):
        candidate = pipeline_record(12, "running")
        client = FakeGitLab(
            pipelines=[candidate], variables={12: release_variables()}
        )
        result = self.inspect(client)
        self.assertEqual("active", result["decision"])
        self.assertEqual(12, result["pipeline_id"])

    def test_failed_release_is_retried(self):
        candidate = pipeline_record(13, "failed")
        client = FakeGitLab(
            pipelines=[candidate], variables={13: release_variables()}
        )
        self.assertEqual("retry", self.inspect(client)["decision"])

    def test_success_requires_every_build_and_publication_job(self):
        candidate = pipeline_record(14, "success")
        incomplete = successful_jobs()[:-1]
        client = FakeGitLab(
            pipelines=[candidate],
            variables={14: release_variables()},
            jobs={14: incomplete},
        )
        self.assertEqual("invalid", self.inspect(client)["decision"])
        client.jobs[14] = successful_jobs()
        self.assertEqual("complete_unmarked", self.inspect(client)["decision"])

    def test_old_release_pipeline_without_identity_variable_is_recognized(self):
        candidate = pipeline_record(15, "running")
        client = FakeGitLab(
            pipelines=[candidate],
            variables={15: release_variables(include_identity=False)},
            pipeline_files={SHA: RELEASE_SOURCES},
        )
        self.assertEqual("active", self.inspect(client)["decision"])

    def test_trigger_carries_release_identity_and_exact_commit(self):
        client = FakeGitLab()
        pipeline = release_pipeline_state.trigger_release(
            client, ref="main", commit_sha=SHA, expected_release_id=RELEASE_ID
        )
        self.assertEqual(900, pipeline["id"])
        request = next(body for method, path, body in client.requests if path == "/pipeline")
        values = {item["key"]: item["value"] for item in request["variables"]}
        self.assertEqual("release_update", values["RUTHENIUM_SCHEDULE_TASK"])
        self.assertEqual(RELEASE_ID, values["RUTHENIUM_RELEASE_ID"])

    def test_retry_keeps_original_pipeline_and_commit(self):
        candidate = pipeline_record(17, "failed")
        client = FakeGitLab(
            pipelines=[candidate], variables={17: release_variables()}
        )
        result = release_pipeline_state.retry_release(
            client,
            ref="main",
            pipeline_id=17,
            commit_sha=SHA,
            expected_release_id=RELEASE_ID,
        )
        self.assertEqual(17, result["id"])
        self.assertEqual(SHA, result["sha"])
        self.assertIn(("POST", "/pipelines/17/retry", None), client.requests)

    def test_marker_requires_all_jobs_and_resource_queue_is_oldest_first(self):
        candidate = pipeline_record(16, "running")
        client = FakeGitLab(pipelines=[candidate], jobs={16: successful_jobs()})
        marker = release_pipeline_state.mark_release(
            client,
            pipeline_id=16,
            commit_sha=SHA,
            expected_release_id=RELEASE_ID,
        )
        self.assertEqual(release_pipeline_state.marker_tag(RELEASE_ID), marker["name"])
        release_pipeline_state.ensure_resource_mode(
            client, "chromium-android-checkout", "oldest_first"
        )
        self.assertEqual("oldest_first", client.resource_mode)

    def test_cli_client_requires_private_mode(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            config = Path(temporary_directory) / "api.curl"
            config.write_text('header = "PRIVATE-TOKEN: fixture"\n')
            config.chmod(0o644)
            with self.assertRaisesRegex(
                release_pipeline_state.ReleaseStateError, "mode-0600"
            ):
                release_pipeline_state.GitLab(
                    "https://" + "gitlab.example/api/v4", 1, config
                )

    def test_plain_http_api_is_limited_to_private_literal_addresses(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            config = Path(temporary_directory) / "api.curl"
            config.write_text('header = "PRIVATE-TOKEN: fixture"\n')
            config.chmod(0o600)
            client = release_pipeline_state.GitLab(
                "http://" + "192." + "168.50.10/api/v4", 1, config
            )
            self.assertEqual("=http", client.curl_protocol)
            with self.assertRaisesRegex(
                release_pipeline_state.ReleaseStateError, "private or loopback"
            ):
                release_pipeline_state.GitLab(
                    "http://" + "8.8.8.8/api/v4", 1, config
                )


if __name__ == "__main__":
    unittest.main()
