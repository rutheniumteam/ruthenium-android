import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import os
import sys
import tempfile
import unittest
import zipfile

from scripts import patch_chromium, prepare_github_release, publish_github_release


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _runner_env() -> dict[str, str]:
    """The runner has no PYTHONPATH; inheriting one hides import failures."""
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return env
VERSION = "151.0.7922.71"
REVISION = "ef35003457e93c278f911a334b06e4a5f8967e06"
ABI = "arm64-v8a"
TARGET_CPU = "arm64"
APPLICATION_ID = "app.ruthenium.browser"
SIGNING_FINGERPRINT = (
    "38:F8:1A:A5:46:4B:33:12:3F:1F:38:25:1D:8A:17:96:31:F3:9B:FE:"
    "92:A6:BA:F7:22:4E:B2:40:E9:90:37:39"
)
SOURCE_SNAPSHOT_SHA256 = "a" * 64
ASSET_URL = (
    "https://api.github.com/repos/rutheniumteam/ruthenium-android/releases/assets/1"
)
MINISTRY_CA_DER_SHA256 = patch_chromium.EXPECTED_DER_SHA256
RELEASE_ID = (
    f"android-{VERSION}-ca-{MINISTRY_CA_DER_SHA256[:12]}-0123456789ab"
)


class ReleasePublicationTest(unittest.TestCase):
    def make_artifacts(self, directory: Path) -> Path:
        artifacts = directory / "artifacts"
        artifacts.mkdir()
        apk_name = f"Ruthenium-{VERSION}-{ABI}.apk"
        apk = artifacts / apk_name
        with zipfile.ZipFile(apk, mode="w") as archive:
            archive.writestr("AndroidManifest.xml", b"fixture")
            archive.writestr(f"lib/{ABI}/libruthenium.so", b"native fixture")
        apk_sha256 = hashlib.sha256(apk.read_bytes()).hexdigest()
        (artifacts / f"{apk_name}.sha256").write_text(
            f"{apk_sha256}  {apk_name}\n", encoding="utf-8"
        )
        (artifacts / "apk-abis.txt").write_text(f"{ABI}\n", encoding="utf-8")
        (artifacts / "aapt2-badging.txt").write_text(
            f"package: name='{APPLICATION_ID}' versionCode='1'\n"
            "application-label:'Ruthenium'\n",
            encoding="utf-8",
        )
        normalized_fingerprint = SIGNING_FINGERPRINT.replace(":", "").lower()
        (artifacts / "apksigner-verification.txt").write_text(
            f"Signer #1 certificate SHA-256 digest: {normalized_fingerprint}\n",
            encoding="utf-8",
        )
        (artifacts / "build-info.txt").write_text(
            prepare_github_release.expected_build_info(
                version=VERSION,
                revision=REVISION,
                release_id=RELEASE_ID,
                abi=ABI,
                target_cpu=TARGET_CPU,
                application_id=APPLICATION_ID,
                ministry_ca_der_sha256=MINISTRY_CA_DER_SHA256,
                signing_fingerprint=SIGNING_FINGERPRINT,
            ),
            encoding="utf-8",
        )
        (artifacts / "Chromium-LICENSE.txt").write_text(
            "Chromium fixture license\n", encoding="utf-8"
        )
        (artifacts / "ruthenium-release-cert.pem").write_bytes(
            (REPOSITORY_ROOT / "signing/ruthenium-release-cert.pem").read_bytes()
        )
        return artifacts

    def create_bundle(self, root: Path) -> Path:
        artifacts = self.make_artifacts(root)
        bundle = root / "bundle"
        prepare_github_release.create_bundle(
            artifacts=artifacts,
            output=bundle,
            version=VERSION,
            revision=REVISION,
            release_id=RELEASE_ID,
            abi=ABI,
            target_cpu=TARGET_CPU,
            application_id=APPLICATION_ID,
            ministry_ca_der_sha256=MINISTRY_CA_DER_SHA256,
            signing_fingerprint=SIGNING_FINGERPRINT,
            source_snapshot_sha256=SOURCE_SNAPSHOT_SHA256,
        )
        return bundle

    def test_release_bundle_is_exact_and_self_verifying(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            bundle = self.create_bundle(Path(temporary_directory))
            manifest = prepare_github_release.verify_bundle(bundle)
            self.assertEqual(RELEASE_ID, manifest["release_tag"])
            self.assertEqual(ABI, manifest["abi"])
            self.assertEqual(8, len(manifest["assets"]))
            expected_files = {"bundle.json"} | {
                asset["name"] for asset in manifest["assets"]
            }
            self.assertEqual(expected_files, {path.name for path in bundle.iterdir()})

    def test_modified_release_asset_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            bundle = self.create_bundle(Path(temporary_directory))
            build_info = bundle / f"Ruthenium-{VERSION}-{ABI}-build-info.txt"
            build_info.write_text("modified\n", encoding="utf-8")
            with self.assertRaisesRegex(
                prepare_github_release.ReleaseBundleError, "does not match manifest"
            ):
                prepare_github_release.verify_bundle(bundle)

    def test_unexpected_build_artifact_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifacts = self.make_artifacts(root)
            (artifacts / "debug-symbols.zip").write_bytes(b"not reviewed")
            with self.assertRaisesRegex(
                prepare_github_release.ReleaseBundleError, "artifact set mismatch"
            ):
                prepare_github_release.create_bundle(
                    artifacts=artifacts,
                    output=root / "bundle",
                    version=VERSION,
                    revision=REVISION,
                    release_id=RELEASE_ID,
                    abi=ABI,
                    target_cpu=TARGET_CPU,
                    application_id=APPLICATION_ID,
                    ministry_ca_der_sha256=MINISTRY_CA_DER_SHA256,
                    signing_fingerprint=SIGNING_FINGERPRINT,
                    source_snapshot_sha256=SOURCE_SNAPSHOT_SHA256,
                )

    def test_release_publisher_and_ci_are_fail_closed(self):
        publisher = (REPOSITORY_ROOT / "scripts/publish_github_release.py").read_text(
            encoding="utf-8"
        )
        pipeline = (REPOSITORY_ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
        self.assertIn("RUTHENIUM_TOR_VERIFIED", publisher)
        self.assertIn("ruthenium-publisher", publisher)
        self.assertIn("127\\.0\\.0\\.1:9050", publisher)
        self.assertIn("download_in_new_circuit", publisher)
        self.assertNotIn("DELETE", publisher)
        self.assertNotIn("requests.", publisher)
        for suffix in ("arm64", "armv7", "x86_64"):
            self.assertIn(f"publish_github_release_{suffix}:", pipeline)
        self.assertNotIn("publish_github_release_x86:", pipeline)
        self.assertNotIn("build_x86:", pipeline)
        self.assertIn("  - release\n", pipeline)
        self.assertIn("dependencies:\n    - build_armv7", pipeline)
        self.assertIn("resource_group: github-publication", pipeline)
        self.assertIn("scripts/prepare_github_release.py verify", pipeline)
        self.assertIn("/usr/local/bin/ruthenium-with-tor", pipeline)
        self.assertIn("--v4-signing-enabled false", pipeline)
        self.assertIn("/usr/bin/python3 -u", pipeline)
        with_tor = (REPOSITORY_ROOT / "scripts/with_tor.sh").read_text(encoding="utf-8")
        self.assertIn("RUTHENIUM_TOR_VERIFIED=1", with_tor)
        self.assertIn("socks5h://", with_tor)
        # The proxy must be exported only inside the branch that verified it,
        # so a command never runs on an unverified circuit.
        verified_block = with_tor.split("IsTor", 1)[1]
        self.assertIn("export ALL_PROXY", verified_block)
        self.assertNotIn("export ALL_PROXY", with_tor.split("IsTor", 1)[0])

    def test_artifact_reuse_is_keyed_on_everything_that_shapes_the_apk(self):
        pipeline = (REPOSITORY_ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
        key_block = pipeline.split("ARTIFACT_CACHE_KEY=\"$(", 1)[1].split(
            "export ARTIFACT_CACHE_KEY", 1
        )[0]
        for component in (
            "$RELEASE_DIGEST",
            "$ANDROID_ABI",
            "$TARGET_CPU",
        ):
            self.assertIn(component, key_block)
        self.assertNotIn("$RUTHENIUM_RELEASE_ID", key_block)
        self.assertIn('test ! -e "$RELEASE_APK.idsig"', pipeline)

    def test_cached_apk_gets_current_release_metadata_without_rebuild(self):
        pipeline = (REPOSITORY_ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
        reuse_block = pipeline.split(
            'if [ -f "$ARTIFACT_CACHE_DIR/$RELEASE_APK_NAME.sha256" ]; then', 1
        )[1].split("exit 0", 1)[0]
        self.assertIn('cp -a "$ARTIFACT_CACHE_DIR/."', reuse_block)
        self.assertIn("write_build_info build-info.txt", reuse_block)
        self.assertLess(
            reuse_block.index('cp -a "$ARTIFACT_CACHE_DIR/."'),
            reuse_block.index("write_build_info build-info.txt"),
        )
        self.assertNotIn("autoninja", reuse_block)
        self.assertEqual(2, pipeline.count("write_build_info build-info.txt"))
        self.assertEqual(1, pipeline.count("printf 'Product Ruthenium"))

    def test_release_asset_namespace_rejects_unexpected_files(self):
        with self.assertRaisesRegex(
            publish_github_release.ReleasePublicationError, "unexpected assets"
        ):
            publish_github_release.validate_asset_namespace(
                [{"name": "unreviewed-debug-symbols.zip"}], VERSION
            )

    def _download(self, curl_exit_codes, output):
        """Drive download_in_new_circuit with curl stubbed out."""
        calls = []
        remaining = list(curl_exit_codes)

        class Result:
            def __init__(self, returncode):
                self.returncode = returncode

        def fake_run(command, *args, **kwargs):
            calls.append(command)
            output.write_bytes(b"partial")
            return Result(remaining.pop(0))

        original = publish_github_release.subprocess.run
        publish_github_release.subprocess.run = fake_run
        try:
            publish_github_release.download_in_new_circuit(
                url=ASSET_URL, output=output, auth_config=None
            )
        finally:
            publish_github_release.subprocess.run = original
        return calls

    def test_broken_download_resumes_in_a_new_circuit(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "asset"
            calls = self._download([92, 0], output)
        self.assertEqual(2, len(calls))
        self.assertNotIn("--continue-at", calls[0])
        self.assertIn("--continue-at", calls[1])

    def test_download_that_keeps_breaking_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "asset"
            with self.assertRaisesRegex(
                publish_github_release.ReleasePublicationError, "after 4 attempts"
            ):
                self._download([92] * 4, output)

    def test_download_restarts_when_the_server_refuses_a_range(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "asset"
            calls = self._download([92, 33, 0], output)
        self.assertNotIn("--continue-at", calls[0])
        self.assertIn("--continue-at", calls[1])
        self.assertNotIn("--continue-at", calls[2])

    def test_download_refuses_an_unexpected_url(self):
        with self.assertRaisesRegex(
            publish_github_release.ReleasePublicationError, "refusing unexpected"
        ):
            publish_github_release.download_in_new_circuit(
                url="https://example.invalid/asset",
                output=Path("/nonexistent"),
                auth_config=None,
            )

    def test_every_script_ci_runs_imports_standalone(self):
        """CI runs `python3 scripts/X.py`, which does not put the root on sys.path."""
        pipeline = (REPOSITORY_ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
        names = sorted(set(re.findall(r"python3 scripts/(\w+\.py)", pipeline)))
        self.assertIn("release_pipeline_state.py", names)
        for name in names:
            with self.subTest(script=name):
                result = subprocess.run(
                    [sys.executable, f"scripts/{name}", "--help"],
                    cwd=REPOSITORY_ROOT,
                    capture_output=True,
                    text=True,
                    env=_runner_env(),
                )
                self.assertEqual(0, result.returncode, result.stderr)

    def test_publisher_directory_has_every_module_it_imports(self):
        """The publisher runs these scripts flat, outside the scripts package.

        A module added to an import here but not to the install list fails only
        on the runner, after the build, inside the Tor boundary.
        """
        pipeline = (REPOSITORY_ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
        blocks = re.findall(
            r"sudo install -o root -g root -m 0755 \\\n(.*?)/usr/local/libexec/ruthenium/",
            pipeline,
            re.DOTALL,
        )
        block = next(b for b in blocks if "publish_github_release.py" in b)
        installed = re.findall(r"scripts/(\w+\.py)", block)
        self.assertIn("publish_github_release.py", installed)
        with tempfile.TemporaryDirectory() as temporary_directory:
            libexec = Path(temporary_directory)
            for name in set(installed):
                shutil.copyfile(REPOSITORY_ROOT / "scripts" / name, libexec / name)
            result = subprocess.run(
                [sys.executable, "-c", "import publish_github_release"],
                cwd=libexec,
                capture_output=True,
                text=True,
                env=_runner_env(),
            )
        self.assertEqual(0, result.returncode, result.stderr)

    def test_release_title_names_the_version_and_ca(self):
        manifest = {
            "chromium_version": VERSION,
            "release_tag": RELEASE_ID,
            "ministry_ca_der_sha256": MINISTRY_CA_DER_SHA256,
        }
        self.assertEqual(
            f"Ruthenium {VERSION} (CA {MINISTRY_CA_DER_SHA256[:12]})",
            publish_github_release.release_title(manifest),
        )

    def test_release_title_has_one_definition(self):
        source = (
            REPOSITORY_ROOT / "scripts/publish_github_release.py"
        ).read_text(encoding="utf-8")
        # Written on create and checked on validate; more copies of the same
        # string is how the draft tag drifted before.
        self.assertEqual(2, source.count("release_title(manifest)"))

    def test_release_notes_do_not_name_the_source_snapshot(self):
        """Notes pinned to a moving snapshot locked later ABIs out of a release."""
        manifest = {
            "chromium_version": VERSION,
            "chromium_revision": REVISION,
            "release_tag": RELEASE_ID,
            "ministry_ca_der_sha256": MINISTRY_CA_DER_SHA256,
            "source_snapshot_sha256": SOURCE_SNAPSHOT_SHA256,
        }
        body = publish_github_release.release_body(manifest)
        self.assertNotIn(SOURCE_SNAPSHOT_SHA256, body)
        self.assertIn(RELEASE_ID, body)
        self.assertIn(REVISION, body)

    def test_provenance_is_a_function_of_the_release_inputs(self):
        """Equal inputs must reproduce it, or a republish collides with itself."""
        manifest = {
            "abi": ABI,
            "chromium_version": VERSION,
            "release_tag": RELEASE_ID,
            "schema_version": 1,
            "source_snapshot_sha256": SOURCE_SNAPSHOT_SHA256,
        }
        moved = dict(manifest, source_snapshot_sha256="e" * 64)
        self.assertEqual(
            publish_github_release.provenance(manifest),
            publish_github_release.provenance(moved),
        )
        _, data = publish_github_release.provenance(manifest)
        self.assertNotIn(SOURCE_SNAPSHOT_SHA256.encode(), data)

    def test_matching_asset_digest_confirms_content(self):
        asset = {"id": 7, "size": 12, "state": "uploaded", "digest": f"sha256:{'b' * 64}"}
        self.assertTrue(
            publish_github_release.validate_metadata(asset, "b" * 64, 12)
        )

    def test_asset_digest_mismatch_fails_closed(self):
        asset = {"id": 7, "size": 12, "state": "uploaded", "digest": f"sha256:{'b' * 64}"}
        with self.assertRaisesRegex(
            publish_github_release.ReleasePublicationError, "digest does not match"
        ):
            publish_github_release.validate_metadata(asset, "c" * 64, 12)

    def test_absent_asset_digest_is_not_a_passing_check(self):
        asset = {"id": 7, "size": 12, "state": "uploaded"}
        self.assertFalse(
            publish_github_release.validate_metadata(asset, "b" * 64, 12)
        )

    def test_unusable_asset_digest_fails_closed(self):
        for digest in (f"md5:{'b' * 32}", "sha256:not-hexadecimal", f"sha256:{'B' * 64}", 5):
            with self.assertRaises(publish_github_release.ReleasePublicationError):
                publish_github_release.asset_sha256({"digest": digest})

    def test_asset_metadata_mismatch_fails_before_the_digest(self):
        digest = f"sha256:{'b' * 64}"
        for asset in (
            {"id": 7, "size": 13, "state": "uploaded", "digest": digest},
            {"id": 7, "size": 12, "state": "starting", "digest": digest},
        ):
            with self.assertRaisesRegex(
                publish_github_release.ReleasePublicationError, "metadata does not match"
            ):
                publish_github_release.validate_metadata(asset, "b" * 64, 12)

    def _confirm_asset_with_recorded_download(self, asset, refreshed):
        calls = []

        class FakeGitHub:
            def json(self, method, url, *, expected, body=None):
                calls.append(f"GET {url}")
                return 200, refreshed

        def fake_validate_download(
            asset, expected_sha256, expected_size, workspace, auth_config
        ):
            calls.append("download")

        original = publish_github_release.validate_download
        publish_github_release.validate_download = fake_validate_download
        try:
            result = publish_github_release.confirm_asset(
                github=FakeGitHub(),
                asset=asset,
                expected_sha256="b" * 64,
                expected_size=12,
                workspace=Path("/nonexistent"),
                auth_config=Path("/nonexistent"),
            )
        finally:
            publish_github_release.validate_download = original
        return result, calls

    def test_confirmed_digest_avoids_transferring_the_asset(self):
        asset = {"id": 7, "size": 12, "state": "uploaded", "digest": f"sha256:{'b' * 64}"}
        _, calls = self._confirm_asset_with_recorded_download(asset, refreshed={})
        self.assertEqual([], calls)

    def test_asset_without_digest_is_refetched_then_downloaded(self):
        asset = {"id": 7, "size": 12, "state": "uploaded"}
        _, calls = self._confirm_asset_with_recorded_download(
            asset, refreshed=dict(asset)
        )
        self.assertEqual(
            [
                "GET https://api.github.com/repos/rutheniumteam/"
                "ruthenium-android/releases/assets/7",
                "download",
            ],
            calls,
        )

    def test_digest_that_appears_on_refetch_avoids_the_download(self):
        asset = {"id": 7, "size": 12, "state": "uploaded"}
        refreshed = dict(asset, digest=f"sha256:{'b' * 64}")
        result, calls = self._confirm_asset_with_recorded_download(asset, refreshed)
        self.assertNotIn("download", calls)
        self.assertEqual(refreshed, result)

    def test_refetch_must_return_the_same_asset(self):
        asset = {"id": 7, "size": 12, "state": "uploaded"}
        with self.assertRaisesRegex(
            publish_github_release.ReleasePublicationError, "different release asset"
        ):
            self._confirm_asset_with_recorded_download(
                asset, refreshed={"id": 9, "size": 12, "state": "uploaded"}
            )

    def test_public_download_check_is_never_reduced_to_metadata(self):
        source = (
            REPOSITORY_ROOT / "scripts/publish_github_release.py"
        ).read_text(encoding="utf-8")
        check = source.split("def independent_release_check", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("validate_download(", check)
        self.assertIn("auth_config=None", check)
        self.assertNotIn("validate_metadata", check)

    def test_public_source_commit_must_name_exact_snapshot(self):
        class FakeGitHub:
            def json(self, method, url, *, expected, body=None):
                self.method = method
                self.url = url
                self.expected = expected
                self.body = body
                return 200, {
                    "sha": "1" * 40,
                    "commit": {
                        "message": "Publish source snapshot\n\nSnapshot-SHA256: "
                        + SOURCE_SNAPSHOT_SHA256,
                        "tree": {"sha": "2" * 40},
                    },
                }

        fake = FakeGitHub()
        commit, tree = publish_github_release.github_main(
            fake, SOURCE_SNAPSHOT_SHA256
        )
        self.assertEqual("1" * 40, commit)
        self.assertEqual("2" * 40, tree)
        with self.assertRaisesRegex(
            publish_github_release.ReleasePublicationError, "does not match"
        ):
            publish_github_release.github_main(fake, "b" * 64)

    def test_github_client_refuses_non_repository_urls_before_curl(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            github = publish_github_release.GitHub(root / "auth", root)
            with self.assertRaisesRegex(
                publish_github_release.ReleasePublicationError,
                "unexpected GitHub URL",
            ):
                github.request("GET", "https://example.invalid/not-github")


if __name__ == "__main__":
    unittest.main()
