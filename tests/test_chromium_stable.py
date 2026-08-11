import json
from pathlib import Path
import tempfile
import unittest

from scripts import check_chromium_stable


CURRENT_VERSION = "151.0.7922.71"
CURRENT_REVISION = "e" * 40


def response(*records: tuple[str, str, int]) -> bytes:
    return json.dumps(
        [
            {
                "channel": "Stable",
                "hashes": {"chromium": revision},
                "milestone": milestone,
                "platform": "Android",
                "version": version,
            }
            for version, revision, milestone in records
        ]
    ).encode("utf-8")


class ChromiumStableTest(unittest.TestCase):
    def test_selects_highest_android_stable_version_not_response_order(self):
        selected = check_chromium_stable.select_release(
            response(
                ("150.0.7000.99", "a" * 40, 150),
                ("151.0.7922.83", "b" * 40, 151),
                (CURRENT_VERSION, CURRENT_REVISION, 151),
            ),
            CURRENT_VERSION,
            CURRENT_REVISION,
        )
        self.assertEqual("update", selected["status"])
        self.assertEqual("151.0.7922.83", selected["version"])
        self.assertEqual("b" * 40, selected["revision"])
        self.assertEqual("7922", selected["branch"])

    def test_same_version_and_revision_is_current(self):
        selected = check_chromium_stable.select_release(
            response((CURRENT_VERSION, CURRENT_REVISION, 151)),
            CURRENT_VERSION,
            CURRENT_REVISION,
        )
        self.assertEqual("current", selected["status"])

    def test_same_version_with_changed_revision_fails_closed(self):
        with self.assertRaisesRegex(
            check_chromium_stable.StableReleaseError, "different revisions"
        ):
            check_chromium_stable.select_release(
                response((CURRENT_VERSION, "a" * 40, 151)),
                CURRENT_VERSION,
                CURRENT_REVISION,
            )

    def test_malformed_stable_record_fails_closed(self):
        with self.assertRaises(check_chromium_stable.StableReleaseError):
            check_chromium_stable.select_release(
                response(("151.0.7922.83", "not-a-hash", 151)),
                CURRENT_VERSION,
                CURRENT_REVISION,
            )

    def test_updates_only_the_release_lock(self):
        selection = check_chromium_stable.select_release(
            response(("151.0.7922.83", "b" * 40, 151)),
            CURRENT_VERSION,
            CURRENT_REVISION,
        )
        pipeline_text = (
            "variables:\n"
            f'  CHROMIUM_VERSION: "{CURRENT_VERSION}"\n'
            f'  CHROMIUM_REVISION: "{CURRENT_REVISION}"\n'
            '  CHROMIUM_BRANCH: "7922"\n'
            '  RUTHENIUM_APPLICATION_ID: "app.ruthenium.browser"\n'
            "job:\n  script:\n    - exit 0\n"
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            pipeline = Path(temporary_directory) / ".gitlab-ci.yml"
            pipeline.write_text(pipeline_text, encoding="utf-8")
            readme = Path(temporary_directory) / "README.md"
            readme.write_text(
                f"The build is pinned to Android Stable Chromium `{CURRENT_VERSION}`, revision\n"
                f"`{CURRENT_REVISION}`.\n\n"
                f"`artifacts/Ruthenium-{CURRENT_VERSION}-arm64-v8a.apk`\n",
                encoding="utf-8",
            )
            check_chromium_stable.update_repository(pipeline, readme, selection)
            updated = pipeline.read_text(encoding="utf-8")
            updated_readme = readme.read_text(encoding="utf-8")
        self.assertIn('CHROMIUM_VERSION: "151.0.7922.83"', updated)
        self.assertIn(f'CHROMIUM_REVISION: "{"b" * 40}"', updated)
        self.assertIn('CHROMIUM_BRANCH: "7922"', updated)
        self.assertIn('RUTHENIUM_APPLICATION_ID: "app.ruthenium.browser"', updated)
        self.assertIn("job:\n  script:\n    - exit 0", updated)
        self.assertIn("151.0.7922.83", updated_readme)
        self.assertIn("b" * 40, updated_readme)

    def test_daily_updater_is_single_flight_retryable_and_fail_closed(self):
        pipeline = (Path(__file__).resolve().parents[1] / ".gitlab-ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("update_release_inputs:", pipeline)
        self.assertIn("chromiumdash.appspot.com/fetch_releases", pipeline)
        self.assertIn("chromium.googlesource.com/chromium/src/+/refs/tags/", pipeline)
        self.assertIn("ChromiumDash revision does not match the official tag", pipeline)
        self.assertIn("content/lending/russian_trusted_root_ca_pem.crt", pipeline)
        self.assertIn("content/Other/doc/russian_trusted_root_ca.cer", pipeline)
        self.assertIn("scripts/check_ministry_ca.py select", pipeline)
        self.assertIn("/repository/commits", pipeline)
        self.assertIn("$COMMIT_MESSAGE [ci skip]", pipeline)
        self.assertIn('commit.get("parent_ids") != [sys.argv[2]]', pipeline)
        self.assertIn('git rev-parse "$LOCAL_COMMIT^{tree}"', pipeline)
        self.assertIn("scripts/release_pipeline_state.py inspect", pipeline)
        self.assertIn("scripts/release_pipeline_state.py trigger", pipeline)
        self.assertIn("scripts/release_pipeline_state.py retry", pipeline)
        self.assertIn("scripts/release_pipeline_state.py mark", pipeline)
        self.assertIn("--mode oldest_first", pipeline)
        self.assertIn('active)\n          echo "Release', pipeline)
        self.assertIn("Retrying release $CURRENT_RELEASE_ID", pipeline)
        self.assertIn("missing)", pipeline)
        self.assertIn("finalize_release:", pipeline)
        self.assertLess(
            pipeline.index("scripts/release_pipeline_state.py inspect"),
            pipeline.index("chromiumdash.appspot.com/fetch_releases"),
        )
        self.assertIn("RUTHENIUM_SCHEDULE_TASK == \"release_update\"", pipeline)
        self.assertIn("RUTHENIUM_GITLAB_RELEASE_TOKEN", pipeline)
        self.assertIn('GIT_AUTHOR_NAME="Ruthenium Project"', pipeline)
        self.assertGreaterEqual(
            pipeline.count('$RUTHENIUM_SCHEDULE_TASK == "check_release_inputs"'), 10
        )


if __name__ == "__main__":
    unittest.main()
