import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from scripts import public_snapshot


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class PublicSnapshotTest(unittest.TestCase):
    def initialize_repository(self, root: Path, files: dict[str, bytes]) -> None:
        subprocess.run(
            [str(public_snapshot.GIT_PATH), "init", "--quiet", "--initial-branch=main"],
            cwd=root,
            check=True,
        )
        subprocess.run(
            [str(public_snapshot.GIT_PATH), "config", "user.name", "Snapshot Test"],
            cwd=root,
            check=True,
        )
        subprocess.run(
            [
                str(public_snapshot.GIT_PATH),
                "config",
                "user.email",
                "snapshot-test" + "@" + "localhost.invalid",
            ],
            cwd=root,
            check=True,
        )
        for relative_path, data in files.items():
            path = root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            if relative_path.endswith(".sh"):
                path.chmod(0o755)
        subprocess.run(
            [str(public_snapshot.GIT_PATH), "add", "--all"], cwd=root, check=True
        )
        subprocess.run(
            [str(public_snapshot.GIT_PATH), "commit", "--quiet", "-m", "fixture"],
            cwd=root,
            check=True,
        )

    def test_snapshot_is_deterministic_and_normalized(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            manifest = b".public-files\nREADME.md\nscripts/run.sh\n"
            self.initialize_repository(
                root,
                {
                    ".public-files": manifest,
                    "README.md": b"Public fixture\n",
                    "scripts/run.sh": b"#!/usr/bin/env bash\nexit 0\n",
                },
            )
            first = root / "first.tar"
            second = root / "second.tar"
            first_report = root / "first.json"
            second_report = root / "second.json"
            report = public_snapshot.create_archive(
                root, "HEAD", first, first_report
            )
            public_snapshot.create_archive(root, "HEAD", second, second_report)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_report.read_bytes(), second_report.read_bytes())
            verified = public_snapshot.verify_archive(
                first, str(report["archive_sha256"])
            )
            self.assertEqual(3, verified["file_count"])
            with tarfile.open(fileobj=io.BytesIO(first.read_bytes()), mode="r:") as archive:
                for member in archive.getmembers():
                    self.assertEqual(0, member.uid)
                    self.assertEqual(0, member.gid)
                    self.assertEqual(0, member.mtime)
                    self.assertIn(member.mode, {0o644, 0o755})

    def test_unlisted_tracked_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.initialize_repository(
                root,
                {
                    ".public-files": b".public-files\nREADME.md\n",
                    "README.md": b"Public fixture\n",
                    "unreviewed.txt": b"must not publish silently\n",
                },
            )
            with self.assertRaisesRegex(public_snapshot.SnapshotError, "unlisted"):
                public_snapshot.create_archive(
                    root, "HEAD", root / "snapshot.tar", root / "report.json"
                )

    def test_symlink_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.initialize_repository(
                root,
                {
                    ".public-files": b".public-files\nREADME.md\nlink\n",
                    "README.md": b"Public fixture\n",
                },
            )
            (root / "link").symlink_to("README.md")
            subprocess.run(
                [str(public_snapshot.GIT_PATH), "add", "link"], cwd=root, check=True
            )
            subprocess.run(
                [
                    str(public_snapshot.GIT_PATH),
                    "commit",
                    "--quiet",
                    "-m",
                    "add link",
                ],
                cwd=root,
                check=True,
            )
            with self.assertRaisesRegex(public_snapshot.SnapshotError, "regular files"):
                public_snapshot.create_archive(
                    root, "HEAD", root / "snapshot.tar", root / "report.json"
                )

    def test_identity_and_secret_markers_fail_closed(self):
        forbidden_values = (
            "/" + "Users/private-operator/signing/key\n",
            "https://" + "gitlab.internal.example/operator/project/repository\n",
            "contact operator" + "@" + "example.net\n",
            "address " + "192.168" + ".12.7\n",
            "github_pat_" + "A" * 40 + "\n",
            "-----BEGIN " + "PRIVATE KEY-----\n",
            "hidden\u202ename\n",
        )
        for value in forbidden_values:
            with self.subTest(value=value):
                with self.assertRaises(public_snapshot.SnapshotError):
                    public_snapshot.scan_text("README.md", value.encode("utf-8"))

    def test_svg_doctype_is_rejected_before_xml_parsing(self):
        svg = (
            '<!DOCTYPE svg [<!ENTITY sample "expanded">]>\n'
            '<svg xmlns="http://www.w3.org/2000/svg">&sample;</svg>\n'
        )
        with self.assertRaisesRegex(public_snapshot.SnapshotError, "active content"):
            public_snapshot.scan_text("image.svg", svg.encode("utf-8"))

    def test_current_manifest_exactly_matches_tracked_files(self):
        tracked = subprocess.run(
            [str(public_snapshot.GIT_PATH), "ls-files", "-z"],
            cwd=REPOSITORY_ROOT,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        tracked_paths = sorted(
            item.decode("utf-8") for item in tracked.split(b"\0") if item
        )
        manifest = public_snapshot.parse_manifest(
            (REPOSITORY_ROOT / public_snapshot.MANIFEST_PATH).read_bytes()
        )
        self.assertEqual(tracked_paths, manifest)

    def test_publisher_has_anonymous_fail_closed_boundary(self):
        publisher = (
            REPOSITORY_ROOT / "scripts/publish_github_snapshot.sh"
        ).read_text(encoding="utf-8")
        pipeline = (REPOSITORY_ROOT / ".gitlab-ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("ruthenium-publisher", publisher)
        self.assertIn("RUTHENIUM_TOR_VERIFIED", publisher)
        self.assertIn("127.0.0.1:9050", publisher)
        self.assertIn("commit-tree", publisher)
        self.assertIn("ls-remote --exit-code --heads", publisher)
        self.assertIn('if [ "$REMOTE_STATUS" -ne 2 ]', publisher)
        self.assertIn('COMMIT_TREE_ARGS=("$PUBLIC_TREE")', publisher)
        self.assertIn("Ruthenium Project", publisher)
        self.assertIn("ruthenium-project@localhost.invalid", publisher)
        self.assertIn("PUBLICATION_VERIFICATION=PASS", publisher)
        self.assertNotIn("push --force", publisher)
        self.assertNotIn("force-with-lease", publisher)
        self.assertIn("publish_github_snapshot:", pipeline)
        self.assertIn("RUTHENIUM_SCHEDULE_TASK", pipeline)
        self.assertIn("/usr/local/bin/ruthenium-with-tor", pipeline)
        self.assertIn("/usr/local/libexec/ruthenium/publish_github_snapshot.sh", pipeline)


if __name__ == "__main__":
    unittest.main()
