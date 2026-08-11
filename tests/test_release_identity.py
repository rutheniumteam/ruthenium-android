import json
from pathlib import Path
import tempfile
import unittest

from scripts import release_identity


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VERSION = "151.0.7922.108"
REVISION = "4" * 40
SIGNING_SHA256 = ":".join(["AB"] * 32)


def sources(**overrides: bytes) -> dict[Path, bytes]:
    value = {
        release_identity.PIPELINE_RELATIVE_PATH: (
            "variables:\n"
            f'  CHROMIUM_VERSION: "{VERSION}"\n'
            f'  CHROMIUM_REVISION: "{REVISION}"\n'
            '  RUTHENIUM_APPLICATION_ID: "app.ruthenium.browser"\n'
            f'  RUTHENIUM_SIGNING_CERT_SHA256: "{SIGNING_SHA256}"\n'
        ).encode(),
        release_identity.LOCK_RELATIVE_PATH: json.dumps(
            {"der_sha256": "d" * 64}
        ).encode(),
        Path("build/args.gn"): b'target_os = "android"\n',
        Path("scripts/patch_chromium.py"): b"# patch\n",
    }
    value.update({Path(key.replace("__", "/")): data for key, data in overrides.items()})
    return value


def identity(**overrides: bytes) -> str:
    return release_identity.release_id(release_identity.release_inputs(sources(**overrides)))


class ReleaseIdentityTest(unittest.TestCase):
    def test_identity_is_pinned_to_this_algorithm(self):
        """A silent change here would rename every release for no reason."""
        self.assertEqual(
            "android-151.0.7922.108-ca-dddddddddddd-8d2cf64ab8e5", identity()
        )

    def test_every_build_input_moves_the_identity(self):
        baseline = identity()
        changed = {
            "scripts__patch_chromium.py": b"# a different patch\n",
            "build__args.gn": b'target_os = "android"\nis_debug = true\n',
            "certificates__ministry-ca-lock.json": json.dumps(
                {"der_sha256": "e" * 64}
            ).encode(),
            ".gitlab-ci.yml": (
                "variables:\n"
                f'  CHROMIUM_VERSION: "{VERSION}"\n'
                f'  CHROMIUM_REVISION: "{"5" * 40}"\n'
                '  RUTHENIUM_APPLICATION_ID: "app.ruthenium.browser"\n'
                f'  RUTHENIUM_SIGNING_CERT_SHA256: "{SIGNING_SHA256}"\n'
            ).encode(),
        }
        for name, data in changed.items():
            with self.subTest(input=name):
                self.assertNotEqual(baseline, identity(**{name: data}))

    def test_identity_names_the_chromium_version_it_builds(self):
        self.assertTrue(identity().startswith(f"android-{VERSION}-"))
        self.assertTrue(release_identity.RELEASE_ID_RE.fullmatch(identity()))

    def test_identity_names_the_ministry_ca_it_builds(self):
        self.assertIn("-ca-dddddddddddd-", identity())
        changed = identity(
            **{
                "certificates__ministry-ca-lock.json": json.dumps(
                    {"der_sha256": "e" * 64}
                ).encode()
            }
        )
        self.assertIn("-ca-eeeeeeeeeeee-", changed)

    def test_malformed_inputs_are_refused(self):
        cases = {
            "certificates__ministry-ca-lock.json": b"{}",
            ".gitlab-ci.yml": b"variables:\n",
        }
        for name, data in cases.items():
            with self.subTest(input=name):
                with self.assertRaises(release_identity.ReleaseIdentityError):
                    identity(**{name: data})

    def test_missing_input_is_refused(self):
        incomplete = sources()
        del incomplete[Path("build/args.gn")]
        with self.assertRaises(release_identity.ReleaseIdentityError):
            release_identity.release_inputs(incomplete)

    def test_this_repository_resolves_to_a_valid_identity(self):
        value = release_identity.release_id(
            release_identity.release_inputs(
                release_identity.read_sources(REPOSITORY_ROOT)
            )
        )
        self.assertTrue(release_identity.RELEASE_ID_RE.fullmatch(value))

    def test_every_hashed_input_is_published(self):
        """The identity is only verifiable if its inputs are public."""
        allowlist = set(
            (REPOSITORY_ROOT / ".public-files").read_text(encoding="utf-8").split()
        )
        for path in release_identity.INPUT_RELATIVE_PATHS:
            with self.subTest(input=path.as_posix()):
                self.assertIn(path.as_posix(), allowlist)

    def test_symlinked_input_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for path, data in sources().items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            replaced = root / "build/args.gn"
            replaced.unlink()
            replaced.symlink_to(root / "scripts/patch_chromium.py")
            with self.assertRaises(release_identity.ReleaseIdentityError):
                release_identity.read_sources(root)


if __name__ == "__main__":
    unittest.main()
