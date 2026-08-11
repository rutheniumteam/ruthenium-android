import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from scripts import check_ministry_ca, patch_chromium


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CURRENT_CERTIFICATE = REPOSITORY_ROOT / "certificates/russian_trusted_root_ca.pem"
CURRENT_LOCK = REPOSITORY_ROOT / "certificates/ministry-ca-lock.json"


class MinistryCaUpdateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generated_directory = tempfile.TemporaryDirectory()
        root = Path(cls.generated_directory.name)
        cls.new_key = root / "new-root-key.pem"
        cls.new_certificate = root / "new-root.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:3072",
                "-nodes",
                "-sha256",
                "-days",
                "730",
                "-subj",
                "/C=RU/O=The Ministry of Digital Development and Communications/"
                "CN=Russian Trusted Root CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE,pathlen:4",
                "-addext",
                "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
                "-keyout",
                str(cls.new_key),
                "-out",
                str(cls.new_certificate),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    @classmethod
    def tearDownClass(cls):
        cls.generated_directory.cleanup()

    def test_checked_in_certificate_and_lock_are_valid(self):
        lock = check_ministry_ca.validate_locked_certificate(
            CURRENT_CERTIFICATE, CURRENT_LOCK
        )
        self.assertEqual(patch_chromium.EXPECTED_DER_SHA256, lock["der_sha256"])

    def test_same_official_copies_are_current(self):
        selection, candidate = check_ministry_ca.select_candidate(
            CURRENT_CERTIFICATE,
            CURRENT_CERTIFICATE,
            CURRENT_CERTIFICATE,
            CURRENT_LOCK,
        )
        self.assertEqual("current", selection["status"])
        self.assertEqual(CURRENT_CERTIFICATE.read_bytes(), candidate)

    def test_official_copies_must_agree_byte_for_byte_after_pem_decode(self):
        with self.assertRaisesRegex(
            check_ministry_ca.MinistryCaError, "do not contain the same DER"
        ):
            check_ministry_ca.select_candidate(
                self.new_certificate,
                CURRENT_CERTIFICATE,
                CURRENT_CERTIFICATE,
                CURRENT_LOCK,
            )

    def test_unexpected_certificate_identity_is_rejected(self):
        signing_certificate = REPOSITORY_ROOT / "signing/ruthenium-release-cert.pem"
        with self.assertRaisesRegex(
            check_ministry_ca.MinistryCaError, "unexpected subject or issuer"
        ):
            check_ministry_ca.validate_x509(signing_certificate)

    def test_valid_rollover_updates_lock_and_increments_same_version_release(self):
        selection, candidate = check_ministry_ca.select_candidate(
            self.new_certificate,
            self.new_certificate,
            CURRENT_CERTIFICATE,
            CURRENT_LOCK,
        )
        self.assertEqual("update", selection["status"])
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            certificate = root / "root.pem"
            lock = root / "lock.json"
            candidate_path = root / "candidate.pem"
            readme = root / "README.md"
            shutil.copyfile(CURRENT_CERTIFICATE, certificate)
            shutil.copyfile(CURRENT_LOCK, lock)
            candidate_path.write_bytes(candidate)
            readme.write_text(
                f"Pinned CA: {patch_chromium.EXPECTED_DER_SHA256}\n",
                encoding="utf-8",
            )

            check_ministry_ca.update_repository(
                selection,
                candidate_path,
                certificate,
                lock,
                readme,
            )

            new_der = patch_chromium.decode_pem(
                certificate.read_text(encoding="ascii")
            )
            new_sha256 = hashlib.sha256(new_der).hexdigest()
            updated_lock = json.loads(lock.read_text(encoding="utf-8"))
            self.assertEqual(selection["der_sha256"], new_sha256)
            self.assertEqual(new_sha256, updated_lock["der_sha256"])
            self.assertIn(new_sha256, readme.read_text())

    def test_certificate_update_leaves_the_pipeline_file_alone(self):
        """A CA rollover changes the trust lock, and nothing about the CI file."""
        self.assertNotIn("pipeline", check_ministry_ca.update_repository.__code__.co_varnames)

    def test_pipeline_accepts_the_exact_ca_only_file_set(self):
        pipeline = (REPOSITORY_ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
        self.assertIn('if [ "$CHROMIUM_CHANGED" = 1 ]; then', pipeline)
        self.assertIn('chromium_changed, ca_changed = sys.argv[6:8]', pipeline)
        self.assertIn('if chromium_changed == "1":', pipeline)
        self.assertIn('if ca_changed == "1":', pipeline)
        self.assertIn('set(changed) != expected', pipeline)


if __name__ == "__main__":
    unittest.main()
