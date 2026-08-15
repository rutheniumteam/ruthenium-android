import base64
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from scripts import fetch_ministry_ca, patch_chromium


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CERTIFICATE_PATH = (
    REPOSITORY_ROOT / patch_chromium.CERTIFICATE_RELATIVE_PATH
)


class PatchChromiumTest(unittest.TestCase):
    def test_production_build_arguments(self):
        args = (REPOSITORY_ROOT / "build/args.gn").read_text(encoding="utf-8")
        self.assertIn("is_official_build = true", args)
        self.assertIn("chrome_pgo_phase = 0", args)
        self.assertIn("clang_use_default_sample_profile = false", args)
        self.assertIn("enable_vr = false", args)
        self.assertIn("disable_fieldtrial_testing_config = true", args)
        self.assertIn("generate_about_credits = true", args)

    def test_build_log_keeps_errors_without_exhausting_gitlab_trace(self):
        pipeline = (REPOSITORY_ROOT / ".gitlab-ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("autoninja -C", pipeline)
        self.assertIn("2>&1", pipeline)
        self.assertIn("/\\[[0-9]+\\/[0-9]+\\]/", pipeline)
        self.assertNotIn("/^\\[[0-9]+\\/[0-9]+\\]/", pipeline)
        self.assertIn("progress % 250", pipeline)
        self.assertIn("{ print; fflush() }", pipeline)

    def test_architecture_build_caches_are_independent(self):
        pipeline = (REPOSITORY_ROOT / ".gitlab-ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('out/$OUTPUT_DIRECTORY', pipeline)
        for output_directory in (
            "RuCaArm64",
            "RuCaArmv7",
            "RuCaX64",
        ):
            self.assertEqual(
                2,
                pipeline.count(output_directory),
                output_directory,
            )
        self.assertNotIn('rm -rf "$CHROMIUM_WORK_DIR/src/out/', pipeline)
        self.assertIn(
            'git cat-file -e "${CHROMIUM_REVISION}^{commit}"', pipeline
        )

    def test_armv7_build_precedes_other_architectures(self):
        pipeline = (REPOSITORY_ROOT / ".gitlab-ci.yml").read_text(
            encoding="utf-8"
        )
        arm64_start = pipeline.index("build_arm64:")
        arm64_end = pipeline.index("\n\nbuild_armv7:", arm64_start)
        x64_start = pipeline.index("build_x86_64:")
        x64_end = pipeline.index("\n\ngithub_preflight:", x64_start)
        for block in (
            pipeline[arm64_start:arm64_end],
            pipeline[x64_start:x64_end],
        ):
            self.assertIn("- job: build_armv7", block)
            self.assertIn("artifacts: false", block)

    def test_main_branch_runs_the_complete_release_automatically(self):
        pipeline = (REPOSITORY_ROOT / ".gitlab-ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("workflow:\n", pipeline)
        self.assertIn(
            "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH && "
            "$RUTHENIUM_SCHEDULE_TASK == null",
            pipeline,
        )
        self.assertIn('RUTHENIUM_SCHEDULE_TASK: "release_update"', pipeline)
        for job in (
            "build_armv7",
            "build_x86_64",
            "publish_github_release_arm64",
            "publish_github_release_armv7",
            "publish_github_release_x86_64",
            "finalize_release",
        ):
            start = pipeline.index(f"{job}:")
            end = pipeline.find("\n\n", start)
            if end == -1:
                end = len(pipeline)
            block = pipeline[start:end]
            self.assertIn(
                '$RUTHENIUM_SCHEDULE_TASK == "release_update"',
                block,
                job,
            )
            self.assertIn("when: on_success", block, job)
        arm64_start = pipeline.index("build_arm64:")
        arm64_end = pipeline.index("\n\nbuild_armv7:", arm64_start)
        self.assertIn("when: on_success", pipeline[arm64_start:arm64_end])

    def test_build_dependencies_cannot_leave_lighttpd_running(self):
        pipeline = (REPOSITORY_ROOT / ".gitlab-ci.yml").read_text(
            encoding="utf-8"
        )
        install_index = pipeline.index("build/install-build-deps.sh")
        stop_index = pipeline.index("sudo systemctl stop lighttpd", install_index)
        active_check_index = pipeline.index(
            "systemctl is-active --quiet lighttpd", stop_index
        )
        self.assertLess(install_index, stop_index)
        self.assertLess(stop_index, active_check_index)

    def test_ci_creates_secret_files_with_private_umask(self):
        pipeline = (REPOSITORY_ROOT / ".gitlab-ci.yml").read_text(
            encoding="utf-8"
        )
        build_start = pipeline.index(".build_apk:")
        signing_directory = pipeline.index("SIGNING_DIR=", build_start)
        self.assertLess(pipeline.index("umask 077", build_start), signing_directory)
        github_start = pipeline.index("github_preflight:")
        auth_config = pipeline.index("AUTH_CONFIG=", github_start)
        self.assertLess(pipeline.index("umask 077", github_start), auth_config)
        self.assertIn('rm -rf -- "$SIGNING_DIR"', pipeline)

    def test_each_build_restores_patch_targets_before_sync_and_keeps_abi_outputs(self):
        pipeline = (REPOSITORY_ROOT / ".gitlab-ci.yml").read_text(
            encoding="utf-8"
        )
        restore = 'git restore --source=HEAD -- "${RUTHENIUM_PATCH_TARGETS[@]}"'
        revision_check = (
            'if [ "$CURRENT_CHROMIUM_REVISION" != "$CHROMIUM_REVISION" ]; then'
        )
        restore_index = pipeline.index(restore)
        check_index = pipeline.index(revision_check)
        sync_index = pipeline.index("gclient sync", check_index)
        patch_index = pipeline.index(
            'scripts/patch_chromium.py" --chromium-src', sync_index
        )
        self.assertLess(restore_index, check_index)
        self.assertLess(check_index, sync_index)
        self.assertLess(sync_index, patch_index)
        self.assertNotIn('rm -rf -- "$BUILD_OUTPUT_DIR"', pipeline)
        self.assertNotIn('git restore --source="$CHROMIUM_REVISION"', pipeline)

    def test_official_certificate_has_pinned_fingerprint(self):
        der = patch_chromium.load_and_verify_der(CERTIFICATE_PATH)
        self.assertGreater(len(der), 1024)
        self.assertEqual(
            patch_chromium.EXPECTED_DER_SHA256,
            hashlib.sha256(der).hexdigest(),
        )

    def test_modified_certificate_is_rejected(self):
        pem = CERTIFICATE_PATH.read_text(encoding="ascii")
        encoded = "".join(
            pem.split("-----BEGIN CERTIFICATE-----", 1)[1]
            .split("-----END CERTIFICATE-----", 1)[0]
            .split()
        )
        der = bytearray(base64.b64decode(encoded))
        der[-1] ^= 1
        modified = (
            "-----BEGIN CERTIFICATE-----\n"
            + base64.encodebytes(der).decode("ascii")
            + "-----END CERTIFICATE-----\n"
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "modified.pem"
            path.write_text(modified, encoding="ascii")
            with self.assertRaisesRegex(ValueError, "unexpected certificate"):
                patch_chromium.load_and_verify_der(path)

    def test_patch_is_scoped_and_idempotent(self):
        source = f"""namespace {{
{patch_chromium.DEFINITION_ANCHOR}
  return true;
}}

void GetCertificatePolicy() {{
{patch_chromium.USE_ANCHOR}
}}
}}  // namespace
"""
        der = patch_chromium.load_and_verify_der(CERTIFICATE_PATH)
        patched = patch_chromium.patch_source(source, der)

        self.assertIn('#if BUILDFLAG(IS_ANDROID)', patched)
        self.assertIn(
            'permitted_dns_names = {".ru", ".xn--p1ai", ".su"}', patched
        )
        self.assertIn(
            "trust_anchors_with_additional_constraints", patched
        )
        self.assertNotIn("trust_anchors.push_back", patched)
        self.assertEqual(patched, patch_chromium.patch_source(patched, der))

    def test_product_text_patches_are_idempotent(self):
        channel_constants = """<resources>
    <string name="app_name" translatable="false">Chromium</string>
    <string name="bookmark_widget_title" translatable="false">Chromium bookmarks</string>
    <string name="search_widget_title" translatable="false">Chromium search</string>
    <string name="quick_action_search_widget_title" translatable="false">Chromium quick action search</string>
</resources>
"""
        channel_constants = patch_chromium.patch_channel_constants(channel_constants)
        self.assertIn(">Ruthenium</string>", channel_constants)
        self.assertIn("Based on Chromium.", channel_constants)
        self.assertIn("Russian Ministry of Digital Development", channel_constants)
        self.assertIn(".ru, .рф, and .su domains", channel_constants)
        self.assertEqual(
            channel_constants,
            patch_chromium.patch_channel_constants(channel_constants),
        )

        preferences = (
            '<PreferenceScreen xmlns:android="http://schemas.android.com/apk/res/android">\n'
            "</PreferenceScreen>\n"
        )
        preferences = patch_chromium.patch_about_preferences(preferences)
        self.assertIn('android:key="ruthenium_description"', preferences)
        self.assertEqual(
            preferences,
            patch_chromium.patch_about_preferences(preferences),
        )

        omnibox = """  bool is_starred_match = IsStarredMatch(match);
  const auto& vector_icon_type = match.GetVectorIcon(is_starred_match, turl);

  return controller_->client()->GetSizedIcon(vector_icon_type,
                                             vector_icon_color);"""
        omnibox = patch_chromium.patch_omnibox_without_vr(omnibox)
        self.assertIn("#if !BUILDFLAG(IS_ANDROID)", omnibox)
        self.assertIn("return gfx::Image();", omnibox)
        self.assertEqual(
            omnibox,
            patch_chromium.patch_omnibox_without_vr(omnibox),
        )

        searchbox = """  const bool is_bookmarked =
      bookmark_model->IsBookmarked(match.destination_url);
  // For starter pack suggestions, use template url to generate proper vector
  // icon.
  const TemplateURL* associated_keyword_turl =
      match.associated_keyword.empty()
          ? nullptr
          : turl_service->GetTemplateURLForKeyword(match.associated_keyword);
  mojom_match->icon_path = AutocompleteIconToResourceName(
      match.GetVectorIcon(is_bookmarked, associated_keyword_turl));
    if (action->GetIconImage().IsEmpty()) {
      icon_path = AutocompleteIconToResourceName(action->GetVectorIcon());
    } else {"""
        searchbox = patch_chromium.patch_searchbox_without_vr(searchbox)
        self.assertEqual(2, searchbox.count("BUILDFLAG(ENABLE_VR)"))
        self.assertEqual(2, searchbox.count("kSearchIconResourceName"))
        self.assertEqual(
            searchbox,
            patch_chromium.patch_searchbox_without_vr(searchbox),
        )

        settings = "mPageTitle.set(getString(R.string.prefs_about_chrome));"
        settings = patch_chromium.patch_about_settings(settings)
        self.assertEqual(
            "mPageTitle.set(getString(R.string.app_name));",
            settings,
        )
        self.assertEqual(settings, patch_chromium.patch_about_settings(settings))

        signin_prefs = (
            "registry->RegisterBooleanPref(prefs::kSigninAllowed, true);"
        )
        signin_prefs = patch_chromium.patch_signin_default(signin_prefs)
        self.assertIn("prefs::kSigninAllowed, false", signin_prefs)
        self.assertEqual(
            signin_prefs,
            patch_chromium.patch_signin_default(signin_prefs),
        )

        identity_disc = """        if (mProfile == null) {
            assert !mButtonData.canShow();
            return;
        }

        ensureProfileDataCache(mProfile);"""
        identity_disc = patch_chromium.patch_identity_disc(identity_disc)
        self.assertIn("Pref.SIGNIN_ALLOWED", identity_disc)
        self.assertIn("mButtonData.setCanShow(false)", identity_disc)
        self.assertEqual(
            identity_disc,
            patch_chromium.patch_identity_disc(identity_disc),
        )

    def test_android_icon_resources_are_complete(self):
        icon_root = REPOSITORY_ROOT / patch_chromium.ICON_RESOURCES_RELATIVE_PATH
        expected_dimensions = {
            "mdpi": (48, 108),
            "hdpi": (72, 162),
            "xhdpi": (96, 216),
            "xxhdpi": (144, 324),
            "xxxhdpi": (192, 432),
        }
        for relative_path in patch_chromium.ICON_TARGETS:
            self.assertTrue((icon_root / relative_path).is_file(), relative_path)

        for density, (legacy_size, adaptive_size) in expected_dimensions.items():
            directory = icon_root / f"res_chromium_base/mipmap-{density}"
            for filename, size in (
                ("app_icon.png", legacy_size),
                ("layered_app_icon.png", adaptive_size),
                ("layered_app_icon_background.png", adaptive_size),
            ):
                data = (directory / filename).read_bytes()
                self.assertEqual(b"\x89PNG\r\n\x1a\n", data[:8])
                width, height = struct.unpack(">II", data[16:24])
                self.assertEqual((size, size), (width, height))

        targets = patch_chromium.target_relative_paths()
        self.assertEqual(len(targets), len(set(targets)))

    def test_complete_checkout_patch_is_idempotent(self):
        network_source = f"""namespace {{
{patch_chromium.DEFINITION_ANCHOR}
  return true;
}}

void GetCertificatePolicy() {{
{patch_chromium.USE_ANCHOR}
}}
}}  // namespace
"""
        channel_constants = """<resources>
    <string name="app_name" translatable="false">Chromium</string>
    <string name="bookmark_widget_title" translatable="false">Chromium bookmarks</string>
    <string name="search_widget_title" translatable="false">Chromium search</string>
    <string name="quick_action_search_widget_title" translatable="false">Chromium quick action search</string>
</resources>
"""
        about_preferences = (
            '<PreferenceScreen xmlns:android="http://schemas.android.com/apk/res/android">\n'
            "</PreferenceScreen>\n"
        )
        about_settings = "mPageTitle.set(getString(R.string.prefs_about_chrome));\n"
        signin_prefs = (
            "registry->RegisterBooleanPref(prefs::kSigninAllowed, true);\n"
        )
        identity_disc = """        if (mProfile == null) {
            assert !mButtonData.canShow();
            return;
        }

        ensureProfileDataCache(mProfile);
"""
        omnibox = """  bool is_starred_match = IsStarredMatch(match);
  const auto& vector_icon_type = match.GetVectorIcon(is_starred_match, turl);

  return controller_->client()->GetSizedIcon(vector_icon_type,
                                             vector_icon_color);
"""
        searchbox = """  const bool is_bookmarked =
      bookmark_model->IsBookmarked(match.destination_url);
  // For starter pack suggestions, use template url to generate proper vector
  // icon.
  const TemplateURL* associated_keyword_turl =
      match.associated_keyword.empty()
          ? nullptr
          : turl_service->GetTemplateURLForKeyword(match.associated_keyword);
  mojom_match->icon_path = AutocompleteIconToResourceName(
      match.GetVectorIcon(is_bookmarked, associated_keyword_turl));
    if (action->GetIconImage().IsEmpty()) {
      icon_path = AutocompleteIconToResourceName(action->GetVectorIcon());
    } else {
"""

        with tempfile.TemporaryDirectory() as temporary_directory:
            chromium_src = Path(temporary_directory)
            text_sources = {
                patch_chromium.SOURCE_RELATIVE_PATH: network_source,
                patch_chromium.CHANNEL_CONSTANTS_RELATIVE_PATH: channel_constants,
                patch_chromium.ABOUT_PREFERENCES_RELATIVE_PATH: about_preferences,
                patch_chromium.ABOUT_SETTINGS_RELATIVE_PATH: about_settings,
                patch_chromium.SIGNIN_PREFS_RELATIVE_PATH: signin_prefs,
                patch_chromium.IDENTITY_DISC_RELATIVE_PATH: identity_disc,
                patch_chromium.OMNIBOX_EDIT_MODEL_RELATIVE_PATH: omnibox,
                patch_chromium.SEARCHBOX_HANDLER_RELATIVE_PATH: searchbox,
            }
            for relative_path, content in text_sources.items():
                path = chromium_src / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            for icon_target in patch_chromium.ICON_TARGETS:
                path = chromium_src / "chrome/android/java" / icon_target
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"upstream resource")

            icon_root = REPOSITORY_ROOT / patch_chromium.ICON_RESOURCES_RELATIVE_PATH
            changed = patch_chromium.patch_checkout(
                chromium_src,
                CERTIFICATE_PATH,
                icon_root,
            )
            self.assertEqual(
                set(patch_chromium.target_relative_paths()),
                set(changed),
            )
            self.assertEqual(
                [],
                patch_chromium.patch_checkout(
                    chromium_src,
                    CERTIFICATE_PATH,
                    icon_root,
                ),
            )


class FetchMinistryCaTest(unittest.TestCase):
    class Response:
        def __init__(self, payload: bytes, final_url: str):
            self.payload = payload
            self.final_url = final_url

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def geturl(self):
            return self.final_url

        def read(self, size: int):
            return self.payload[:size]

    def test_downloaded_certificate_is_canonical_and_verified(self):
        payload = CERTIFICATE_PATH.read_bytes().replace(b"\n", b"\r\n")
        response = self.Response(payload, fetch_ministry_ca.CERTIFICATE_URL)
        downloaded = fetch_ministry_ca.download_certificate(
            opener=lambda request, timeout: response
        )
        self.assertEqual(
            patch_chromium.load_and_verify_der(CERTIFICATE_PATH),
            patch_chromium.decode_and_verify_pem(downloaded.decode("ascii")),
        )
        self.assertTrue(downloaded.endswith(b"-----END CERTIFICATE-----\n"))
        self.assertEqual(
            patch_chromium.EXPECTED_DER_SHA256,
            hashlib.sha256(
                patch_chromium.decode_and_verify_pem(downloaded.decode("ascii"))
            ).hexdigest(),
        )

    def test_download_rejects_unpinned_certificate(self):
        modified = CERTIFICATE_PATH.read_bytes().replace(b"M", b"N", 1)
        response = self.Response(modified, fetch_ministry_ca.CERTIFICATE_URL)
        with self.assertRaisesRegex(ValueError, "unexpected certificate SHA-256"):
            fetch_ministry_ca.download_certificate(
                opener=lambda request, timeout: response
            )

    def test_download_rejects_insecure_redirect(self):
        response = self.Response(
            CERTIFICATE_PATH.read_bytes(),
            "http://gu-st.ru/russian_trusted_root_ca_pem.crt",
        )
        with self.assertRaisesRegex(ValueError, "redirected away from pinned URL"):
            fetch_ministry_ca.download_certificate(
                opener=lambda request, timeout: response
            )

    def test_download_rejects_redirect_to_different_https_host(self):
        response = self.Response(
            CERTIFICATE_PATH.read_bytes(),
            "https://example.com/russian_trusted_root_ca_pem.crt",
        )
        with self.assertRaisesRegex(ValueError, "redirected away from pinned URL"):
            fetch_ministry_ca.download_certificate(
                opener=lambda request, timeout: response
            )

    def test_atomic_write(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "nested" / "root.pem"
            fetch_ministry_ca.write_atomically(output, b"certificate\n")
            self.assertEqual(b"certificate\n", output.read_bytes())


if __name__ == "__main__":
    unittest.main()
