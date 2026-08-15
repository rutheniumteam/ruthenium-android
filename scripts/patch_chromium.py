#!/usr/bin/env python3
"""Apply the Ruthenium Android product and scoped Russian CA patch."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import shutil
from pathlib import Path
import re


SOURCE_RELATIVE_PATH = Path(
    "chrome/browser/net/profile_network_context_service.cc"
)
CERTIFICATE_RELATIVE_PATH = Path(
    "certificates/russian_trusted_root_ca.pem"
)
CERTIFICATE_LOCK_RELATIVE_PATH = Path("certificates/ministry-ca-lock.json")
ICON_RESOURCES_RELATIVE_PATH = Path("assets/ruthenium-icon/android-res")
CHANNEL_CONSTANTS_RELATIVE_PATH = Path(
    "chrome/android/java/res_chromium_base/values/channel_constants.xml"
)
ABOUT_PREFERENCES_RELATIVE_PATH = Path(
    "chrome/android/java/res/xml/about_chrome_preferences.xml"
)
ABOUT_SETTINGS_RELATIVE_PATH = Path(
    "chrome/android/java/src/org/chromium/chrome/browser/about_settings/"
    "AboutChromeSettings.java"
)
SIGNIN_PREFS_RELATIVE_PATH = Path(
    "components/signin/internal/identity_manager/primary_account_manager.cc"
)
IDENTITY_DISC_RELATIVE_PATH = Path(
    "chrome/android/java/src/org/chromium/chrome/browser/identity_disc/"
    "IdentityDiscController.java"
)
OMNIBOX_EDIT_MODEL_RELATIVE_PATH = Path(
    "chrome/browser/ui/omnibox/omnibox_edit_model.cc"
)
SEARCHBOX_HANDLER_RELATIVE_PATH = Path(
    "chrome/browser/ui/webui/cr_components/searchbox/searchbox_handler.cc"
)
CERTIFICATE_PRIMARY_URL = (
    "https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt"
)
CERTIFICATE_SECONDARY_URL = (
    "https://gu-st.ru/content/Other/doc/russian_trusted_root_ca.cer"
)
CERTIFICATE_SOURCE_URLS = (
    CERTIFICATE_PRIMARY_URL,
    CERTIFICATE_SECONDARY_URL,
)


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def load_certificate_lock(path: Path | None = None) -> dict[str, str]:
    if path is None:
        path = Path(__file__).resolve().parents[1] / CERTIFICATE_LOCK_RELATIVE_PATH
    data = path.read_bytes()
    if not data or len(data) > 4096:
        raise ValueError("certificate lock has an invalid size")
    try:
        value = json.loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("certificate lock is not valid UTF-8 JSON") from error
    if not isinstance(value, dict) or canonical_json(value) != data:
        raise ValueError("certificate lock is not canonical JSON")
    if set(value) != {"der_sha256", "primary_url", "secondary_url"}:
        raise ValueError("certificate lock has unexpected fields")
    if not isinstance(value["der_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", value["der_sha256"]
    ):
        raise ValueError("certificate lock has an invalid DER SHA-256")
    if value["primary_url"] != CERTIFICATE_PRIMARY_URL:
        raise ValueError("certificate lock has an unexpected primary URL")
    if value["secondary_url"] != CERTIFICATE_SECONDARY_URL:
        raise ValueError("certificate lock has an unexpected secondary URL")
    return value  # type: ignore[return-value]


EXPECTED_DER_SHA256 = load_certificate_lock()["der_sha256"]

DEFINITION_ANCHOR = (
    "bool IsValidDNSConstraint(std::string_view possible_dns_constraint) {"
)
USE_ANCHOR = """  auto additional_certificates =
      cert_verifier::mojom::AdditionalCertificates::New();"""

DEFINITION_BEGIN = "// BEGIN Russian Trusted Root CA (Android-only, DNS-constrained)"
DEFINITION_END = "// END Russian Trusted Root CA (Android-only, DNS-constrained)"
USE_BEGIN = "  // BEGIN Russian Trusted Root CA scoped trust"
USE_END = "  // END Russian Trusted Root CA scoped trust"

APP_NAME_REPLACEMENTS = {
    '<string name="app_name" translatable="false">Chromium</string>':
        '<string name="app_name" translatable="false">Ruthenium</string>',
    '<string name="bookmark_widget_title" translatable="false">Chromium bookmarks</string>':
        '<string name="bookmark_widget_title" translatable="false">Ruthenium bookmarks</string>',
    '<string name="search_widget_title" translatable="false">Chromium search</string>':
        '<string name="search_widget_title" translatable="false">Ruthenium search</string>',
    '<string name="quick_action_search_widget_title" translatable="false">Chromium quick action search</string>':
        '<string name="quick_action_search_widget_title" translatable="false">Ruthenium quick action search</string>',
}
ABOUT_SUMMARY_RESOURCE = (
    '    <string name="ruthenium_about_summary" translatable="false">'
    'Based on Chromium. The Russian Ministry of Digital Development certificate '
    'is used for websites in the .ru, .рф, and .su domains.</string>\n'
)
ABOUT_PREFERENCE = """    <Preference
        android:key="ruthenium_description"
        android:title="@string/app_name"
        android:summary="@string/ruthenium_about_summary"
        android:selectable="false" />
"""

ICON_TARGETS = (
    Path("res_base/drawable/ic_launcher.xml"),
    Path("res_base/drawable/ic_launcher_round.xml"),
    Path("res_chromium_base/drawable/themed_app_icon.xml"),
    Path("res_chromium_base/mipmap-nodpi/layered_app_icon_foreground.xml"),
    *(
        Path(f"res_chromium_base/mipmap-{density}/{filename}")
        for density in ("mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi")
        for filename in (
            "app_icon.png",
            "layered_app_icon.png",
            "layered_app_icon_background.png",
        )
    ),
)


def decode_pem(pem: str) -> bytes:
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    if pem.count(begin) != 1 or pem.count(end) != 1:
        raise ValueError("expected exactly one PEM certificate")

    encoded = pem.split(begin, 1)[1].split(end, 1)[0]
    try:
        der = base64.b64decode("".join(encoded.split()), validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("invalid PEM certificate encoding") from error
    return der


def decode_and_verify_pem(pem: str) -> bytes:
    der = decode_pem(pem)
    actual_sha256 = hashlib.sha256(der).hexdigest()
    if actual_sha256 != EXPECTED_DER_SHA256:
        raise ValueError(
            f"unexpected certificate SHA-256: {actual_sha256}"
        )
    return der


def load_and_verify_der(certificate_path: Path) -> bytes:
    return decode_and_verify_pem(certificate_path.read_text(encoding="ascii"))


def format_der_array(der: bytes) -> str:
    lines = []
    for offset in range(0, len(der), 12):
        chunk = der[offset : offset + 12]
        lines.append("    " + ", ".join(f"0x{byte:02x}" for byte in chunk) + ",")
    return "\n".join(lines)


def definition_block(der: bytes) -> str:
    return f"""{DEFINITION_BEGIN}
#if BUILDFLAG(IS_ANDROID)
// Source: {CERTIFICATE_PRIMARY_URL}
// DER SHA-256: {EXPECTED_DER_SHA256}
constexpr uint8_t kRussianTrustedRootCaDer[] = {{
{format_der_array(der)}
}};
#endif  // BUILDFLAG(IS_ANDROID)
{DEFINITION_END}

"""


def use_block() -> str:
    return f"""
{USE_BEGIN}
#if BUILDFLAG(IS_ANDROID)
  auto russian_trusted_root =
      cert_verifier::mojom::CertWithConstraints::New();
  russian_trusted_root->certificate = std::vector<uint8_t>(
      kRussianTrustedRootCaDer,
      kRussianTrustedRootCaDer + sizeof(kRussianTrustedRootCaDer));
  // A leading dot permits subdomains only. That covers registrable names below
  // the TLD while excluding unrelated DNS namespaces.
  russian_trusted_root->permitted_dns_names = {{".ru", ".xn--p1ai", ".su"}};
  additional_certificates->trust_anchors_with_additional_constraints.push_back(
      std::move(russian_trusted_root));
#endif  // BUILDFLAG(IS_ANDROID)
{USE_END}"""


def patch_source(source: str, der: bytes) -> str:
    markers = (DEFINITION_BEGIN, DEFINITION_END, USE_BEGIN, USE_END)
    marker_count = sum(marker in source for marker in markers)
    if marker_count == len(markers):
        return source
    if marker_count:
        raise ValueError("source contains an incomplete prior patch")

    if source.count(DEFINITION_ANCHOR) != 1:
        raise ValueError("Chromium definition anchor was not found exactly once")
    if source.count(USE_ANCHOR) != 1:
        raise ValueError("Chromium use anchor was not found exactly once")

    source = source.replace(
        DEFINITION_ANCHOR,
        definition_block(der) + DEFINITION_ANCHOR,
        1,
    )
    source = source.replace(USE_ANCHOR, USE_ANCHOR + use_block(), 1)
    return source


def replace_once(source: str, old: str, new: str, description: str) -> str:
    if new in source:
        return source
    if source.count(old) != 1:
        raise ValueError(f"{description} anchor was not found exactly once")
    return source.replace(old, new, 1)


def guard_unique_cpp_region(
    source: str,
    start_pattern: str,
    end_pattern: str,
    fallback_statement: str,
    description: str,
) -> str:
    """Guard one semantic C++ region without depending on its formatting."""
    begin_marker = f"// BEGIN Ruthenium {description}"
    end_marker = f"// END Ruthenium {description}"
    marker_counts = (source.count(begin_marker), source.count(end_marker))
    if marker_counts == (1, 1):
        return source
    if marker_counts != (0, 0):
        raise ValueError(f"{description} contains an incomplete prior patch")

    flags = re.MULTILINE | re.DOTALL
    starts = list(re.finditer(start_pattern, source, flags))
    ends = list(re.finditer(end_pattern, source, flags))
    if len(starts) != 1 or len(ends) != 1:
        raise ValueError(f"{description} anchor was not found exactly once")
    start = starts[0]
    end = ends[0]
    if start.start() > end.start() or start.end() > end.end():
        raise ValueError(f"{description} anchors are out of order")

    indent = start.group("indent")
    guarded = (
        f"{indent}{begin_marker}\n"
        "#if !BUILDFLAG(IS_ANDROID) || BUILDFLAG(ENABLE_VR)\n"
        f"{source[start.start():end.end()]}\n"
        "#else\n"
        f"{indent}{fallback_statement}\n"
        "#endif\n"
        f"{indent}{end_marker}"
    )
    return source[: start.start()] + guarded + source[end.end() :]


def patch_channel_constants(source: str) -> str:
    for old, new in APP_NAME_REPLACEMENTS.items():
        source = replace_once(source, old, new, "application name")
    if 'name="ruthenium_about_summary"' not in source:
        source = replace_once(
            source,
            "</resources>",
            ABOUT_SUMMARY_RESOURCE + "</resources>",
            "channel constants closing tag",
        )
    return source


def patch_about_preferences(source: str) -> str:
    if 'android:key="ruthenium_description"' in source:
        return source
    return replace_once(
        source,
        '<PreferenceScreen xmlns:android="http://schemas.android.com/apk/res/android">\n',
        '<PreferenceScreen xmlns:android="http://schemas.android.com/apk/res/android">\n'
        + ABOUT_PREFERENCE,
        "About preference screen",
    )


def patch_about_settings(source: str) -> str:
    return replace_once(
        source,
        "mPageTitle.set(getString(R.string.prefs_about_chrome));",
        "mPageTitle.set(getString(R.string.app_name));",
        "About page title",
    )


def patch_signin_default(source: str) -> str:
    return replace_once(
        source,
        "registry->RegisterBooleanPref(prefs::kSigninAllowed, true);",
        "registry->RegisterBooleanPref(prefs::kSigninAllowed, false);",
        "browser sign-in default",
    )


def patch_identity_disc(source: str) -> str:
    return replace_once(
        source,
        """        if (mProfile == null) {
            assert !mButtonData.canShow();
            return;
        }

        ensureProfileDataCache(mProfile);""",
        """        if (mProfile == null
                || !UserPrefs.get(mProfile.getOriginalProfile())
                        .getBoolean(Pref.SIGNIN_ALLOWED)) {
            mButtonData.setCanShow(false);
            return;
        }

        ensureProfileDataCache(mProfile);""",
        "identity disc sign-in visibility",
    )


def patch_omnibox_without_vr(source: str) -> str:
    return guard_unique_cpp_region(
        source,
        r"^(?P<indent>[ \t]*)bool\s+is_starred_match\s*=\s*"
        r"IsStarredMatch\s*\(\s*match\s*\)\s*;",
        r"^[ \t]*return\s+controller_->client\(\)->GetSizedIcon\s*\(\s*"
        r"vector_icon_type\s*,\s*vector_icon_color\s*\)\s*;",
        "return gfx::Image();",
        "Android omnibox icon fallback",
    )


def patch_searchbox_without_vr(source: str) -> str:
    source = guard_unique_cpp_region(
        source,
        r"^(?P<indent>[ \t]*)const\s+bool\s+is_bookmarked\s*=\s*"
        r"bookmark_model->IsBookmarked\s*\(\s*match\.destination_url\s*\)\s*;",
        r"^[ \t]*mojom_match->icon_path\s*=\s*AutocompleteIconToResourceName\s*"
        r"\(\s*match\.GetVectorIcon\s*\(\s*is_bookmarked\s*,\s*"
        r"associated_keyword_turl\s*\)\s*\)\s*;",
        "mojom_match->icon_path = kSearchIconResourceName;",
        "Android searchbox match icon fallback",
    )
    return guard_unique_cpp_region(
        source,
        r"^(?P<indent>[ \t]*)icon_path\s*=\s*AutocompleteIconToResourceName\s*"
        r"\(\s*action->GetVectorIcon\s*\(\s*\)\s*\)\s*;",
        r"^[ \t]*icon_path\s*=\s*AutocompleteIconToResourceName\s*"
        r"\(\s*action->GetVectorIcon\s*\(\s*\)\s*\)\s*;",
        "icon_path = kSearchIconResourceName;",
        "Android searchbox action icon fallback",
    )


def write_text_if_changed(path: Path, content: str) -> bool:
    original = path.read_text(encoding="utf-8")
    if original == content:
        return False
    path.write_text(content, encoding="utf-8")
    return True


def copy_if_changed(source: Path, destination: Path) -> bool:
    if not source.is_file():
        raise FileNotFoundError(f"missing Ruthenium icon resource: {source}")
    if not destination.is_file():
        raise FileNotFoundError(f"missing Chromium icon target: {destination}")
    if source.read_bytes() == destination.read_bytes():
        return False
    shutil.copyfile(source, destination)
    return True


def text_patch_transforms():
    return (
        (CHANNEL_CONSTANTS_RELATIVE_PATH, patch_channel_constants),
        (ABOUT_PREFERENCES_RELATIVE_PATH, patch_about_preferences),
        (ABOUT_SETTINGS_RELATIVE_PATH, patch_about_settings),
        (SIGNIN_PREFS_RELATIVE_PATH, patch_signin_default),
        (IDENTITY_DISC_RELATIVE_PATH, patch_identity_disc),
        (OMNIBOX_EDIT_MODEL_RELATIVE_PATH, patch_omnibox_without_vr),
        (SEARCHBOX_HANDLER_RELATIVE_PATH, patch_searchbox_without_vr),
    )


def text_target_relative_paths() -> tuple[Path, ...]:
    return (
        SOURCE_RELATIVE_PATH,
        *(path for path, _ in text_patch_transforms()),
    )


def target_relative_paths() -> tuple[Path, ...]:
    icon_targets = tuple(Path("chrome/android/java") / path for path in ICON_TARGETS)
    return (
        *text_target_relative_paths(),
        *icon_targets,
    )


def check_text_patch_compatibility(
    chromium_src: Path,
    certificate_path: Path,
) -> None:
    source_path = chromium_src / SOURCE_RELATIVE_PATH
    patch_source(
        source_path.read_text(encoding="utf-8"),
        load_and_verify_der(certificate_path),
    )
    for relative_path, transform in text_patch_transforms():
        transform((chromium_src / relative_path).read_text(encoding="utf-8"))


def patch_checkout(
    chromium_src: Path,
    certificate_path: Path,
    icon_resources: Path,
) -> list[Path]:
    changed: list[Path] = []

    source_path = chromium_src / SOURCE_RELATIVE_PATH
    source = source_path.read_text(encoding="utf-8")
    patched = patch_source(source, load_and_verify_der(certificate_path))
    if write_text_if_changed(source_path, patched):
        changed.append(SOURCE_RELATIVE_PATH)

    for relative_path, transform in text_patch_transforms():
        path = chromium_src / relative_path
        if write_text_if_changed(path, transform(path.read_text(encoding="utf-8"))):
            changed.append(relative_path)

    for icon_target in ICON_TARGETS:
        destination_relative_path = Path("chrome/android/java") / icon_target
        if copy_if_changed(
            icon_resources / icon_target,
            chromium_src / destination_relative_path,
        ):
            changed.append(destination_relative_path)

    return changed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--chromium-src",
        type=Path,
        help="Path to the Chromium src checkout",
    )
    parser.add_argument(
        "--certificate",
        type=Path,
        default=Path(__file__).resolve().parents[1] / CERTIFICATE_RELATIVE_PATH,
    )
    parser.add_argument(
        "--icon-resources",
        type=Path,
        default=Path(__file__).resolve().parents[1] / ICON_RESOURCES_RELATIVE_PATH,
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="Print Chromium-relative files modified by this patch",
    )
    parser.add_argument(
        "--list-text-targets",
        action="store_true",
        help="Print Chromium-relative text files inspected by this patch",
    )
    parser.add_argument(
        "--check-text-patches",
        action="store_true",
        help="Validate text patch compatibility without changing files",
    )
    args = parser.parse_args()
    if args.list_targets:
        for path in target_relative_paths():
            print(path)
        return
    if args.list_text_targets:
        for path in text_target_relative_paths():
            print(path)
        return
    if args.chromium_src is None:
        parser.error(
            "--chromium-src is required unless a --list-*-targets option is used"
        )
    if args.check_text_patches:
        check_text_patch_compatibility(
            args.chromium_src.resolve(),
            args.certificate.resolve(),
        )
        print("Chromium text patch compatibility passed")
        return
    changed = patch_checkout(
        args.chromium_src.resolve(),
        args.certificate.resolve(),
        args.icon_resources.resolve(),
    )
    if changed:
        print("patched:")
        for path in changed:
            print(f"  {path}")
    else:
        print("already patched")


if __name__ == "__main__":
    main()
