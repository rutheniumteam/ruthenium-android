# Notices

Ruthenium is an independent Chromium build. It is not affiliated with or
endorsed by Google, the Chromium project, or the Russian Ministry of Digital
Development.

Chromium source code is not redistributed in this repository. The build system
downloads a pinned upstream Chromium revision and applies the published
Ruthenium changes. Chromium and its bundled third-party components retain their
respective copyright notices and licenses; the build publishes Chromium's
license and complete generated credits alongside the APK.

The checked-in Russian Trusted Root CA certificate is a public trust anchor
distributed by the Ministry-operated endpoint documented in `README.md`. Its
pinned fingerprint and DNS-name constraints are part of the auditable build
configuration.
