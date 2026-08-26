# Ruthenium for Android

Ruthenium is an Android build of Chromium where the Russian Trusted Root CA is a
trust anchor constrained to the `.ru`, `.xn--p1ai` (`.рф`), and `.su` DNS
namespaces. The CA is not added to Android's system trust store, and it cannot
vouch for a DNS name outside those three zones.

The build is pinned to Android Stable Chromium `152.0.7977.64`, revision
`506c834ecceaa943c5f41e6cfe7f68acb5c45346`.

## Trust boundary

Chromium's ordinary trust stores are left exactly as they are, and they remain
what verifies almost every site. The Russian root is supplied separately, as an
additional trust anchor that carries a name constraint, through Chromium's own
`trust_anchors_with_additional_constraints` mechanism on Android. Its permitted
DNS subtrees are:

- `.ru`
- `.xn--p1ai` (the ASCII form of `.рф`)
- `.su`

The leading dot permits names below the zone — `bank.ru`, `pay.bank.ru`,
`archive.su` — rather than the bare TLD. A name such as `bank.ru.example.com`
sits below `.com` and is not permitted.

The constraint applies to every DNS name a certificate asserts, not only to the
hostname being requested. A certificate for `bank.ru` that also carries
`example.com` is therefore refused outright, even while `bank.ru` is the site
being opened. That is the conservative direction of failure: such a site does
not open, and no DNS name outside the three zones is trusted through this
anchor.

Chromium's normal certificate checks are untouched. The requested hostname must
still appear in the leaf SAN, and validity, signatures, revocation policy, and
every other path requirement still apply.

The root certificate is pinned by its DER SHA-256 fingerprint:

`d26d2d0231b7c39f92cc738512ba54103519e4405d68b5bd703e9788ca8ecf31`

The build uses only the root as a trust anchor. Servers are expected to send the
Russian Trusted Sub CA intermediate, as normal TLS deployments do.

CI downloads the root from the Ministry-operated distribution endpoint before
every build and verifies it against `certificates/ministry-ca-lock.json` before
use. A malformed or unreviewed download fails the build instead of silently
changing the trust anchor. The checked-in PEM remains an auditable fixture for
tests and offline review.

## Backlog

Known gaps, kept here so the trust boundary above is read with them in mind.

**The name constraint does not cover IP addresses.** It declares permitted DNS
subtrees only, and a permitted subtree for one name type leaves other name types
unconstrained, so a leaf certificate whose subjectAltName is an `iPAddress` is
not restricted by it. Under this root, such a certificate is accepted for a URL
that addresses the host by IP. Sites are reached by name, and a certificate
issued to a bare IP address is rare, so this ranks low. The fix is to declare a
degenerate permitted CIDR alongside the DNS subtrees, which makes the IP name
type constrained and every real address fall outside it.

## Product identity

The Android application is built as:

- application name: `Ruthenium`;
- Android application ID: `app.ruthenium.browser`, derived from
  `ruthenium.app`;
- canonical adaptive, round, monochrome, and legacy icon resources generated
  from `assets/ruthenium-icon/`;
- release signature documented in `SIGNING.md`.

The Android About screen includes:

> **Ruthenium**
>
> Based on Chromium. The Russian Ministry of Digital Development certificate is
> used for websites in the `.ru`, `.рф`, and `.su` domains.

The internal Java namespaces remain `org.chromium.*`; only the external Android
application ID changes.

Browser-level Google sign-in is disabled. Public Chromium does not ship the
Android account-manager implementation used by Google Chrome, and access to
Chrome Sync is restricted for third-party Chromium-based products. Signing in
to ordinary Google websites remains available like any other web sign-in.

The build generates the complete `chrome://credits` page so Chromium's license
notice and bundled third-party notices remain available in the distributed
binary. The original Google/Chromium copyright and legal-information entries
are not replaced by the Ruthenium About text. CI also places the upstream
Chromium BSD license beside every APK as `Chromium-LICENSE.txt`.

## Build

GitLab CI keeps the large Chromium checkout beside the regular job workspace so
subsequent rebuilds of the same architecture can reuse it. A release pipeline
builds `arm64-v8a`, `armeabi-v7a`, and `x86_64`, each producing its own APK and
checksum. Any pipeline on `main` that does not name another task is a release
pipeline and runs the whole chain without a manual job. Each architecture has a
persistent, independent GN/Ninja output directory, so switching ABI never removes
or invalidates another architecture's build cache.

A finished artifact set is keyed by the release identity and the architecture.
When that key is unchanged, the existing set is re-verified against the
signature, application ID, ABI, and recorded revision and then reused rather than
rebuilt. Changing any build input moves the identity and rebuilds.

The primary output artifact is:

`artifacts/Ruthenium-152.0.7977.64-arm64-v8a.apk`

## Public source publication

The private build repository is never mirrored to GitHub because its history
and Git metadata are outside the public trust boundary. Publication instead
uses the exact allowlist in `.public-files` to create a deterministic source
snapshot with normalized ownership, permissions, and timestamps.

Before publication, CI rejects unlisted tracked files, symlinks, secret file
types, token and private-key markers, private infrastructure addresses,
absolute user paths, hidden bidirectional Unicode, active SVG content, and PNG
identity metadata. The fail-closed `ruthenium-publisher` account can reach only
the local Tor SOCKS port. It creates a neutral commit whose parent is the
current public `main`; private commits, reflogs, remotes, and author metadata
are never copied.

After a fast-forward push, a second Tor circuit fetches `main` again and CI
requires both the public commit and Git tree to match the generated snapshot.
If the snapshot is unchanged, the scheduled publisher exits without creating
an empty commit.

## Public Android releases

Every architecture has its own build job and its own GitHub release-publication
job, and a release pipeline runs the whole chain end to end. All APKs for one
Ruthenium release use the tag
`android-<Chromium version>-ca-<CA digest>-<release digest>` and remain separate
ABI-specific assets; no universal APK silently combines different native builds.

The CA digest is the first 12 hex characters of the pinned Ministry root's DER
SHA-256. The release digest is the first 12 hex characters of a SHA-256 over all
inputs that decide what the APK contains: the Chromium version and revision,
the application ID, the signing certificate, the same pinned Ministry root,
and the exact bytes of `build/args.gn` and `scripts/patch_chromium.py`. Every one
of those is published, so a checkout can recompute both identifiers and confirm
that a release tag belongs to the source it claims. Equal inputs always name the
same release, and any change to them names a different one, with no counter to
maintain and no way for a changed build to land in a release that is already
public.

Before an APK can be published, CI independently checks its ZIP integrity,
native ABI, application ID, application label, signing-certificate fingerprint,
build metadata, and SHA-256 file. The release job also requires the deterministic
public source snapshot from the same pipeline to be present on public `main`.

GitHub access is possible only from the fail-closed `ruthenium-publisher`
account through a verified Tor circuit. Existing assets are immutable from the
pipeline's point of view: an asset with the same name is accepted only if its
size and SHA-256 are identical; otherwise publication stops instead of replacing
it. After upload, CI downloads every affected asset through a fresh Tor circuit
and requires a byte-for-byte match before reporting success. Releases include
the APK, checksum, build information, Chromium license, signing certificate, and
machine-readable provenance recording the inputs the binary was built from. The
release notes and the provenance name no source commit: the snapshot moves on
every unrelated push, and the release identity already ties the binaries to the
published files that produce them.

## Automated release updates

A daily GitLab schedule queries the official ChromiumDash Android `Stable`
channel. The updater selects the numerically highest four-part version rather
than trusting response order, validates the platform, channel, milestone, and
Chromium revision, and then requires the matching release tag at
`chromium.googlesource.com` to resolve to the same Git commit.

The same job downloads the Ministry root from two separately published official
paths and requires both PEM files to decode to the same DER certificate. Before
accepting a rollover it also verifies the self-signature, exact Ministry subject
and issuer, remaining lifetime, RSA key size, signature algorithm, critical CA
constraints, and certificate-signing key usage. Any disagreement stops the job
without changing the trust lock.

If Chromium and the certificate are both current, the scheduled pipeline writes
nothing and starts no build. A new Chromium version or a new certificate changes
the release identity by itself, so neither needs a release counter to be bumped.
The updater commits the new lock under the neutral Ruthenium
Project identity with CI skipped for that mechanical commit, then starts exactly
one `release_update` pipeline from it. That pipeline builds all three ABIs,
publishes the sanitized source snapshot, and publishes the verified APKs through
the Tor-only GitHub release boundary.

Release updates are single-flight. Before querying upstream, the nightly updater
requires the currently locked release to have completed all three builds and all
three GitHub publication jobs. An active pipeline is left running and upstream
changes are deferred. A failed, canceled, or timed-out pipeline is retried from
the same locked commit, preserving its GN/Ninja output directories. Completion
is recorded as a private GitLab marker tag only after every required job succeeds.
The shared checkout queue is kept in `oldest_first` mode, and ordinary source-only
publication is deferred while a release is incomplete, so a newer pipeline or
source snapshot cannot displace an in-progress release.
