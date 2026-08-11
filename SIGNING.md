# Android release signing

The release key is intentionally stored outside the repository.

- Published certificate: `signing/ruthenium-release-cert.pem`
- Store type: PKCS12
- Alias: `ruthenium-release`
- Subject: `CN=Ruthenium Release, OU=Android Distribution, O=Ruthenium Project`
- Algorithm: RSA 4096 / SHA256withRSA
- Valid until: 2053-12-21
- Certificate SHA-256: `38:F8:1A:A5:46:4B:33:12:3F:1F:38:25:1D:8A:17:96:31:F3:9B:FE:92:A6:BA:F7:22:4E:B2:40:E9:90:37:39`

Never commit the private keystore or its password. Back up both before the
first public release: future APK updates must use the same signing identity.

The build environment supplies the base64-encoded PKCS12 data and its password
through the secret variables `RUTHENIUM_KEYSTORE_B64` and
`RUTHENIUM_KEYSTORE_PASSWORD`. The pipeline verifies the certificate
fingerprint before building, signs the zip-aligned APK, and verifies the
resulting APK certificate before publishing artifacts. Secret values, storage
locations, and backup media are intentionally outside the public build source.
