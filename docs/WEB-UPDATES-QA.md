# Signed web application updates — acceptance

Reviewed 2026-10-30. These are development changes after the published alpha.10; no new public ISO release is claimed.

## Tested source and checks

[CI 40913064560](https://github.com/blasterfish7/murus_igneus/actions/runs/40913064560), source `a50beeb02b4162053b854a16fe76a0734e9dd37d`, completed successfully:

- 251 Python tests, no skips; Ruff and syntax checks.
- 24 real Chromium checks, including dashboard rates, signed-bundle UI, typed confirmation, missing trust key, recovery state and existing password/MFA/parental/network flows.
- Four real HTTPS parental category downloads and the management TLS/transaction-lock fixture.
- 13 native, 9 enterprise, 23 parental and 6 DHCP-WAN/anti-lockout packet checks.
- 73 original-ISO checks: UEFI live boot, changed console/web password, real packet suites inside the image, installation onto a fresh 16 GiB disk, cold disk boot with ISO detached and the update checks below.

The installed update lab used actual DEBs, Ed25519 signatures, HTTPS APIs, dpkg and OpenRC. It confirmed:

1. HTTPS staging rejects a DEB with a digest different from the signed manifest.
2. The independent worker installs a signed package, restarts HTTPS and preserves credentials/configuration.
3. Web rollback installs the previous saved DEB and restores its configuration.
4. A real failing dpkg postinst triggers automatic package/configuration recovery and returns HTTPS.
5. A persisted interrupted journal is detected; console recovery restarts the stopped service.
6. The temporary lab signing key is removed. No production signing key is generated or installed.

## Final UI adjustment

Commit `92d338aad50820b755a1c7675052d4a80a450828` changes only CSS and the browser acceptance script after the complete ISO run. Long digests/release notes wrap on mobile. The 24-check Chromium suite passed locally with the signed-bundle preview open at 390 px. Updater/server/Python code is identical to the fully tested source. The tested ISO candidate predates this CSS-only adjustment; a future public build must include it.

## Preserved candidate and published release

Actions artifact storage was full. The existing fallback verified and preserved the original tested ISO/DEB/report as private draft release `428144307`, tag `candidate-alpha10-a50beeb02b41-40913064560`.

- ISO: 475064320 bytes, SHA256 `1521b80245ef481af682f0c314d764ccbdf9449f79255c0c81027c59c0fa6b67`.
- DEB: 131116 bytes, SHA256 `91062cc349ad43fc9db897dd2edcebf5e488714e7cf191917658cfd69aced7c9`.

This candidate is not published as alpha.10. The existing public alpha.10 remains release `426467921`, with ISO SHA256 `c60bbab52010d09e1dd283eba6a204e400b6606b99b1b9ec314731f943fcffaa` and DEB SHA256 `1954d47f9e0f878c7641cf5def9274e234c88abe932bdc36f5a0ebbdb205e710`.

## Limits

This updates the application, not Devuan/kernel/bootloader. A trusted Ed25519 public key and matching signed bundles must be provisioned before installation. GitHub release discovery does not authorize installation, and a private catalog can require offline uploads. The real lab does not certify hard-power-cut recovery, disk corruption or physical hardware. See [UPDATES](UPDATES.md) for bootstrap, recovery commands and backup semantics.
