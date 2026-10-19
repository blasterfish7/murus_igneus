# Integration status — Murus Igneus 0.3.0-alpha

**Experimental / incomplete. DO NOT DEPLOY.**

## Completed
- Merged Claude review PRs #2 and #3 into `develop/0.3.0-alpha`.
- Copied 15 new Devuan packaging, ISO-builder, VPN/IPS/antivirus prototype and test files from `codex/devuan-excalibur-packaging` into this integration branch.
- Preserved the hardened existing backend and configuration code rather than blindly overwriting them.

## Not yet completed
- Devuan-specific `server.py`, `configuration.py`, web GUI and packaging workflows have NOT been reconciled against Claude fixes.
- AI-assisted diagnostics are NOT implemented.
- WireGuard, Suricata/IPS, proxy antivirus and web installation have NOT been validated as functional.
- No validated bootable Devuan ISO or release artifact is available.
- Unit and runtime checks of this combined branch remain outstanding.
- Default lab password `igneus` is PUBLIC and insecure outside isolated testing.

Do not merge PR #4 or publish a release until these items have been reviewed and tested.
