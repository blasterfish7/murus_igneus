# legacy

Historical scripts recovered from the OpenWall 0.2.0 Alpine ISO. They are kept for provenance and are **not** part of the Devuan/OpenRC build.

- `alpine/openwall-install` and `alpine/openwall-info` refer to `/opt/openwall`, `/etc/openwall` and `/etc/init.d/openwall`, none of which exist in this repository. The current application reads its state from `/etc/murus_igneus` (see `src/murus_igneus/server.py`).
- `openwall-install` erases the disk you select. Do not run it on a machine you care about.
- `openwall-info` prints the initial web password on the console; that password is the publicly known laboratory credential described in `SECURITY.md`.

See `SOURCE_STATUS.md` and `docs/PROVENANCE.md` for what is and is not known about these sources.
