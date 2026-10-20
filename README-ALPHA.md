# Murus Igneus 0.3.0-alpha

Experimental open-source Linux firewall project targeting Devuan 6 Excalibur and OpenRC.

## Actual status

- The recovered and rebranded OpenWall 0.2 application is committed in `src/` (the original Alpine helper scripts are kept in `legacy/`). It may still be incomplete: see `SOURCE_STATUS.md`.
- The original IPv4 firewall, static routing, NAT, configuration import and web interface need VM regression testing after migration.
- The Devuan bootable ISO has **not** yet been built or tested.
- AI, UTM/Suricata/ClamAV and VPN are **planned**, not implemented in this alpha.
- Earlier development builds used a publicly known laboratory password (`igneus`); current builds generate a random admin password at first start (see `SECURITY.md`). The software is still unsafe for production.

Do not expose management interfaces to the Internet or deploy this software as a production firewall. License attribution for recovered MIT application files must be preserved alongside repository license notices.
