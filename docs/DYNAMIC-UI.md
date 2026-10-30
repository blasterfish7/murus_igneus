# Dynamic administration interface

Dashboard and Interfaces now share a live visual presentation using the existing local JavaScript/CSS and theme tokens, without an external UI framework or CDN.

- The authenticated read-only `/api/dashboard` endpoint reads Linux `/proc` CPU, available memory, uptime and per-interface byte counters. It does not run commands or acquire the configuration transaction lock.
- The browser samples every five seconds while the dashboard is visible. CPU and traffic require two samples; per-port traffic is reported in bits/second. Counter resets and gaps exceeding twenty seconds discard the traffic series. The chart stores at most 36 samples in page memory. These counters include all traffic on the selected port; they are not application or child usage attribution.
- Hidden browser tabs stop scheduled status/inventory/telemetry polling. Returning to the dashboard refreshes data; only one telemetry/inventory request can run at a time. Missing telemetry clears values and displays a failure/partial-data message.
- Port cards display live device names, link state, MAC and actual addresses. Configuration actions still edit the draft, do not borrow observed addresses and cannot repurpose the reserved management port. The technical table remains available.
- The existing confirmation countdown now includes a progress indicator. Firewall rules, authentication, configuration serialization and rollback behavior remain unchanged.
- Responsive layout, light/dark theme and reduced-motion preferences use the existing styles.

## Version updates

The dashboard change alone does not implement a firmware updater. Subsequent source work adds a separate signed application update workflow; see [Updates](UPDATES.md) for provisioning, package/configuration recovery and limits. Devuan/kernel updates and OS A/B rollback remain separate. The published alpha.10 ISO is unchanged by these source changes.

## Verification

Local validation: 233 Python tests (three SNMP-dependent tests skipped locally), 22 real Chromium acceptance checks, Python lint and JavaScript syntax. New coverage exercises Linux counter parsing, missing sources, computed CPU/bit rates, counter reset, telemetry error/recovery, port cards and mobile layout. Browser screenshots use controlled HTTP fixtures, not a running customer appliance.
