# IPv4 parental controls

[Italiano](PARENTAL.md) · **English** · [Documentation](INDEX.md)

Murus filters DNS and can pause forwarding for devices that route through it. Set Murus as their gateway; a separate VM that does not see their traffic cannot enforce the profile. There is no HTTPS content inspection or full application identification.

## Set up a profile

1. Configure and confirm LAN, WAN, routing and Internet policies.
2. For stable device matching, add a DHCP reservation for its IPv4 and stable MAC, then renew the lease. If devices can change addresses, use a dedicated VLAN/SSID and cover the entire subnet.
3. In **Parental control**, download the required category lists, select the LAN and enter IPv4 devices or subnets. Maximum: eight profiles and 64 entries per profile. Label individual IPv4 devices or select existing reservations. Labels do not create reservations, and devices on different LANs require separate profiles.
4. Select categories, permanent service blocks, additional domains and any exceptions. A domain includes its subdomains. Exceptions override domain blocks but do not bypass pause or forwarding schedules. Forced DNS also prevents exceptions for known encrypted resolvers.
5. Save the draft, choose **Verifica e applica**, and confirm within 90 seconds. A selected category without a downloaded list prevents activation.

## Schedules and family settings

| Setting | Effect |
| --- | --- |
| Allowed Internet hours | Blocks forwarding outside listed hours. Empty means no restriction. |
| Night mode | Blocks forwarding during selected hours, independently of allowed hours. Preset: every day 21:00–07:00. |
| Study mode | Allows only the configured study domains in DNS, without loosening permanent blocks. Preset: Mon–Fri 16:00–18:00. Include sign-in and learning resources. |
| Social hours | Adds DNS blocks for selected services only during the specified hours. Preset: WhatsApp and Instagram Mon–Fri 15:00–19:00. |
| Temporary pause | **Pausa ora** blocks forwarding for 15 minutes to 24 hours, including existing sessions. **Riprendi** removes only the temporary pause. |
| Bonus | Temporarily bypasses night and allowed hours, up to 240 minutes. Zero revokes it. Pause, resolver failures, DNS filters and study mode still apply. |

Schedules use the profile timezone (typically Europe/Rome), support midnight and daylight saving time, and are checked every two seconds. Start is inclusive and end exclusive. Check the firewall clock. During a forwarding pause DHCP and DNS remain available; the HTTP proxy cannot bypass the pause. A resolver transition is validated before activation, and failure blocks forwarding until recovery. Pauses and bonuses persist privately on disk and are not included in native export. Bonuses are tied to the full profile configuration.

For social hours, choose **Servizi bloccati solo nelle fasce social**. Forced DNS is required. Permanent categories such as **Contenuti per adulti** remain active outside those hours. A service selected as a permanent block remains blocked all day. Explicit DNS exceptions still apply.

## DNS and lists

Each profile uses a dedicated local dnsmasq instance. Forced DNS redirects TCP/UDP 53 and blocks common encrypted DNS ports 853/784/8853. Without it, only DNS addressed to the firewall is filtered. An optional QUIC block on UDP 443 can affect other apps and cannot block all DoH.

Available HaGeZi lists ([source and GPL-3.0 license](https://github.com/hagezi/dns-blocklists)): adult (`wildcard/nsfw-onlydomains.txt`), gambling (`wildcard/gambling.mini-onlydomains.txt`), malware/phishing (`wildcard/tif.mini-onlydomains.txt`) and known bypass tools (`wildcard/doh-vpn-proxy-bypass-onlydomains.txt`). Downloads are opt-in; they are not bundled in the ISO. Limits: 16 MiB and 300,000 domains per list, 600,000 combined per profile. Invalid responses preserve the previous copy. Source, date and SHA-256 are recorded; there is no producer signature verification.

Manual updates require applying the draft. Optional automatic refresh checks active categories hourly and downloads copies at least 24 hours old. Lists older than 48 hours are flagged. Resolver validation, private previous copies and rollback protect active filtering. If rollback also fails, affected forwarding stays blocked. Pending configuration changes or maintenance defer activation. DNS may be briefly unavailable during a resolver restart.

Built-in service lists include Instagram, WhatsApp, TikTok, Facebook/Messenger, YouTube, Snapchat, Discord and Twitch. Lists can miss domains or affect other services that share them, such as `googlevideo.com`.

Google SafeSearch and YouTube Restricted Mode require forced DNS. They use local DNS aliases for supported provider names. The code uses explicit provider IPs; provider changes may require a Murus update. Domain and service blocks take precedence. The local HTTP proxy respects profile restrictions. See the [Italian guide](PARENTAL.md) for the complete provider host list.

## Local reporting and privacy

Enable **Abilita reporting locale** in the draft and apply it. Reporting is off by default. Refresh after about ten seconds. Choose 24 hours or seven days and filter by profile or IPv4/subnet. Reports contain forwarded IPv4 volumes, hourly trends, parental packet drops and up to 100 global DNS domains with query and NXDOMAIN counts. CSV exports the full selected period and all profiles. Clearing requires confirmation, removes all profiles' history and resumes collection if enabled.

Volumes include inter-network and VPN forwarding but exclude the local HTTP proxy. A DNS query is not evidence of a visit; byte counts are not attributable to domains. There is no URL or page-content log, and time spent on sites/apps is not measured. A /32 distinguishes one device; a subnet aggregates all its hosts. Samples are collected every ten seconds into one-hour UTC buckets, displayed in the browser's local time. Restarts may lose the most recent interval.

Aggregates stay in `/etc/murus_igneus/logs/parental.sqlite` (0600, directory 0700) for at most seven days, 50,000 rows or 32 MiB. High volumes can shorten history. No raw DNS logs are written to disk and reporting does not send data to AI or cloud services. Admin authentication and TOTP, if enabled, protect reports; export and clearing require CSRF. Disable collection to stop new records; prior data expires or can be cleared. Protect backups and console access.

## Limits and verification

Caches, existing connections, external VPN/proxies, unknown DoH, direct IPs, alternate gateways and mobile data can bypass domain filtering. IPv4 protection does not cover IPv6. The optional IPv6 guard blocks the **entire selected LAN through Murus**, including unassigned devices and local IPv6 access; it does not control traffic on alternate routers or directly on the same segment. Prefer a dedicated LAN/VLAN.

Large lists and multiple profiles consume RAM alongside IPS and antivirus. Changes and history in live mode without persistence are lost on reboot. Native configuration exports include profiles and reservations; lists and pauses live in private state. When using the AI assistant with a configuration draft, profile information can be included subject to its consent and redaction settings.

CI checks malformed input, IDNA, schedules, DST, feeds and pauses. The Chromium test uses the real compiler. The disposable runtime lab uses actual dnsmasq, nftables, UDP/TCP DNS, traffic, DHCP, proxy tests, resolver failure and rollback. It is not a guarantee of complete app or category coverage.
