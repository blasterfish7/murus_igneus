# Native networking — alpha.4

This milestone adds independent native VLAN, DHCP/DNS, DNAT and connection views.
It does not reuse Fortinet code, firmware or assets. The backup importer remains
conservative: support for these native features does not make proprietary backup
sections automatically importable.

## VLAN

Declare the physical parent in Interfaces, with or without an IPv4 address. Add
another interface with a unique Linux device name (e.g. `eth2.20`), `parent=eth2`,
`vlan_id=20` and its IPv4/prefix. The parent must be a declared physical data port;
management, loopback, VPN parents, nested VLANs and duplicate parent/tag pairs are
rejected. Maximum 64 VLANs. Linux device names are limited to 15 safe characters.
Existing unrelated VLANs cannot be adopted by name: runtime verifies the Murus
ownership alias, tag and parent. A tag change removes owned routes/addresses
before recreating the device. Rollback recreates the old VLAN before restoring
its addresses/routes. Removal does not remove the physical parent.

## DHCP and DNS

DHCP has one IPv4 pool per static data interface, with a 1–168 hour lease. Start
and end must be inside its subnet and exclude network, broadcast and firewall
address. The gateway advertised is the interface address. Specify up to four DNS
server addresses, or leave them empty when local DNS is enabled on that interface.
Do not enable a pool on a segment that already has an authoritative DHCP server.
Reservations, relay, DHCPv6 and delegated prefixes are not implemented.

DNS provides caching/forwarding and DHCP lease names with a local domain.
Unresolved names within that domain are kept local rather than forwarded upstream. Select
the data interfaces and up to eight explicit upstream IPv4 resolvers. There is no
automatic `/etc/resolv.conf` fallback or `/etc/hosts` import. No DNSSEC or DNS
category filtering is claimed. Forwarding to the firewall itself is rejected.
DNS input is allowed only from the selected interface subnet to its local IPv4;
WAN and management receive no new DNS/DHCP firewall permission implicitly.

The application supervises a dedicated `dnsmasq-base` executable (GPL), using a
generated standalone config under `/run/murus-igneus`. Installing `dnsmasq-base`
does not enable the distribution's separate dnsmasq service. The process is
restarted inside the apply/rollback transaction. Lease storage is
`/var/lib/murus-igneus/dnsmasq.leases`, copied during web installation; existing
lease rows can outlive the pool configuration that created them.

## Port forwarding

Each enabled publication is an explicit firewall permission, evaluated before
ordinary forward policies. The GUI and preview warn about this ordering. It
contains an ID, source CIDR, ingress interface, explicit public IPv4, TCP or UDP
port, target interface, internal host and target port. Public IPv4 must equal the
static ingress interface address. Target must be a usable host on the specified
different internal subnet. Duplicate public tuples and conflicts with the enabled
WireGuard listener are rejected. A disabled entry retains its settings without
installing NAT or permit rules.

The permit checks DNAT conntrack status, original destination/port, source,
translated target/port and both interfaces. Direct traffic to the internal host
does not gain permission. Suricata's subsequent forward hook still inspects
permitted DNAT flows when enabled. No hairpin NAT, address aliases, port ranges,
one-to-one NAT, IPv6 or automatic FortiGate VIP conversion is implemented.

## Connections and logs

The authenticated, read-only `/api/traffic` endpoint returns a bounded IPv4
conntrack sample (500 rows / 256 KiB), including original/reply tuples, state and
optional byte/packet accounting. Missing tools/permissions are reported; absent
kernel accounting is shown as unavailable. Events include enabled policy/DNAT
log prefixes from the tail of the kernel buffer, subject to rate limiting.
There is no persistent traffic archive, full flow accounting, deletion of sessions
or guarantee that every packet/event is represented. Network namespaces can have
kernel logging disabled independently. The GUI filters the current sample and
can refresh every five seconds while visible.

## Validation

Unit/regression tests cover malformed/injected settings, unsafe pools, management
overlaps, foreign VLAN collisions, tag rollback order, DNS listener permissions,
original-tuple DNAT checks, VPN port conflicts, old backup equivalence and bounded
telemetry parsing. CI also executes `tools/validate-native-networking.py` under
`unshare --mount --net` on a disposable Linux runner. This exchanges real VLAN,
DHCP, DNS and TCP DNAT packets, checks denied sources/direct access and exercises
rollback. Its JSON report is an Actions artifact. These checks do not substitute
for Devuan ISO boot/install, physical-switch or hardware acceptance. Historical
alpha.3 ISO results remain specific to alpha.3.

Protocol references: [dnsmasq manual](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)
and [nftables manual](https://netfilter.org/projects/nftables/manpage.html).

The real Chromium GUI harness is `tools/validate-networking-browser.cjs`, with
a loopback HTTP fixture that disables system commands and application. It creates
physical/VLAN interfaces, DHCP/DNS and a publication through the forms and passes
the resulting draft to the real backend compiler. Runtime health/traffic responses
in that harness are controlled fixtures; actual packet acceptance is separate.
The ISO job also boots the exact generated image with OVMF UEFI in QEMU TCG and
executes the packet suite using the modules actually installed in that image.
It verifies the real HTTPS backend and graceful poweroff; it does not test disk
installation or physical hardware. Its JSON report includes the ISO SHA-256.
