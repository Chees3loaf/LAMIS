# ATLAS v2.1.0.2 — Release Notes

Hotfix on top of v2.1.0.1. All four fixes target the Nokia PSI inventory path;
no feature work and no changes to the RLS Route Builder shipped in 2.1.0.1.

## 🐞 Fixes

### PSI devices all collapsed onto one workbook tab
The PSI report read the device name from `shelf_detail`, which is parsed from
`show general system-identification` — a command that carries the shelf type but
**no hostname line**. The parser therefore synthesised `"Nokia <product>"`, i.e.
`Nokia 1830`, identically on every shelf.

Two symptoms, one cause:

- **Device Name showed `Nokia 1830`** instead of the TID, even though ATLAS had
  already captured the real name via `show general name`.
- **Each PSI overwrote the previous one's tab.** The sheet title and the
  rescan-same-device match both key off that name, so every shelf resolved to
  `Nokia_1830`, deleted the prior sheet, and wrote in its place.

The workbook now consults the `system_name` DataFrame first, so the TID from
`show general name` wins. Generic product labels (`Nokia 1830`) and parser
sentinels (`Unknown`, `Error`) are no longer accepted as device identities — a
shelf with no readable TID falls through to the chassis-serial fallback and
keeps its own tab instead of colliding. Real hostnames that merely contain the
vendor name (`nokia-1830-a`, `Nokia 1830 East`) are unaffected.

### PSI shelves identified as generic 1830, running the wrong script
The Telnet identification probe decided PSI vs. PSS purely from the
`System Description` string. A PSI answers `Nokia 1830 OLS <ver> SONET ADM` —
with no `PSI` anywhere in it — so real PSI shelves were routed to the generic
1830 script. That script collects 4 datasets where the PSI pipeline collects 10
(missing `shelf_detail`, `module_inventory`, `software_info`, `slot_info`,
`redundancy_info`, `power_info`, and `topology`), and the run produced the
default workbook instead of the PSI report.

The probe now falls back to `show general system-identification` and keys off
`Shelf type` (`PSI-4L`/`PSI-8L` → PSI, `PSI-M` → PSIM) when the description
leaves the device on the generic path. PSS shelves are unchanged, and any
failure keeps the previous generic answer — the refinement can never turn a
successful identification into a failed one. Costs one extra Telnet round trip,
and only on devices that would otherwise be misrouted.

### Three minutes and a spurious credential prompt per PSI
On a PSI, SSH authentication succeeds but the shell drops you at the alarm
banner with no usable CLI — the real CLI is behind the Telnet getty. Every
identification command returned empty, and ATLAS treated that as a credential
problem: it rotated all five default credentials with 2s/4s/8s lockout backoff,
exhausted them, **prompted the operator for credentials**, then ran the entire
cascade a second time with what was entered. Only then did it reach the Telnet
probe, which identified the device in about four seconds. Measured cost on a
single shelf: **3 minutes 1 second**.

Identification now detects a completely mute shell — authentication succeeded,
a shell opened, and not one command echoed anything — and breaks straight out
to the Telnet probe. No credential can unmute a shell that the account already
authenticated against. Partial output still rotates credentials as before; the
short-circuit fires only on total silence.

### "Unreachable" reported for devices that were up
Phase 1 of a Network-mode run was labelled *Pinging* but never sent an ICMP
packet — it is a TCP connect probe on port 22, falling back to port 23. A shelf
that answers ping while serving no SSH or Telnet listener (management access not
enabled on the interface — on a PSI, remote CIT on the OAMP port) was reported
as flatly **Unreachable**, which reads as a bad address or a routing fault.

- The phase is now labelled **Probing SSH/Telnet**, matching what it tests.
- On failure, one ICMP echo classifies the result. Hosts that answer ping get
  `No SSH/Telnet listener (host answers ping)` plus a log line naming the likely
  cause, instead of being lumped in with genuinely dead addresses.
- A host actively **refusing** Telnet on port 23 is now correctly treated as up.
  Port 22 already handled refusal this way; port 23 did not.

## 📝 Docs
- `INVENTORY_LOGIC_FLOW.md` described phase 1 as `ICMP ping (Windows "ping -n 1")`
  in two places. It has never been ICMP; corrected to describe the TCP probe and
  the new failure classification.

## ✅ Tests
- Regression coverage for the device-name resolution, the shelf-type
  refinement (PSI-4L/8L, PSI-M, PSS passthrough, missing-value and abort
  fallbacks), the mute-shell short-circuit, and the updated phase breadcrumbs.
- Suite: 1749 passed, 7 pre-existing failures unrelated to this release
  (credential seeding, diaguser prefill, serial-debug knob).

## 📦 Build
- `ATLAS_Setup.exe`
- Version: `2.1.0.2` — installer product and file version, and
  `config.APP_VERSION` as reported by the running app and compared by the
  updater. (`ATLAS.exe` itself carries no Windows version resource; `ATLAS.spec`
  passes no `version=` file. Pre-existing, unchanged by this release.)
- Size: `78,551,500` bytes (`74.91 MiB`)
- SHA-256:
  `C13A7BED2ED7A7EAA723EAA1D6E352670934CE678F35DE4BEC5ECC9D008CA51F`
- Signing status: **NotSigned** (`--no-sign` build — no code-signing
  certificate present at `certs\LightRiver_codesign.pfx`; obtain one before
  external distribution where policy requires Authenticode)

## 🚀 Publishing
Clients on 2.1.0.1 will not see this build until a GitHub Release tagged
`v2.1.0.2` exists with the installer attached — the update feed is currently
still on `v2.0.10.0`, and neither `v2.1.0.1` nor `v2.1.0.2` is tagged in the
repo. The updater's version regex does accept the 4-part form, so the upgrade
will be offered once the release is published.
