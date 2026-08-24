# Nokia Network Audit — Standalone Tool

This package is intentionally independent of ATLAS. It currently provides a
transcript-first topology and health audit for:

- Nokia 7705 SAR-8
- Nokia 7250 IXR-R6, IXR-R6d, and IXR-R6dl
- Nokia 1830 PSS-8 with SFDC8B filters
- 1G, 10G, and 100G Ethernet links and LAGs
- OC-3/STM-1, OC-12/STM-4, and OC-48/STM-16 links

## Run

This works right now — the sample captures are committed:

```powershell
py -3 -m nokia_network_audit .\tests_network_audit\fixtures
```

Arguments may be files, directories, or wildcards. Wildcards are expanded by the
tool rather than the shell, because PowerShell hands `*.txt` to a native command
unexpanded.

### Auditing your own devices

Put transcripts in `captures\` and point at the directory:

```powershell
py -3 -m nokia_network_audit .\captures
```

`captures\` is git-ignored (as is `*.log`) so raw device output never lands in a
commit. Three ways to fill it:

- **The toolbar button** — the intended path. It writes `transcript.txt` and runs
  the audit in one press. See
  [`nokia_network_audit/securecrt/README.md`](nokia_network_audit/securecrt/README.md).
- **SecureCRT session log** — *File → Log Session*, run the commands from
  `baseline_commands\`, then copy the log into `captures\`.
- **The SSH capture module** — see "Production baseline capture" below.

Any terminal log parses; there is no required file naming or extension beyond
`.txt`/`.log` when expanding a directory.

The default output directory contains:

- `audit.json` — structured device, link, evidence, and finding data
- `audit.md` — human-readable findings

Specify a different directory with `--output`.

Run the dependency-free test suite with:

```powershell
py -3 -m unittest discover -s tests_network_audit -v
```

## SecureCRT button (audit the session you are already in)

The usual way to run this in the field. Press a toolbar button while logged
into a device and it captures the baseline over that existing session — no
second connection, no credentials, works through jump hosts, telnet, and
serial consoles.

See [`nokia_network_audit/securecrt/README.md`](nokia_network_audit/securecrt/README.md)
for the four-step button setup.

## Production baseline capture

Preview the exact commands before connecting:

```powershell
py -3 -m nokia_network_audit.capture --host 10.0.0.10 --username admin `
  --profile 7705-sar-8 --preview
```

Capture over SSH:

```powershell
py -3 -m nokia_network_audit.capture --host 10.0.0.10 --username admin `
  --profile 7705-sar-8
```

Available profiles are `7705-sar-8`, `7250-ixr-r6`, `7250-ixr-r6d`,
`7250-ixr-r6dl`, and `1830-pss-8`. Passwords are prompted without echo and are
not stored in the transcript. Key authentication can be enabled with
`--use-keys`.

Host keys are rejected unless already trusted by the system. For the first
connection, independently verify the fingerprint and add it to known hosts.
`--accept-new-host-key` exists for controlled lab use but should not be the
normal production workflow.

The runner enforces a strict command allowlist: every entry in a profile's
`commands` must begin with `show`. Pagination setup is held separately in
`CommandProfile.paging_command` and checked against its own two-entry
allowlist, so it cannot be used as a hole in the `show`-only rule:

- SR OS classic — `environment no more`
- 1830 PSS — `paging status disabled` (R24.12 CLI Guide §2.16, p207; the value
  is `disabled`, not `disable`)

Profiles containing `configure`, `clear`, `admin`, reset, or other
operationally mutating commands are rejected.

Equivalent command lists for manual terminal capture are in
`baseline_commands/`.

Start with one device of each platform during a maintenance-aware observation
window. Some detail commands can produce substantial CPM output on a large
system even though they are read-only. Review CPU and session policy locally
before expanding to the full network.

## Current milestone

The first milestone is deliberately offline and deterministic:

1. Parse saved command transcripts.
2. Normalize device, port, LAG, SONET/SDH, optic, and wavelength data.
3. Build evidence-bearing candidate topology edges.
4. Audit mixed LAG rates, failed members, SONET/SDH state and alarms, APS
   completeness, optic power against the module's own DDM limits, equipment
   alarms, and weak topology evidence.

The parsers are validated against real captures from a 7250 IXR-R6, a 7705
SAR-8 v2, and an 1830 PSS-8 (`tests_network_audit/fixtures/`). That matters
more than it sounds: `show port detail` prints **two label/value columns per
line**, so a value read to end-of-line silently swallows the next label —
`Oper State` came back as `up   Config Duplex : full`, which made every port
look down. Ports also are not all `slot/mda/port` (`1/1/c7/1`, `A/gnss`), and
`Description` is printed *above* the identifying `Interface :` line.

### Topology

Links come only from adjacency the equipment reports about itself:

| Source | Gives | Confidence |
| --- | --- | --- |
| `show router ospf neighbor` | peer's **system address** (its Router ID) | 0.75 – 1.00 |
| `show interface topology *` (1830) | peer NE's management address | 0.75 – 1.00 |
| frequency + matching circuit ID | candidate optical pair | 0.85 |

Two join keys let independent captures be stitched together, both verified
against live equipment:

- **OSPF Router ID = the peer's `system` interface address.** So a neighbour
  named `172.16.245.193` resolves to whichever captured device owns that
  address.
- **A `/31` makes the far-end interface address arithmetic.** Local
  `172.18.6.106/31` means the peer is `172.18.6.107`; finding that address in
  the peer's own capture pins the link to a **port on both ends** and proves
  each device reported the same adjacency independently — worth 1.00.

A link reported by both ends is one row carrying both pieces of evidence, not
two rows. Corroboration requires identifying the *same pairing*, not merely that
the two devices name each other — they can peer on several ports, so "the peer
mentions me somewhere" would stamp 1.00 on one-sided evidence. A pairing is
provable when the /31 far-end address is one of the peer's interface addresses,
when both ends report the same optical channel, or when the far-end port we were
handed is a port the peer reports back under that same name.

**Known limitation — 1830 line ports appear twice.** `show interface topology *`
names the *far* end with a numeric port index (`1/3/4`) while the device itself
uses the symbolic AID (`1/3/LINEOUT`; the CLI guide defines the form as
`<shelf>/<slot>/LINEIN`). No mapping between the two exists in device output, so
a bidirectional line span shows as two 0.95 rows rather than one confirmed row.
Optical *channel* links do not have this problem — the wavelength identifies
both ends, so they resolve to a single 1.00 row.

Frequency correlation runs only for channels nothing has already claimed, and
requires a matching circuit ID: wavelengths are reused everywhere, so pairing
every same-frequency channel produced O(n²) candidates that were almost all
wrong.

**Port descriptions are deliberately not used to build links.** The convention
(`MOPN001_7250 1/1/1 to MOPN001_7705 1/1/5`) looks authoritative but is
hand-written, and real equipment shows why it cannot be trusted: the 7250 gives
*both* `1/1/1` and `1/2/1` that same text because it was copied between LAG
members. Believing it produced a 1.00-confidence link from a port that does not
carry it. Peer *names* instead come from the interface name (`to_BKLY001_7250`),
which sits on the same object as the protocol adjacency that proves the link.

### Every LAG checked against its far end

A LAG reports itself healthy whenever its own members are up — which is exactly
the case that hides a mismatch. The far end can have a different number of
members, or members at another rate, and each device still looks fine on its own.
So once both ends of a LAG have been captured, they are compared:

| Rule | Meaning |
| --- | --- |
| `LAGPAIR-000` | Both ends agree — same member count, same rates, same number up |
| `LAGPAIR-001` | Member count differs between the two ends (FAIL) |
| `LAGPAIR-002` | Member rates differ between the two ends (FAIL) |
| `LAGPAIR-003` | One end has a member down that the other does not (WARN) |

The two ends are paired on **LACP System Id**, not LAG number: nothing requires
an operator to use the same number on both sides, and in practice they diverge.
This is an independent join key from the OSPF/`/31` pairing used for links, so
the two corroborate each other.

No extra commands are needed — `show lag detail` already returns every LAG with
its LACP actor and partner state.

### Hops and the capture worklist

`audit.md` reports shortest hop count between audited devices (breadth-first
over discovered links), and a **Reported but not audited** table — the peers your
devices name but which were not captured. That is the worklist: the network
tells you what else exists, one row per device rather than one per alias.

Note this is *topology* distance, not a management path.

The worklist also says **how to get a session** on each missing peer, which
differs by platform:

| Platform | Reaching a neighbour |
| --- | --- |
| 7705 SAR / 7250 IXR (SR OS) | `telnet` and `ssh` exist at the root of the CLI, so the router works as a stepping stone: `telnet [ip-address \| dns-name] [port] [router router-instance]` (7705 SAR Basic System Configuration Guide 25.10.R1, basic command reference). An OSPF neighbour's system address is reachable in the instance the adjacency lives in. |
| 1830 PSS | No CLI client — the general CLI is config/echo/help/history/logout/paging/prompt/session/show. Reach a remote NE by **direct IP**; the gateway NE routes DCN traffic over the OSC (1830 DCN Planning and Engineering Guide). |

These are suggestions printed for a person. `telnet` and `ssh` are not read-only,
so neither is in any capture profile, and the toolbar button never runs one — a
nested session changes the prompt underneath the reader, which is exactly the
failure mode that made an early capture unusable.

### Not yet validated

SONET/SDH **port parsing**. The captures on hand carry DS1/E1 and C37.94 ports
but no OC-n, and the vendor doc set has no verbatim SONET `show port detail`
output to work from. The SONET rules are covered by tests built from model
objects, so the logic is exercised, but the parsing path needs a real
OC-3/12/48 capture before it can be trusted.

## Next milestone

Add live, read-only collectors behind a common `Collector` protocol:

- SR OS classic CLI collector for the 7705 SAR-8
- SR OS MD-CLI collector for IXR-R6/R6d/R6dl
- 1830 PSS CLI collector
- LLDP, OSPF, IS-IS, BGP, LACP-partner, PPP/MLPPP, APS, and optical PM parsers
- bounded recursive discovery with checkpoints and allowlists

Live collection must save the raw transcript before parsing it. This keeps the
audit reproducible and allows parser tests to be built from sanitized field
captures without repeatedly accessing equipment.
