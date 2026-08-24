# 7705 SAR — "what's up?" command set

A curated health check for the **classic** 7705 SAR (`System Type : 7705 SAR-8 v2`
and siblings). Every command below was verified against the 7705 SAR 24.10/25.10
documentation set — none are guesses.

All are read-only `show` commands.

> **Not on this platform:** `show system alarms` and the whole facility-alarm
> subsystem are **7705 SAR Gen 2 only**. "SAR-8 v2" is a shelf revision of the
> classic SAR, not Gen 2 — the names are easy to confuse. Classic SR OS has no
> single "list my active alarms" command, which is why alarm state has to be
> pieced together from the chassis and the event log.

## 1. Is anything alarmed?

| Command | What it tells you |
| --- | --- |
| `show chassis detail` | Critical/Major/Minor **LED state**, over-temperature, per-component `Current alarm state`, and the four external alarm inputs. This is the closest thing to an alarm list. |
| `show external-alarms input` | Contact-closure and environmental inputs, including named Ethernet-port alarms (`CABINET-DOOR`). Asserted rows read `Alarm-Detected`. |
| `show log log-id 99` | The event log — what actually *happened*, and when. The one place a transient shows up. |

## 2. Is the hardware healthy?

| Command | What it tells you |
| --- | --- |
| `show card state` | One-line view of every card/MDA: admin, operational, port count. Fastest "is anything down". |
| `show card detail` | Temperatures vs threshold, firmware status, boot reason, memory. |
| `show mda detail` | Per-adapter state, plus **Sync-E capability and timing status**. |
| `show redundancy synchronization` | Whether the standby CSM is actually in sync. A silent failure here means no protection. |
| `show system cpu` / `show system memory-pools` | Control-plane load. |

## 3. Is timing locked?

| Command | What it tells you |
| --- | --- |
| `show system sync-if-timing` | System timing state — `CSM A : Master Locked`, reference order, per-reference quality. On a mobile-backhaul network this is often the first thing to check and the easiest to miss. |

## 4. Are the interfaces and neighbours up?

This is the part you are doing by hand today.

| Command | What it tells you |
| --- | --- |
| `show port` | Every port, one line: admin/link/oper, MTU, LAG membership, optic type. |
| `show port detail` | Descriptions, **optical Tx/Rx power with the module's own DDM thresholds**, error counters. |
| `show lag` / `show lag detail` | LAG state, member up/down, LACP actor **and partner** system id. |
| `show router interface` | L3 interfaces: admin/oper, bound port, address. |
| `show router ospf neighbor` | OSPF adjacencies — the neighbour's Router Id is its `system` address. |
| `show router ospf interface` | Which interfaces OSPF is actually running on, and their state. |
| `show router ospf status` | Instance-level: area count, SPF runs, overload. |
| `show router isis adjacency` | IS-IS adjacencies (hostname-keyed, not address-keyed). |
| `show router ldp session` | LDP peers and session state. |
| `show router bgp neighbor` | BGP peers, if configured. |
| `show system lldp neighbor` | L2 neighbour system name and port — independent of any routing protocol, and the **only** command that pairs individual LAG *member* ports. OSPF reports a LAG as one interface, so without this you can tell two shelves are adjacent but not which fibre lands in which slot. `Remote Chassis ID` is the peer's base MAC, which is also its LACP System Id. |

## 5. Is the service/transport layer intact?

| Command | What it tells you |
| --- | --- |
| `show service service-using` | Every configured service and its admin/oper state. |
| `show router mpls lsp` | LSP operational state. |
| `show router rsvp session` | RSVP-signalled sessions. |
| `show aps` | APS group state, for SONET/SDH protection. |
| `show port-tree <port-id>` | SONET/SDH path containers under a port. |

## Which of these the tool already runs

`baseline_commands/7705-sar-8.txt` is the automated set (**27 commands**) and
covers sections 1, 2 (mostly), 3, 4 and 5.

Captured **and audited**: `show chassis detail`, `show external-alarms input`,
`show system sync-if-timing`, `show redundancy synchronization`,
`show port detail`, `show lag detail`, `show router interface`,
`show router ospf neighbor`, `show system lldp neighbor`.

Captured but **not yet interpreted** — the data accumulates so a parser can be
written against real output rather than guessed:

| Command | Why not parsed yet |
| --- | --- |
| `show system cpu` | Parsed into structured rows for reporting, but **not audited**: there is no defensible threshold, and the sample is taken *while the audit is driving the CLI*. On a live run `Management` read 82.97% capacity — that is the audit measuring itself. |
| `show router isis adjacency detail`, `show router isis capabilities` | No IS-IS device captured yet — every probe so far answers `MINOR: CLI ISIS instance 0 is not configured.` |
| `show log log-id 99` | Added to the 7705 baseline so onset times start accumulating. Up to 500 entries and time-ordered rather than state, so it needs a different kind of parser than the rest — raise/clear pairing, not a snapshot. It runs last for that reason. **7705 only**: the 7250 profiles share the same classic SR OS and would accept it verbatim, but were left unchanged. |

Still left out entirely:

- `show system memory-pools` — no output example in the classic docs.
- `show port-tree` — needs a port id argument, so it cannot be a fixed command.

## What is audited automatically today

| Rule | Meaning |
| --- | --- |
| `CHASSIS-001/002` | Critical / Major-Minor alarm LED lit |
| `CHASSIS-003` | Over-temperature |
| `CHASSIS-004` | A component reports an active alarm |
| `CHASSIS-005` | An external alarm input is asserted |
| `TIMING-001` | Not locked to a timing reference (FAIL) |
| `TIMING-002` | A reference is enabled but not qualified — a lost protection path |
| `TIMING-003` | Reports locked, but no reference is selected |
| `TIMING-004` | Reports locked, but the clock it tracks traces back to a device in holdover. Cross-device, like `LAGPAIR` — no single capture contains this. |
| `TIMING-005` | In holdover **because its reference sits on a port that is down** — a physical fault to dispatch against, as opposed to a node whose references are all up and merely signalling DUS, which clears itself once the real break is fixed. |
| `REDUNDANCY-001` | Standby control card not ready — no control-plane protection (FAIL) |
| `REDUNDANCY-002` | A previous standby failure is recorded |
| `OPTIC-001/002` | Optic Tx/Rx power outside the module's own DDM limits |
| `PORT-001` | A standalone port is admin-up but oper-down **and has been up before** — a break. LAG members are left to the LAG rules, and a connector is not graded alongside its own channel. |
| `PORT-002` | Enabled, down, and `Phys State Chng Cnt` is 0 — the link has never been lit, so it is a build item, not an outage. Reported at INFO so real breaks stay visible. |
| `LAG-000..004` | LAG member state and capacity |
| `LAGPAIR-000..003` | A LAG compared against its far end, once both are captured |
| `SONET-001..003` | OC-n enabled-but-down, live alarms, incomplete APS. Admin-down channels are skipped: a channelised OC3 adapter presents four ports, and the unused ones correctly report `lais`/`slof`/`slos`. |
| `SONET-004` | The far end's `Rx S1` sync quality is not traceable to a primary reference. WARN when that port is the selected timing reference — this is why a node can report `Master Locked` at `st3` — INFO elsewhere. |
| `ALARM-001` | 1830 `show condition` entries |
| `OPTICAL-010/011` | A coherent, frequency-tuned pluggable means an optical shelf carries the link. `011` names a span whose shelf was never captured — the only way to find the transport layer, since a transparent wavelength puts the far-end *router* in LLDP and OSPF. |
