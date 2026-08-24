from __future__ import annotations

import re
from collections import Counter

from .models import (
    AuditSnapshot,
    DeviceKind,
    Finding,
    FindingSeverity,
    Platform,
    SONET_RATES_BPS,
)


class AuditEngine:
    def run(self, snapshot: AuditSnapshot) -> list[Finding]:
        snapshot.finalize()
        findings: list[Finding] = []
        for device in snapshot.devices.values():
            findings.extend(self._identity(device))
            findings.extend(self._lags(device))
            findings.extend(self._ports(device))
            findings.extend(self._sonet(device))
            findings.extend(self._optics(device))
            findings.extend(self._optical(device))
            findings.extend(self._chassis(device))
            findings.extend(self._timing(device))
            findings.extend(self._redundancy(device))
            findings.extend(self._alarms(device))
        findings.extend(self._lag_pairs(snapshot))
        findings.extend(self._sync_tree(snapshot))
        findings.extend(self._dwdm_spans(snapshot))
        findings.extend(self._links(snapshot))
        snapshot.findings = findings
        return findings

    def _dwdm_spans(self, snapshot):
        """Router ports riding a DWDM line system, and whether its shelf was audited.

        Nothing in a router capture names the optical shelf in front of it: a
        transparent wavelength puts the far-end *router* into LLDP and OSPF, so
        the whole transport layer is invisible from the routed view, and each
        shelf is the only thing that knows its own span partner.

        The pluggable gives it away. A coherent, frequency-tuned module is
        talking to a line system; a grey QSFP28 on 1310 nm is a direct fibre.
        Across a 128-device network this picked out 12 ports at exactly the six
        sites that have an 1830, with nothing else matching -- so it is a
        reliable way to find the shelves that still need capturing, and the
        frequency names the channel to look for when you get there.
        """
        # One shelf serves the whole site: GRIZ001_1830 carries both 9310 and
        # 9320, the wavelengths used by GRIZ001_7250 and GRIZ002_7250. Keying on
        # the shelf number rather than the site therefore reported GRIZ002 as
        # unaudited when its shelf was sitting in the snapshot.
        def site_of(device):
            return re.sub(r"\d+$", "", device.device_id.split("_")[0])

        optical_sites = {
            site_of(device)
            for device in snapshot.devices.values()
            if device.kind is DeviceKind.OPTICAL
        }
        findings = []
        for device in snapshot.devices.values():
            if device.kind is not DeviceKind.ROUTER:
                continue
            site = site_of(device)
            for port in sorted(device.ports.values(), key=lambda p: p.port_id):
                optic = port.optic
                if optic is None or not optic.coherent or not optic.frequency_thz:
                    continue
                channel = optic.itu_channel
                where = f"{optic.frequency_thz:g} THz"
                if channel:
                    where += f" (channel {channel})"
                if site in optical_sites:
                    findings.append(
                        Finding(
                            "OPTICAL-010",
                            FindingSeverity.PASS,
                            f"{device.device_id}:{port.port_id}",
                            f"Coherent span at {where}; the optical shelf at "
                            f"{site} was audited.",
                            evidence=[f"optic {optic.part_number or ''}".strip()],
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            "OPTICAL-011",
                            FindingSeverity.INFO,
                            f"{device.device_id}:{port.port_id}",
                            f"Coherent span at {where}, so an optical shelf "
                            f"carries this link, but no shelf at {site} was "
                            "captured. Nothing in a router names it -- seed it "
                            "by management address to audit the span.",
                            evidence=[f"optic {optic.part_number or ''}".strip()],
                        )
                    )
        return findings

    def _sync_timing_upstream(self, device):
        """The device the selected timing reference comes from, if identifiable.

        The reference names a source port; LLDP says who is on the other end of
        that port, and the port description names it when LLDP does not. Sync-E
        rides the port, so the far end of the port is the upstream clock.
        """
        reference = next(
            (r for r in device.timing.references if r.selected == "Yes"), None
        )
        port = reference.source_port if reference else None
        if not port:
            return None
        parent = port.rsplit("/", 1)[0]
        for adjacency in device.adjacencies:
            if adjacency.protocol == "lldp" and adjacency.local_port in (port, parent):
                return adjacency.remote
        candidate = device.ports.get(port) or device.ports.get(parent)
        description = candidate.description if candidate else None
        if description and " to " in description:
            return description.split(" to ")[-1].split()[0]
        return None

    def _sync_tree(self, snapshot):
        """Follow each device's timing upstream and report what it really tracks.

        ``TIMING-001`` catches a device that admits it is in holdover. What it
        cannot see is the far more common consequence: everything *downstream* of
        that device still reports ``Master Locked`` at ``eec2`` and looks
        perfectly healthy, while the clock it is tracking is a free-running
        oscillator.

        On a live network this was the whole picture rather than an edge case --
        40 of 40 devices traced back to one of two nodes in holdover, and only
        those two showed any symptom. A per-device rule cannot find that, because
        no single capture contains it.
        """
        upstream = {}
        holdover = set()
        for name, device in snapshot.devices.items():
            if not device.timing.reported:
                continue
            upstream[name] = self._sync_timing_upstream(device)
            if any(
                "holdover" in str(state).lower()
                for state in device.timing.status.values()
            ):
                holdover.add(name)

        findings = []
        for name in sorted(upstream):
            if name in holdover:
                continue  # TIMING-001 already speaks for this one.
            seen = {name}
            current = name
            root = None
            while True:
                nxt = upstream.get(current)
                if nxt is None or nxt not in upstream or nxt in seen:
                    root = current if current in holdover else None
                    break
                seen.add(nxt)
                current = nxt
                if current in holdover:
                    root = current
                    break
            if root is None:
                continue
            hops = len(seen) - 1
            findings.append(
                Finding(
                    "TIMING-004",
                    FindingSeverity.WARN,
                    snapshot.devices[name].device_id,
                    f"Reports locked, but its timing traces back to {root}, "
                    f"which is in holdover ({hops} hop{'s' if hops != 1 else ''} "
                    "upstream). The reference is not traceable to a real source.",
                    evidence=["show system sync-if-timing"],
                )
            )
        return findings

    def _lag_pairs(self, snapshot):
        """Check every LAG against its far end, where both ends were captured.

        A LAG looks healthy from one side whenever its own members are up, which
        is exactly the case that hides a misconfiguration: the far end can have a
        different number of members, or members at a different rate, and each
        device will still report itself as fine. The two ends are paired on LACP
        System Id rather than LAG number, because nothing requires an operator to
        use the same number on both sides.
        """
        findings = []
        by_system: dict[str, list] = {}
        for device in snapshot.devices.values():
            for lag in device.lags.values():
                if lag.system_id:
                    by_system.setdefault(lag.system_id.lower(), []).append((device, lag))

        seen: set[tuple[str, str, str, str]] = set()
        for device in snapshot.devices.values():
            for lag in device.lags.values():
                partner = (lag.partner_system_id or "").lower()
                if not partner or not lag.system_id:
                    continue
                for far_device, far_lag in by_system.get(partner, []):
                    if far_device.device_id == device.device_id:
                        continue
                    if (far_lag.partner_system_id or "").lower() != lag.system_id.lower():
                        continue
                    key = tuple(
                        sorted(
                            [
                                (device.device_id, lag.lag_id),
                                (far_device.device_id, far_lag.lag_id),
                            ]
                        )
                    )
                    flat = (key[0][0], key[0][1], key[1][0], key[1][1])
                    if flat in seen:
                        continue
                    seen.add(flat)
                    findings.extend(self._compare_lag(device, lag, far_device, far_lag))
        return findings

    def _compare_lag(self, device, lag, far_device, far_lag):
        subject = (
            f"{device.device_id}:lag-{lag.lag_id} <-> "
            f"{far_device.device_id}:lag-{far_lag.lag_id}"
        )
        evidence = [f"LACP System Id {lag.system_id} / {far_lag.system_id}"]
        findings = []

        near_count, far_count = len(lag.members), len(far_lag.members)
        if near_count and far_count and near_count != far_count:
            findings.append(
                Finding(
                    "LAGPAIR-001",
                    FindingSeverity.FAIL,
                    subject,
                    f"Member count differs: {device.device_id} has {near_count}, "
                    f"{far_device.device_id} has {far_count}.",
                    evidence=evidence,
                )
            )

        near_rates = sorted({m.rate for m in lag.members if m.rate})
        far_rates = sorted({m.rate for m in far_lag.members if m.rate})
        if near_rates and far_rates and near_rates != far_rates:
            findings.append(
                Finding(
                    "LAGPAIR-002",
                    FindingSeverity.FAIL,
                    subject,
                    f"Member rates differ: {device.device_id} {near_rates}, "
                    f"{far_device.device_id} {far_rates}.",
                    evidence=evidence,
                )
            )

        near_up = sum(1 for m in lag.members if (m.oper_state or "").lower() == "up")
        far_up = sum(1 for m in far_lag.members if (m.oper_state or "").lower() == "up")
        if near_count and far_count and near_up != far_up:
            findings.append(
                Finding(
                    "LAGPAIR-003",
                    FindingSeverity.WARN,
                    subject,
                    f"Operational member count differs: {near_up} up on "
                    f"{device.device_id}, {far_up} on {far_device.device_id}.",
                    evidence=evidence,
                )
            )

        if not findings:
            capacity = lag.operational_capacity_bps
            detail = f"{near_up} members up each side"
            if capacity and capacity == far_lag.operational_capacity_bps:
                detail += f"; {capacity} bps both ends"
            findings.append(
                Finding(
                    "LAGPAIR-000",
                    FindingSeverity.PASS,
                    subject,
                    f"Both ends agree: {detail}.",
                    evidence=evidence,
                )
            )
        return findings

    def _identity(self, device):
        if device.platform == Platform.UNKNOWN:
            return [
                Finding(
                    "IDENTITY-001",
                    FindingSeverity.UNKNOWN,
                    device.device_id,
                    "Platform could not be identified.",
                )
            ]
        return [
            Finding(
                "IDENTITY-000",
                FindingSeverity.PASS,
                device.device_id,
                f"Identified as {device.platform.value}.",
            )
        ]

    def _lags(self, device):
        findings = []
        for lag in device.lags.values():
            subject = f"{device.device_id}:lag-{lag.lag_id}"
            rates = [m.rate for m in lag.members if m.rate]
            if rates and len(set(rates)) > 1:
                findings.append(
                    Finding(
                        "LAG-001",
                        FindingSeverity.FAIL,
                        subject,
                        f"Mixed member rates detected: {sorted(set(rates))}.",
                    )
                )
            down = [m.port_id for m in lag.members if (m.oper_state or "").lower() != "up"]
            unrated = [m.port_id for m in lag.members if m.rate_bps is None]
            if down:
                findings.append(
                    Finding(
                        "LAG-002",
                        FindingSeverity.WARN,
                        subject,
                        f"Non-operational members: {', '.join(down)}.",
                    )
                )
            elif unrated:
                # Reporting a capacity here would understate the LAG, because
                # members whose rate was not captured contribute zero.
                findings.append(
                    Finding(
                        "LAG-004",
                        FindingSeverity.UNKNOWN,
                        subject,
                        f"{len(lag.members)} members operational, but the rate of "
                        f"{', '.join(unrated)} was not captured, so capacity "
                        "cannot be totalled.",
                    )
                )
            elif lag.members:
                findings.append(
                    Finding(
                        "LAG-000",
                        FindingSeverity.PASS,
                        subject,
                        f"{len(lag.members)} members operational; capacity "
                        f"{lag.operational_capacity_bps} bps.",
                    )
                )
            else:
                findings.append(
                    Finding(
                        "LAG-003",
                        FindingSeverity.UNKNOWN,
                        subject,
                        "LAG was found but member detail was not collected.",
                    )
                )
        return findings

    def _ports(self, device):
        """A port that is enabled but not passing traffic.

        The most basic fault there is, and nothing reported it: ``_lags`` only
        looks at ports that are LAG members, so a standalone link could be dead
        and the audit would say nothing. A live run had 28 such ports -- among
        them both of STJO's uplinks to DITT, which is what put that site's
        timing reference into LOS and dropped it into holdover.

        Admin-down ports are deliberately excluded: taking a port out of service
        is a decision someone made, not a fault. Ports carrying a sublayer (a
        connector such as ``1/2/c7`` alongside its channel ``1/2/c7/1``) report
        oper state on both, so only the leaf is graded to avoid counting one
        break twice.

        A down port splits into two very different work items, and
        ``Phys State Chng Cnt`` tells them apart: a link that has never once
        transitioned has never been lit, so it is a build item rather than an
        outage. Checked against field-confirmed examples of each -- four spans to
        sites that are live in the field all read 2, and twelve spans to shelves
        that are not yet fibered in all read 0, with no overlap. When the counter
        is absent (TDM and microwave ports do not print it) the port is graded as
        a fault, because nothing here proves it was never working.
        """
        members = {
            member.port_id
            for lag in device.lags.values()
            for member in lag.members
        }
        parents = {
            port_id.rsplit("/", 1)[0]
            for port_id in device.ports
            if "/" in port_id
        }
        findings = []
        for port_id, port in sorted(device.ports.items()):
            if port_id in members or port_id in parents:
                continue
            if port.rate in SONET_RATES_BPS:
                continue  # SONET-001 owns these, in SONET's own vocabulary
            if (port.admin_state or "").lower() != "up":
                continue
            if (port.oper_state or "").lower() == "up":
                continue
            described = f" ({port.description})" if port.description else ""
            if port.phys_state_changes == 0:
                findings.append(
                    Finding(
                        "PORT-002",
                        FindingSeverity.INFO,
                        f"{device.device_id}:{port_id}",
                        f"Port is enabled but its physical link has never come "
                        f"up{described}. Provisioned and not yet connected, "
                        "rather than a failure.",
                        evidence=["show port detail: Phys State Chng Cnt 0"],
                    )
                )
                continue
            seen = (
                f" The link has changed state {port.phys_state_changes} times, "
                "so it has carried traffic before."
                if port.phys_state_changes
                else ""
            )
            findings.append(
                Finding(
                    "PORT-001",
                    FindingSeverity.WARN,
                    f"{device.device_id}:{port_id}",
                    f"Port is administratively up but operationally "
                    f"{port.oper_state or 'not up'}{described}.{seen}",
                    evidence=["show port"],
                )
            )
        return findings

    def _sonet(self, device):
        """SONET/SDH ports, including the sync quality they carry.

        These rules existed but had never once fired: they gate on the port rate
        being a known OC-n, and the rate was never read because a SONET port
        labels it "Speed" where Ethernet says "Oper Speed". Sixty OC3 ports in a
        live network produced no findings of any kind.

        Turning them on required care about what a *spare* channel looks like. A
        channelised OC3 adapter presents four ports and typically has one in
        service; the rest sit admin-down and quite correctly report ``lais``,
        ``slof`` and ``slos``, because there is no signal and nobody expects one.
        Grading those would have added forty confident failures about equipment
        working exactly as configured, so admin-down ports are skipped here for
        the same reason ``_ports`` skips them.
        """
        reference_ports = {
            reference.source_port
            for reference in device.timing.references
            if reference.selected == "Yes" and reference.source_port
        }
        findings = []
        for port in sorted(device.ports.values(), key=lambda p: p.port_id):
            if port.rate not in SONET_RATES_BPS:
                continue
            if (port.admin_state or "").lower() != "up":
                continue
            subject = f"{device.device_id}:{port.port_id}"
            operational = (port.oper_state or "").lower() == "up"
            if not operational:
                findings.append(
                    Finding(
                        "SONET-001",
                        FindingSeverity.FAIL,
                        subject,
                        f"{port.rate.upper()} port is enabled but not "
                        f"operationally up.",
                    )
                )
            if port.alarms:
                findings.append(
                    Finding(
                        "SONET-002",
                        FindingSeverity.FAIL,
                        subject,
                        f"Active SONET/SDH alarms: {', '.join(port.alarms)}.",
                    )
                )
            if port.aps_group and not port.aps_role:
                findings.append(
                    Finding(
                        "SONET-003",
                        FindingSeverity.WARN,
                        subject,
                        "APS group is present but working/protection role is unknown.",
                    )
                )
            if not operational:
                continue
            # The S1 byte is the far end's advertised sync quality. A port can be
            # flawless and still be handing over holdover-grade timing, which no
            # up/down or alarm field shows: three live 7705s report "Master
            # Locked" at st3 for exactly this reason, and nothing said why.
            quality = port.sonet.rx_s1_quality
            if quality and port.sonet.rx_traceable is False:
                is_reference = port.port_id in reference_ports
                findings.append(
                    Finding(
                        "SONET-004",
                        FindingSeverity.WARN if is_reference else FindingSeverity.INFO,
                        subject,
                        f"Far end advertises sync quality {quality} "
                        f"({port.sonet.rx_s1}), which is not traceable to a "
                        "primary reference"
                        + (
                            "; this port is the selected timing reference, so "
                            "the node can only be as good as this."
                            if is_reference
                            else "."
                        ),
                        evidence=["show port detail: Rx S1 Byte"],
                    )
                )
        return findings

    def _optics(self, device):
        """Compare each pluggable's live power against its own DDM limits."""
        findings = []
        for port in device.ports.values():
            optic = port.optic
            if optic is None:
                continue
            subject = f"{device.device_id}:{port.port_id}"
            for direction, value, limits in (
                ("Tx", optic.tx_dbm, optic.tx_limits),
                ("Rx", optic.rx_dbm, optic.rx_limits),
            ):
                verdict = limits.classify(value)
                if verdict is None:
                    continue
                bounds = (
                    f"high alarm {limits.high_alarm} dBm, "
                    f"low alarm {limits.low_alarm} dBm"
                )
                findings.append(
                    Finding(
                        "OPTIC-001" if verdict == "alarm" else "OPTIC-002",
                        FindingSeverity.FAIL
                        if verdict == "alarm"
                        else FindingSeverity.WARN,
                        subject,
                        f"{direction} power {value} dBm is outside the module's "
                        f"{verdict} threshold ({bounds}).",
                        evidence=[f"optic {optic.part_number or optic.model or ''}".strip()],
                    )
                )
        return findings

    def _chassis(self, device):
        """Raise what a classic SR OS chassis says about its own health.

        Classic 7705 SAR and 7250 IXR have no "list active alarms" command --
        ``show system alarms`` and the facility-alarm subsystem are 7705 SAR
        Gen 2 only. What they report is in ``show chassis detail``: the
        front-panel LEDs, over-temperature state, a per-component alarm state,
        and the external alarm inputs. All of it was already being captured and
        none of it was being read, so routers showed no alarm state at all while
        the 1830s produced findings from ``show condition``.
        """
        health = device.chassis
        if not health.reported:
            return []

        findings = []
        subject = device.device_id
        for lit in health.leds_lit:
            name = lit.split("=")[0]
            findings.append(
                Finding(
                    "CHASSIS-001" if name == "Critical" else "CHASSIS-002",
                    FindingSeverity.FAIL if name == "Critical" else FindingSeverity.WARN,
                    subject,
                    f"{name} alarm LED is lit ({lit.split('=', 1)[1]}).",
                    evidence=["show chassis detail"],
                )
            )

        if health.over_temperature_ok is False:
            findings.append(
                Finding(
                    "CHASSIS-003",
                    FindingSeverity.FAIL,
                    subject,
                    f"Over-temperature state is {health.over_temperature}.",
                    evidence=["show chassis detail"],
                )
            )

        for component in health.components_in_alarm:
            findings.append(
                Finding(
                    "CHASSIS-004",
                    FindingSeverity.WARN,
                    subject,
                    f"Component reports an active alarm - {component}.",
                    evidence=["show chassis detail"],
                )
            )

        for entry in health.external_inputs:
            if not entry.asserted:
                continue
            severity = (entry.severity or "").strip().lower()
            findings.append(
                Finding(
                    "CHASSIS-005",
                    FindingSeverity.FAIL
                    if severity in {"critical", "major"}
                    else FindingSeverity.WARN,
                    f"{subject}:{entry.input_id}",
                    "External alarm input %s is asserted (%s, state %s)."
                    % (
                        entry.name or entry.input_id,
                        entry.severity or "unclassified",
                        entry.state,
                    ),
                    evidence=["external alarm input"],
                )
            )

        if not findings:
            detail = "LEDs off"
            if health.over_temperature:
                detail += f", temperature {health.over_temperature}"
            if health.external_inputs:
                detail += f", {len(health.external_inputs)} external input(s) clear"
            findings.append(
                Finding(
                    "CHASSIS-000",
                    FindingSeverity.PASS,
                    subject,
                    f"Chassis reports no alarm: {detail}.",
                    evidence=["show chassis detail"],
                )
            )
        return findings

    def _timing(self, device):
        """Check the node is locked to a timing reference.

        A node running on its own oscillator lights no LED and changes no
        interface state, so nothing else in this audit would notice. On a network
        carrying Sync-E that silence is the problem.
        """
        timing = device.timing
        if not timing.reported:
            return []

        findings = []
        subject = device.device_id
        if timing.unlocked:
            findings.append(
                Finding(
                    "TIMING-001",
                    FindingSeverity.FAIL,
                    subject,
                    "Not locked to a timing reference: "
                    + ", ".join(timing.unlocked)
                    + ".",
                    evidence=["show system sync-if-timing"],
                )
            )

        # Why the node lost its clock, where the capture can say so. A holdover
        # node whose reference sits on a physically down port has a cause you can
        # dispatch against; one whose references are all up but signalling DUS is
        # a *consequence* -- its neighbours stopped offering timing because the
        # tree lost its root elsewhere. Separating the two is the difference
        # between "send a truck to this span" and "fix it upstream and this
        # clears itself".
        #
        # Confirmed on a live network: of six nodes in holdover, four had a
        # reference on a broken span and two did not, and only the first four
        # were worth a work order.
        if timing.unlocked:
            broken = []
            for reference in timing.references:
                port_id = reference.source_port
                if not port_id:
                    continue
                port = device.ports.get(port_id) or device.ports.get(
                    port_id.rsplit("/", 1)[0]
                )
                if port is None:
                    continue
                if (port.admin_state or "").lower() != "up":
                    continue
                if (port.oper_state or "").lower() == "up":
                    continue
                far = ""
                if port.description and " to " in port.description:
                    far = " to " + port.description.split(" to ")[-1].split()[0]
                broken.append(f"{reference.name} on {port_id}{far}")
            if broken:
                findings.append(
                    Finding(
                        "TIMING-005",
                        FindingSeverity.FAIL,
                        subject,
                        "In holdover because its timing reference is on a port "
                        "that is down: "
                        + "; ".join(broken)
                        + ". This is a physical fault, not a downstream effect.",
                        evidence=["show system sync-if-timing", "show port detail"],
                    )
                )

        # A reference that is administratively up but unusable is a lost
        # protection path, even while another reference carries the node.
        for reference in timing.references:
            if not reference.is_admin_up:
                continue
            if reference.is_qualified is False:
                findings.append(
                    Finding(
                        "TIMING-002",
                        FindingSeverity.WARN,
                        f"{subject}:{reference.name}",
                        "Reference is enabled but not qualified for use"
                        + (
                            f" ({reference.not_qualified_reason})"
                            if reference.not_qualified_reason
                            else ""
                        )
                        + ".",
                        evidence=["show system sync-if-timing"],
                    )
                )

        if timing.locked and not timing.selected_references and timing.references:
            findings.append(
                Finding(
                    "TIMING-003",
                    FindingSeverity.WARN,
                    subject,
                    "Reported locked, but no reference is selected for use.",
                    evidence=["show system sync-if-timing"],
                )
            )

        if not findings:
            selected = ", ".join(timing.selected_references) or "none reported"
            findings.append(
                Finding(
                    "TIMING-000",
                    FindingSeverity.PASS,
                    subject,
                    "Timing locked (%s); selected reference: %s."
                    % (", ".join(f"{k}={v}" for k, v in sorted(timing.status.items())),
                       selected),
                    evidence=["show system sync-if-timing"],
                )
            )
        return findings

    def _redundancy(self, device):
        """Check the standby control card is actually ready to take over.

        Nothing else in a capture reveals this: every interface, LAG and protocol
        session stays up right until the active card fails and there is no
        standby to take it.

        Only the two states that mean the same thing on any network are judged.
        The sync *mode* is a configuration choice -- "Config only synchronized"
        is correct when the mode is "Configuration" -- so it is recorded, not
        graded.
        """
        redundancy = device.redundancy
        if not redundancy.reported:
            return []

        findings = []
        subject = device.device_id
        if redundancy.standby_ready is False:
            findings.append(
                Finding(
                    "REDUNDANCY-001",
                    FindingSeverity.FAIL,
                    subject,
                    f"Standby is not ready ({redundancy.standby_status}) - the "
                    "node has no control-plane protection.",
                    evidence=["show redundancy synchronization"],
                )
            )
        if redundancy.had_failure:
            findings.append(
                Finding(
                    "REDUNDANCY-002",
                    FindingSeverity.WARN,
                    subject,
                    f"A previous standby failure is recorded: "
                    f"{redundancy.last_failure}.",
                    evidence=["show redundancy synchronization"],
                )
            )
        if not findings:
            findings.append(
                Finding(
                    "REDUNDANCY-000",
                    FindingSeverity.PASS,
                    subject,
                    "Standby %s; %s (last config sync %s)."
                    % (
                        redundancy.standby_status or "state not reported",
                        redundancy.config_sync_status or "sync status not reported",
                        redundancy.last_config_sync or "unknown",
                    ),
                    evidence=["show redundancy synchronization"],
                )
            )
        return findings

    def _alarms(self, device):
        """Raise the alarms the equipment is already reporting itself."""
        findings = []
        for alarm in device.alarms:
            if alarm.is_critical:
                severity = FindingSeverity.FAIL
            elif alarm.is_major:
                severity = FindingSeverity.FAIL
            elif alarm.severity.upper() in {"MN", "MINOR", "WR", "WARNING"}:
                severity = FindingSeverity.WARN
            elif alarm.service_affecting:
                severity = FindingSeverity.WARN
            else:
                # "NR" is a condition the NE reports without raising an alarm.
                # Dropping these lost real optical problems -- OPR-OUT
                # ("outgoing channel optical power out of range") and PWRADJFAIL
                # on the only channels carrying traffic. Report them at the
                # equipment's own weight rather than hiding or inflating them.
                severity = FindingSeverity.INFO
            subject = f"{device.device_id}:{alarm.subject or 'SYSTEM'}"
            detail = alarm.description or alarm.condition
            findings.append(
                Finding(
                    "ALARM-001",
                    severity,
                    subject,
                    f"{alarm.severity} {'SA' if alarm.service_affecting else 'NSA'} "
                    f"{alarm.condition}: {detail}.",
                    evidence=[f"raised {alarm.raised_at}"] if alarm.raised_at else [],
                )
            )
        return findings

    def _optical(self, device):
        findings = []
        frequencies = [
            channel.frequency_thz
            for channel in device.optical_channels.values()
            if channel.frequency_thz is not None
        ]
        duplicates = [freq for freq, count in Counter(frequencies).items() if count > 1]
        if duplicates:
            findings.append(
                Finding(
                    "OPTICAL-001",
                    FindingSeverity.WARN,
                    device.device_id,
                    f"Duplicate local channel frequencies: {duplicates}.",
                )
            )
        return findings

    def _links(self, snapshot):
        findings = []
        for link in snapshot.links.values():
            if link.confidence < 0.5:
                findings.append(
                    Finding(
                        "TOPOLOGY-001",
                        FindingSeverity.UNKNOWN,
                        link.link_id,
                        "Candidate link lacks corroborating evidence.",
                    )
                )
        return findings
