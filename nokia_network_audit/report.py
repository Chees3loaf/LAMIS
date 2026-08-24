from __future__ import annotations

import json
from pathlib import Path

from .graph import hop_counts, missing_peers
from .models import SEVERITY_ORDER, AuditSnapshot, FindingSeverity


def write_json(snapshot: AuditSnapshot, target: Path) -> None:
    target.write_text(
        json.dumps(snapshot.to_dict(), indent=2, default=str),
        encoding="utf-8",
    )


def _severity_rank(severity: FindingSeverity) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


def write_markdown(snapshot: AuditSnapshot, target: Path) -> None:
    counts = {}
    for finding in snapshot.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    tally = "  ".join(
        f"{severity.value} {counts[severity]}"
        for severity in SEVERITY_ORDER
        if severity in counts
    )

    lines = [
        "# Nokia Network Audit",
        "",
        f"Devices: {len(snapshot.devices)}",
        f"Links: {len(snapshot.links)}",
        f"Findings: {len(snapshot.findings)}" + (f" — {tally}" if tally else ""),
        "",
        "## Devices",
        "",
        "| Device | Platform | Release | Management | Ports | LAGs | Channels |",
        "|---|---|---|---|---|---|---|",
    ]
    for device in snapshot.devices.values():
        lines.append(
            f"| {device.device_id} | {device.platform.value} | "
            f"{device.software_release or '—'} | {device.management_ip or '—'} | "
            f"{len(device.ports)} | {len(device.lags)} | "
            f"{len(device.optical_channels)} |"
        )

    lines += [
        "",
        "## Findings",
        "",
        "Most severe first.",
        "",
        "| Severity | Rule | Subject | Message |",
        "|---|---|---|---|",
    ]
    # Stable sort, so findings keep their discovery order within a severity.
    for finding in sorted(snapshot.findings, key=lambda f: _severity_rank(f.severity)):
        message = finding.message.replace("|", "\\|")
        lines.append(
            f"| {finding.severity.value} | {finding.rule_id} | "
            f"{finding.subject} | {message} |"
        )

    if snapshot.links:
        lines += [
            "",
            "## Links",
            "",
            "| Confidence | A end | Z end | Evidence |",
            "|---|---|---|---|",
        ]
        for link in sorted(
            snapshot.links.values(), key=lambda l: (-l.confidence, l.link_id)
        ):
            evidence = "; ".join(
                e.detail for e in link.evidence if e.detail
            ).replace("|", "\\|")
            a = f"{link.a.device_id}:{link.a.interface_id or '—'}"
            z = f"{link.z.device_id}:{link.z.interface_id or '—'}"
            lines.append(f"| {link.confidence:.2f} | {a} | {z} | {evidence} |")

    hops = hop_counts(snapshot)
    if hops:
        lines += [
            "",
            "## Hops between audited devices",
            "",
            "Shortest path over discovered links.",
            "",
            "| From | To | Hops |",
            "|---|---|---|",
        ]
        for (start, target_device), distance in sorted(hops.items()):
            lines.append(f"| {start} | {target_device} | {distance} |")

    missing = missing_peers(snapshot)
    if missing:
        lines += [
            "",
            "## Reported but not audited",
            "",
            "Peers these devices name. Capturing them extends the topology.",
            "",
            "| Peer | Reported by | To reach it |",
            "| --- | --- | --- |",
        ]
        for peer in missing:
            lines.append(
                f"| {peer.display} | {', '.join(peer.reporters)} | "
                f"{'; '.join(peer.reach)} |"
            )

    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
