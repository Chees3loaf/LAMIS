from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CommandProfile:
    name: str
    description: str
    commands: tuple[str, ...]
    paging_command: str | None = None
    identity_command: str | None = None


# Session-scoped display settings, not configuration. Kept out of ``commands``
# so the command allowlist can stay strictly ``show``-only.
#
# SR OS classic CLI exposes pagination as the ``more`` CLI environment setting
# (7705 SAR Basic System Configuration Guide 25.10.R1, "CLI environment
# commands": "more - Enables the CLI output to be displayed one screen at a
# time"), negated in the usual classic-CLI style.
#
# The 1830 PSS uses a dedicated ``paging`` command whose ``status`` value is
# spelled ``disabled``, not ``disable`` (1830 PSS R24.12 CLI Guide 2.16
# "paging", p207; Access Levels: Administrator, Provisioner, Observer;
# "Command Access Level Impact: None").
PAGING_COMMANDS = frozenset(
    {
        "environment no more",
        "paging status disabled",
    }
)


SROS_BASELINE = (
    "show system information",
    "show chassis detail",
    "show card state",
    "show card detail",
    "show mda",
    "show mda detail",
    "show port",
    "show port detail",
    "show lag",
    "show lag detail",
    "show router interface",
    "show router interface detail",
    "show router ospf neighbor",
    "show router isis adjacency",
    # IS-IS names its neighbours by hostname, not by a routable address the way
    # OSPF's Router Id does, so discovery needs a second source to turn that
    # name into somewhere to connect. "capabilities" carries
    # "Router Cap : <ip>" per LSP ID, which is that mapping (7705 SAR Routing
    # Protocols Guide 25.10.R1, show>router>isis). On an OSPF-only device both
    # return "ISIS instance 0 is not configured" and cost nothing.
    "show router isis adjacency detail",
    "show router isis capabilities",
    "show router bgp neighbor",
    "show router ldp session",
    "show service service-using",
    "show aps",
    # Direct L2 adjacency: peer system name and port, straight from the device.
    # Verified in the 7705 SAR Basic System Configuration Guide 25.10.R1
    # ("show system lldp neighbor", System management) and the Gen 2 Clear,
    # Monitor, Show and Tools reference (show>system>lldp, "neighbor").
    "show system lldp neighbor",
    # Contact-closure and environmental alarms. Classic SR OS has no facility
    # alarm list -- "show system alarms" is 7705 SAR Gen 2 only -- so this plus
    # the LED/temperature/component state in "show chassis detail" is the whole
    # alarm picture. Named for this platform in the 7705 SAR-8 Shelf V2 Chassis
    # Installation Guide, output example in the Interface Configuration Guide
    # 25.10.R1 ("show external-alarms input").
    "show external-alarms input",
    # Synchronous timing: whether the node is locked to a reference or quietly
    # running on its own oscillator, which lights no LED and changes no
    # interface state. Parsed and audited (TIMING-000..003).
    "show system sync-if-timing",
    # Captured but not yet interpreted -- the classic 7705 SAR docs carry no
    # output example for these two, and guessing a layout is how a first LLDP
    # attempt invented 54 adjacencies on a device that had none. They are here so
    # the data starts accumulating; parsers follow once real output exists.
    "show redundancy synchronization",
    "show system cpu",
)


# The default system event log. Classic SR OS keeps no standing alarm list, so
# "show chassis detail" reports only that a component is in alarm *now* -- no
# onset time, and no trace of a fault that already cleared. Log 99 is the
# 500-entry in-memory log every node runs by default and it timestamps each
# raise and each clear, which is what turns "fan 1 is failed" into "fan 1 has
# been flapping since 07/28". Output example in the 7705 SAR System Management
# Guide 25.10.R1 (3HE21353AAABTQZZA01) p.433, "show log log-id 99"; the same
# output was captured off a live SAR-8 v2 on B-25.10.R1.
#
# Appended last: the log can run the full 500 entries, so it stays behind the
# structured inventory output rather than in front of it.
SROS_EVENT_LOG = ("show log log-id 99",)

# Scoped to the 7705 deliberately. The 7250 IXR profiles below run the same
# classic SR OS and would accept this verbatim, but they are left unchanged
# until someone asks -- adding it here would silently alter what three other
# platforms capture.
SAR_8_BASELINE = SROS_BASELINE + SROS_EVENT_LOG


PSS_BASELINE = (
    # Verified against the 1830 PSS R24.12 CLI Guide (3KC-71311-RBAA-THZZA) and
    # matched to the command forms ATLAS already runs in scripts/Nokia_PSI.py.
    "show general name",
    "show general system-identification",
    "show software dynamic",
    "show shelf inventory *",
    "show slot *",
    "show card inventory *",
    # ``show card <sfd-sfc-card> <slot-aid>``; ``sfdc8b`` is a documented
    # <sfd-sfc-card> value and ``*`` a documented <slot-aid> meaning "all
    # slots" (R24.12 CLI Guide, Filter card commands, Input Parameters).
    "show card sfdc8b *",
    "show interface sfdc8b *",
    "show interface inventory *",
    "show interface topology *",
    "show condition",
    "show alarmleds",
)


PROFILES = {
    "7705-sar-8": CommandProfile(
        name="7705-sar-8",
        description="7705 SAR-8 classic SR OS router, LAG, SONET/SDH, and optic baseline",
        commands=SAR_8_BASELINE,
        paging_command="environment no more",
        identity_command="show system information",
    ),
    "7250-ixr-r6": CommandProfile(
        name="7250-ixr-r6",
        description="7250 IXR-R6 SR OS router, LAG, routing, and optic baseline",
        commands=SROS_BASELINE,
        paging_command="environment no more",
        identity_command="show system information",
    ),
    "7250-ixr-r6d": CommandProfile(
        name="7250-ixr-r6d",
        description="7250 IXR-R6d SR OS router, LAG, routing, and optic baseline",
        commands=SROS_BASELINE,
        paging_command="environment no more",
        identity_command="show system information",
    ),
    "7250-ixr-r6dl": CommandProfile(
        name="7250-ixr-r6dl",
        description="7250 IXR-R6dl SR OS router, LAG, routing, and optic baseline",
        commands=SROS_BASELINE,
        paging_command="environment no more",
        identity_command="show system information",
    ),
    "1830-pss-8": CommandProfile(
        name="1830-pss-8",
        description="1830 PSS-8 equipment, alarms, SFDC8B, and optical power baseline",
        commands=PSS_BASELINE,
        paging_command="paging status disabled",
        identity_command="show general system-identification",
    ),
}


def get_profile(name: str) -> CommandProfile:
    try:
        return PROFILES[name]
    except KeyError as exc:
        raise ValueError(f"Unknown command profile: {name}") from exc


def normalize_command(command: str) -> str:
    return " ".join(command.strip().lower().split())


def is_read_only_command(command: str) -> bool:
    return normalize_command(command).startswith("show ")


def is_paging_command(command: str) -> bool:
    return normalize_command(command) in PAGING_COMMANDS


def validate_profile(profile: CommandProfile) -> None:
    unsafe = [command for command in profile.commands if not is_read_only_command(command)]
    if unsafe:
        raise ValueError(
            f"Profile {profile.name!r} contains non-read-only commands: {unsafe}"
        )
    if profile.paging_command is not None and not is_paging_command(
        profile.paging_command
    ):
        raise ValueError(
            f"Profile {profile.name!r} has an unrecognized paging command: "
            f"{profile.paging_command!r}"
        )
    if profile.identity_command is not None and not is_read_only_command(
        profile.identity_command
    ):
        raise ValueError(
            f"Profile {profile.name!r} has a non-read-only identity command: "
            f"{profile.identity_command!r}"
        )


def session_commands(profile: CommandProfile) -> tuple[str, ...]:
    """The full ordered command list to send, paging setup included."""
    validate_profile(profile)
    if profile.paging_command:
        return (profile.paging_command,) + tuple(profile.commands)
    return tuple(profile.commands)
