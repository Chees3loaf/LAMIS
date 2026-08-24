from __future__ import annotations

import re


# A prompt line, e.g. "A:MOPN001_7250# show port", "*A:SITE-A>config>router# ...",
# or the 1830's bare "MOPN001_1830# show general name".
#
# The discriminator is that a prompt has **no whitespace before its "#"**.
# Allowing any run of non-"#" characters instead matches real output lines --
# ``Last Boot Config Header: # TiMOS-B-25.10.R2 both/hops64 Nokia 7250 IXR``
# was read as a prompt, inventing a section named after the software version and
# truncating the genuine ``show system information`` section at that point.
COMMAND_RE = re.compile(
    r"^\*?(?:[A-Za-z]:)?[\w.\-]+(?:>[\w.\-]*)*#[ \t]*(\S.*?)[ \t]*$",
    re.MULTILINE,
)

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Devices emit BEL and other C0 controls mid-output (SR OS rings the bell on
# "MINOR: CLI ... is not configured"). Keep tab and newline; drop the rest.
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# A banner line: a run of '=' (SR OS section rule) on its own line.
BANNER_RE = re.compile(r"^={3,}[ \t]*$", re.MULTILINE)

# SR OS ``show ... detail`` output is laid out in two label/value columns:
#
#     Interface          : 1/5/8              Oper Speed       : 1 Gbps
#     Admin State        : up                 Oper Duplex      : full
#
# so a naive "capture to end of line" read of ``Admin State`` returns
# ``up                 Oper Duplex      : full``. This matches the start of a
# second column -- two or more spaces, a label, then its colon -- so the value
# can be cut at that point. Requiring the run of spaces is what keeps values
# that legitimately contain a colon (MAC addresses, timestamps) intact.
SECOND_COLUMN_RE = re.compile(r"[ \t]{2,}[A-Za-z][A-Za-z0-9 ./()%*_+-]*:")


def strip_ansi(text: str) -> str:
    """Drop escape sequences and stray control bytes.

    The 1830 PSS colours critical rows in ``show condition``, so a captured
    transcript carries escape sequences in the middle of the alarm text, and
    SR OS rings the terminal bell on messages like "MINOR: CLI BGP is not
    configured." -- leaving a BEL glued to the end of the line.
    """
    return CONTROL_RE.sub("", ANSI_RE.sub("", text.replace("\r\n", "\n")))


def split_command_sections(text: str) -> dict[str, str]:
    matches = list(COMMAND_RE.finditer(text))
    if not matches:
        return {"transcript": text}
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        command = match.group(1).strip()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = text[match.end() : end]
        # A command can legitimately appear twice in one transcript; keep both.
        if command in sections:
            sections[command] += "\n" + body
        else:
            sections[command] = body
    return sections


def trim_second_column(value: str) -> str:
    """Cut a captured value at the start of the next label/value column."""
    match = SECOND_COLUMN_RE.search(value)
    if match:
        value = value[: match.start()]
    return value.strip()


def field(text: str, label: str) -> str | None:
    """Read ``label : value``, honouring SR OS two-column layout.

    A label can sit in either column:

        Interface          : 1/1/1                      Oper Speed       : 10 Gbps
        Admin State        : up                         Oper Duplex      : full

    ``Interface`` and ``Admin State`` start their lines, but ``Oper Speed`` and
    ``Oper Duplex`` only ever appear mid-line. Anchoring solely to line start
    silently returns nothing for every right-hand label. The left column is
    tried first so a label appearing in both places prefers the primary one.
    """
    escaped = re.escape(label)
    for pattern in (
        rf"^[ \t]*{escaped}[ \t]*:[ \t]*(.*?)[ \t]*$",
        # Right-hand column: the run of spaces is what proves it is a new
        # column rather than the tail of a longer label.
        rf"[ \t]{{2,}}{escaped}[ \t]*:[ \t]*(.*?)[ \t]*$",
    ):
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            value = trim_second_column(match.group(1))
            if value:
                return value
    return None


def first_field(text: str, *labels: str) -> str | None:
    for label in labels:
        value = field(text, label)
        if value is not None:
            return value
    return None


def capture_host(text: str) -> str | None:
    """The address the capture was taken from, per the transcript header.

    An 1830 PSS does not print its own management address in any of the baseline
    commands, so without this its links to a peer that *was* audited could never
    be resolved by address. The capture tooling records ``# Host: <addr>``.
    """
    match = re.search(r"^#[ \t]*Host[ \t]*:[ \t]*(\S+)", text, re.MULTILINE)
    return match.group(1) if match else None


def normalize_state(value: str | None) -> str | None:
    """Reduce an SR OS state to its bare keyword.

    Real output qualifies the state -- ``up - Active in LAG 2``,
    ``up/active``, ``Link Up`` -- so a bare ``== "up"`` comparison on the raw
    string reports every LAG member as down.
    """
    if not value:
        return None
    token = value.strip().lower()
    for separator in (" - ", "/", " "):
        if separator in token:
            token = token.split(separator)[0].strip()
            if token:
                break
    return token or None


def is_absent(value: str | None) -> bool:
    """True for the placeholders SR OS and the 1830 use to mean "no value"."""
    if value is None:
        return True
    return value.strip().lower() in {
        "n/a",
        "na",
        "none",
        "-",
        "(not specified)",
        "not specified",
        "unspecified",
        "",
    }


def banner_blocks(body: str) -> list[str]:
    """Split ``show ... detail`` output into its ``===``-delimited sections.

    Each returned block starts at its section title (the line after the opening
    banner) so fields printed above the identifying ``Interface :`` line --
    ``Description`` in particular -- stay with the right port.
    """
    bounds = [match.start() for match in BANNER_RE.finditer(body)]
    if not bounds:
        return [body]
    blocks = []
    for index, start in enumerate(bounds):
        end = bounds[index + 1] if index + 1 < len(bounds) else len(body)
        block = body[start:end]
        if block.strip():
            blocks.append(block)
    return blocks
