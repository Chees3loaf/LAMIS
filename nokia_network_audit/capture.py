from __future__ import annotations

import argparse
import getpass
import os
import re
import socket
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .profiles import (
    PROFILES,
    CommandProfile,
    get_profile,
    session_commands,
    validate_profile,
)


PROMPT_RE = re.compile(r"(?:^|\n)[^\r\n]{0,160}[>#]\s*$")
PAGER_MARKERS = (
    "Press any key to continue",
    "--More--",
    "Press <space> to continue",
)


class ShellChannel(Protocol):
    def send(self, data: str) -> object: ...
    def recv_ready(self) -> bool: ...
    def recv(self, size: int) -> bytes: ...
    def close(self) -> object: ...


@dataclass(frozen=True, slots=True)
class CaptureOptions:
    command_timeout: float = 90.0
    idle_grace: float = 0.6
    poll_interval: float = 0.1


def safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return cleaned or "device"


def transcript_path(output_dir: Path, host: str, profile: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return output_dir / f"{safe_filename(host)}_{safe_filename(profile)}_{stamp}.txt"


def _strip_pager_markers(text: str) -> str:
    for marker in PAGER_MARKERS:
        text = text.replace(marker, "")
    return text.replace("\x08", "")


def read_until_prompt(
    channel: ShellChannel,
    *,
    options: CaptureOptions,
    initial: str = "",
) -> str:
    output = initial
    deadline = time.monotonic() + options.command_timeout
    last_data = time.monotonic()
    while time.monotonic() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(65535).decode("utf-8", errors="replace")
            output += chunk
            last_data = time.monotonic()
            if any(marker in chunk for marker in PAGER_MARKERS):
                channel.send(" ")
            cleaned = _strip_pager_markers(output).replace("\r", "")
            if PROMPT_RE.search(cleaned):
                return cleaned
        else:
            cleaned = _strip_pager_markers(output).replace("\r", "")
            if (
                cleaned
                and PROMPT_RE.search(cleaned)
                and time.monotonic() - last_data >= options.idle_grace
            ):
                return cleaned
            time.sleep(options.poll_interval)
    raise TimeoutError(
        f"Timed out after {options.command_timeout:.0f}s waiting for device prompt"
    )


def capture_profile(
    channel: ShellChannel,
    profile: CommandProfile,
    *,
    host: str,
    options: CaptureOptions | None = None,
) -> str:
    validate_profile(profile)
    options = options or CaptureOptions()
    header = [
        "# Nokia Network Audit raw baseline transcript",
        f"# Host: {host}",
        f"# Profile: {profile.name}",
        f"# Captured UTC: {datetime.now(timezone.utc).isoformat()}",
        "# Commands are read-only operational queries.",
        "",
    ]
    parts = ["\n".join(header)]
    try:
        banner = read_until_prompt(channel, options=options)
        parts.append(banner)
    except TimeoutError:
        # Some SSH servers do not emit a prompt until the first newline.
        channel.send("\n")
        parts.append(read_until_prompt(channel, options=options))

    for command in session_commands(profile):
        parts.append(f"\n# COMMAND: {command}\n")
        channel.send(command + "\n")
        try:
            parts.append(read_until_prompt(channel, options=options))
        except TimeoutError as exc:
            parts.append(f"\n# ERROR: {exc}\n")
    return "\n".join(parts)


def _connect(args, password: str):
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError(
            "Live SSH capture requires paramiko. Install it in this Python "
            "environment or run the manual command list."
        ) from exc

    client = paramiko.SSHClient()
    try:
        client.load_system_host_keys()
        if args.known_hosts:
            client.load_host_keys(str(args.known_hosts))
        if args.accept_new_host_key:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(
            hostname=args.host,
            port=args.port,
            username=args.username,
            password=password,
            look_for_keys=args.use_keys,
            allow_agent=args.use_keys,
            timeout=args.connect_timeout,
            auth_timeout=args.connect_timeout,
            banner_timeout=args.connect_timeout,
        )
        return client
    except Exception as exc:
        client.close()
        raise RuntimeError(f"SSH connection to {args.host} failed: {exc}") from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nokia-baseline-capture",
        description="Capture a guarded, read-only baseline from a Nokia device.",
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--profile", required=True, choices=sorted(PROFILES))
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--output-dir", type=Path, default=Path("baseline-captures"))
    parser.add_argument("--known-hosts", type=Path)
    parser.add_argument("--accept-new-host-key", action="store_true")
    parser.add_argument("--use-keys", action="store_true")
    parser.add_argument(
        "--password-env",
        metavar="VARIABLE",
        help="Read the SSH password from this environment variable.",
    )
    parser.add_argument("--connect-timeout", type=float, default=15.0)
    parser.add_argument("--command-timeout", type=float, default=90.0)
    parser.add_argument(
        "--preview",
        action="store_true",
        help="Print commands without connecting.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    profile = get_profile(args.profile)
    validate_profile(profile)
    if args.preview:
        print(f"{profile.description}\n")
        for command in session_commands(profile):
            print(command)
        return 0

    password = ""
    if args.password_env:
        password = os.environ.get(args.password_env, "")
        if not password:
            raise SystemExit(
                f"Environment variable {args.password_env!r} is not set or is empty."
            )
    elif not args.use_keys:
        password = getpass.getpass(f"SSH password for {args.username}@{args.host}: ")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    target = transcript_path(args.output_dir, args.host, args.profile)
    client = None
    channel = None
    try:
        client = _connect(args, password)
        channel = client.invoke_shell(width=240, height=1000)
        transcript = capture_profile(
            channel,
            profile,
            host=args.host,
            options=CaptureOptions(command_timeout=args.command_timeout),
        )
        target.write_text(transcript, encoding="utf-8")
    except (RuntimeError, TimeoutError, socket.error, OSError) as exc:
        print(f"Capture failed: {exc}", file=sys.stderr)
        return 2
    finally:
        if channel is not None:
            channel.close()
        if client is not None:
            client.close()
    print(f"Baseline transcript saved to: {target.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
