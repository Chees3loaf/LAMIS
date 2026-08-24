"""Drive the SecureCRT button script against a simulated terminal session.

The script is written for SecureCRT's embedded interpreter, which injects a
``crt`` object into the script's globals. Nothing about that object is special,
so a fake one lets the whole button flow -- prompt discovery, platform
detection, the read-only guard, command capture, transcript layout, and the
offline audit hand-off -- run in a normal test process with no hardware.
"""

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "nokia_network_audit" / "securecrt" / "nokia_audit_button.py"
FIXTURES = REPO_ROOT / "tests_network_audit" / "fixtures"

PROMPT = "*A:SITE-A# "

SYSTEM_INFO = """
System Name            : SITE-A
System Type            : 7705 SAR-8
System Version         : TiMOS-B-25.10.R1
"""

PORT_DETAIL = """
===============================================================================
Ethernet Interface
===============================================================================
Description        : 10/100/Gig Ethernet SFP
Interface          : 1/1/1
Admin State        : up
Oper State         : up
"""

RESPONSES = {
    "show system information": SYSTEM_INFO,
    "show port detail": PORT_DETAIL,
    "environment no more": "",
}


class FakeScreen:
    """A read stream plus a screen, modelled the way SecureCRT exposes them.

    ``stale_prompt`` pre-seeds the stream with an unconsumed prompt, which is
    what a bare carriage return leaves behind when learning the prompt. That is
    the condition that desynchronised every read from its command.
    """

    def __init__(self, prompt, responses, stale_prompt=False):
        self.prompt = prompt
        self.responses = responses
        self.buffer = prompt if stale_prompt else ""
        self.sent = []
        self.MatchIndex = 0
        self.Synchronous = False
        self.IgnoreEscape = False

    # -- cursor / prompt discovery -------------------------------------
    @property
    def CurrentRow(self):
        return 1

    @property
    def CurrentColumn(self):
        return len(self.prompt) + 1

    def Get(self, row1, col1, row2, col2):
        return self.prompt[col1 - 1 : col2]

    # -- I/O -----------------------------------------------------------
    def Send(self, data):
        self.sent.append(data)
        if data in ("\r", " "):
            return
        command = data.rstrip("\r")
        output = self.responses.get(command, "\nError: unknown command\n")
        self.buffer += command + "\n" + output + "\n" + self.prompt

    def ReadString(self, targets, timeout=None):
        if isinstance(targets, str):
            targets = [targets]
        best = None
        for index, target in enumerate(targets, start=1):
            position = self.buffer.find(target)
            if position != -1 and (best is None or position < best[0]):
                best = (position, index, target)
        if best is None:
            self.MatchIndex = 0
            text, self.buffer = self.buffer, ""
            return text
        position, index, target = best
        text = self.buffer[:position]
        self.buffer = self.buffer[position + len(target) :]
        self.MatchIndex = index
        return text

    def WaitForString(self, target, timeout=None):
        """Skip the stream forward past ``target``; False if it is not there."""
        position = self.buffer.find(target)
        if position == -1:
            return False
        self.buffer = self.buffer[position + len(target) :]
        return True


class FakeDialog:
    def __init__(self):
        self.messages = []

    def MessageBox(self, message, title="", options=0):
        self.messages.append(message)
        return 1  # IDOK

    def Prompt(self, message, title="", default="", is_password=False):
        return default  # accept the detected platform


class FakeSession:
    Connected = True
    RemoteAddress = "10.20.30.40"

    def SetStatusText(self, text):
        pass


class FakeCrt:
    def __init__(self, prompt=PROMPT, responses=None, stale_prompt=False):
        self.Screen = FakeScreen(
            prompt,
            responses if responses is not None else RESPONSES,
            stale_prompt=stale_prompt,
        )
        self.Dialog = FakeDialog()
        self.Session = FakeSession()
        self.ScriptFullName = str(SCRIPT)


def _sections(transcript):
    """Split a written transcript on its "# COMMAND:" markers."""
    sections = {}
    current = None
    for line in transcript.split("\n"):
        if line.startswith("# COMMAND: "):
            current = line[len("# COMMAND: ") :].strip()
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    return {name: "\n".join(body) for name, body in sections.items()}


def run_button(crt_obj, output_dir):
    previous = os.environ.get("NOKIA_AUDIT_OUTPUT")
    os.environ["NOKIA_AUDIT_OUTPUT"] = str(output_dir)
    try:
        namespace = {"crt": crt_obj, "__name__": "securecrt_button"}
        exec(compile(SCRIPT.read_text(encoding="utf-8"), str(SCRIPT), "exec"), namespace)
        return namespace
    finally:
        if previous is None:
            os.environ.pop("NOKIA_AUDIT_OUTPUT", None)
        else:
            os.environ["NOKIA_AUDIT_OUTPUT"] = previous


FAR_SYSTEM_INFO = """
System Name            : SITE-B
System Type            : 7250 IXR-R6
System Version         : TiMOS-B-25.10.R2

Tel/Tel6/SSH/FTP Admin : Disabled/Disabled/Enabled/Disabled
"""

ORIGIN_ROUTER_INFO = """
System Name            : SITE-A
System Type            : 7705 SAR-8 v2
System Version         : TiMOS-B-25.10.R1

Tel/Tel6/SSH/FTP Admin : Disabled/Disabled/Enabled/Disabled
"""

ORIGIN_ROUTER_IF = """
Interface-Name                   Adm       Opr(v4/v6)  Mode    Port/SapId
   IP-Address                                                  PfxState
-------------------------------------------------------------------------------
system                           Up        Up/Down     Network system
   172.16.0.1/32                                                n/a
to_SITE-B                        Up        Up/Down     Network lag-1
   172.18.0.0/31                                                n/a
"""

ORIGIN_OSPF = """
Interface-Name                   Rtr Id          State      Pri  RetxQ   TTL
   Area-Id
-------------------------------------------------------------------------------
to_SITE-B                        172.16.0.2      Full       1    0       39
   0.0.0.0
"""


class ChainFakeScreen(FakeScreen):
    """Two devices and a session that can move between them.

    Models the part that matters: after ``ssh`` the prompt belongs to a
    different device, and ``logout`` brings it back. Getting that wrong is how a
    chained run strands the operator's session.
    """

    def __init__(
        self, origin_prompt, origin_responses, far_prompt, far_responses,
        logout_lag=6,
    ):
        super().__init__(origin_prompt, origin_responses)
        self.origin_prompt = origin_prompt
        self.far_prompt = far_prompt
        self.far_responses = far_responses
        self.on_far = False
        self.awaiting_password = False
        self.hop_commands = []
        self.logouts = 0
        # Real hardware does not switch prompts the instant "logout" is typed.
        # Without modelling that lag, a poll-until-it-changes loop looks fine
        # here and only reveals itself against a device.
        self.logout_lag = logout_lag
        self._lag_left = 0

    @property
    def prompt(self):
        if self._lag_left > 0:
            return self.far_prompt
        return self.far_prompt if self.on_far else self.origin_prompt

    @prompt.setter
    def prompt(self, value):  # set by FakeScreen.__init__
        self.origin_prompt = value

    @property
    def responses(self):
        return self.far_responses if self.on_far else self._origin_responses

    @responses.setter
    def responses(self, value):
        self._origin_responses = value

    def Send(self, data):
        self.sent.append(data)
        if data in ("\r", " "):
            # A poll costs a keystroke and burns down the settling lag.
            if self._lag_left > 0:
                self._lag_left -= 1
                self.buffer += "\n" + self.prompt
            return
        command = data.rstrip("\r")
        if self.awaiting_password:
            self.awaiting_password = False
            self.on_far = True
            self.buffer += "\n" + self.far_prompt
            return
        if command.startswith(("ssh ", "telnet ")):
            self.hop_commands.append(command)
            self.awaiting_password = True
            self.buffer += command + "\nPassword: "
            return
        if command == "logout":
            self.logouts += 1
            self.on_far = False
            self._lag_left = self.logout_lag
            self.buffer += "\nConnection closed.\n" + self.origin_prompt
            return
        output = self.responses.get(command, "\nError: unknown command\n")
        self.buffer += command + "\n" + output + "\n" + self.prompt


class ChainDialog(FakeDialog):
    """Says yes to chaining and supplies credentials."""

    def __init__(self, accept_chain=True, accept_hostkey=True):
        super().__init__()
        self.accept_chain = accept_chain
        self.accept_hostkey = accept_hostkey
        self.prompts = []

    def MessageBox(self, message, title="", options=0):
        self.messages.append(message)
        if options & 4:  # Yes/No
            if "host key" in message:
                return 6 if self.accept_hostkey else 7
            return 6 if self.accept_chain else 7
        return 1  # IDOK

    def Prompt(self, message, title="", default="", is_password=False):
        self.prompts.append((message, is_password))
        if "Username" in message:
            return "admin"
        if "Password" in message:
            return "secret"
        if "Addresses separated by spaces" in message:
            return getattr(self, "seed_answer", "")
        return default


class PssLoginScreen(FakeScreen):
    """Replays a real 1830 PSS-8 login, captured from a live 7250.

    Verbatim, including the SYSLOG line the shelf emits mid-login and the alarm
    banner it prints before the prompt. Both sit between the cues the hop logic
    is waiting on, which is exactly where a stray "looks like an error" match
    would abort a perfectly good session.

    Note there is no ``login:`` prompt: ``ssh -l cli`` satisfies the getty at
    the ssh layer, and the CLI behind it then asks for its own identity. The
    two-step is real, but only one step is interactive.
    """

    HOSTKEY = (
        "\nThe authenticity of host '10.9.102.176' can't be established.\n"
        "ECDSA key fingerprint is SHA256:pdVlCsJx31ZPwerPcacvbH315p6BN7C4g8fPA9OsnME.\n"
        "ECDSA key fingerprint is MD5:71:5e:48:de:9f:f7:a4:7c:44:3b:54:a8:2a:dd:50:f2.\n"
        "Are you sure you want to continue connecting (yes/no/[fingerprint])? "
    )
    AFTER_YES = (
        "yes\n\n\n"
        "19:20:37.928507:SYSLOG src/PlatBackplane.cc:151 PlatGetBackplaneId() "
        "Backplane ID from ENV is 0x58 (88 decimal)\n\n"
        "Username: "
    )
    AFTER_USER = "\nPassword: "
    AFTER_PASSWORD = (
        "\nLast Login: Tue Dec 23 17:29:32 2025 from telnet_10.9.103.201\n\n\n"
        "Alarm Status:  Critical-1   Major-0   Minor-0 Warning-0\n\n"
        "CHEM001_1830# "
    )

    def __init__(self, origin_prompt="B:ALVY002_7250# "):
        super().__init__(origin_prompt, {})
        self.origin_prompt = origin_prompt
        self.far_prompt = "CHEM001_1830# "
        self.on_far = False
        self.stage = None
        self.hop_commands = []
        self.replies = []

    @property
    def prompt(self):
        return self.far_prompt if self.on_far else self.origin_prompt

    @prompt.setter
    def prompt(self, value):
        self.origin_prompt = value

    def Send(self, data):
        self.sent.append(data)
        if data in ("\r", " "):
            self.buffer += "\n" + self.prompt
            return
        text = data.rstrip("\r")
        if text.startswith("ssh "):
            self.hop_commands.append(text)
            self.stage = "hostkey"
            self.buffer += text + self.HOSTKEY
            return
        self.replies.append(text)
        if self.stage == "hostkey" and text == "yes":
            self.stage = "username"
            self.buffer += self.AFTER_YES
        elif self.stage == "username":
            self.stage = "password"
            self.buffer += self.AFTER_USER
        elif self.stage == "password":
            self.stage = None
            self.on_far = True
            self.buffer += self.AFTER_PASSWORD
        else:
            self.buffer += "\n" + self.prompt


class PssGettyPasswordScreen(PssLoginScreen):
    """A shelf that demands an ssh password for the getty account.

    Verbatim from a live 1830 at 10.9.102.99, whose siblings at .175 and .176 go
    straight to ``Username:``. The account has no password, so the prompt is
    answered with an empty line; sending the CLI password there spends the one
    permitted attempt on the wrong identity and the shelf closes the connection
    before the real login is ever reached.
    """

    ASKS_FOR_GETTY_PASSWORD = "yes\n\n\ncli@10.9.102.99's password: "

    def Send(self, data):
        self.sent.append(data)
        if data in ("\r", " "):
            # An empty reply at the getty stage is the correct answer, and moves
            # the login on to the CLI's own prompt.
            if self.stage == "getty-password":
                self.stage = "username"
                self.buffer += self.AFTER_YES.split("yes\n", 1)[-1]
                return
            self.buffer += "\n" + self.prompt
            return
        text = data.rstrip("\r")
        if text.startswith("ssh "):
            self.hop_commands.append(text)
            self.stage = "hostkey"
            self.buffer += text + self.HOSTKEY
            return
        self.replies.append(text)
        if self.stage == "hostkey" and text == "yes":
            self.stage = "getty-password"
            self.buffer += self.ASKS_FOR_GETTY_PASSWORD
        elif self.stage == "getty-password":
            # A word typed here is a failed login attempt, and the shelf asks
            # again before dropping the session.
            self.buffer += "\n" + self.ASKS_FOR_GETTY_PASSWORD
        elif self.stage == "username":
            self.stage = "password"
            self.buffer += self.AFTER_USER
        elif self.stage == "password":
            self.stage = None
            self.on_far = True
            self.buffer += self.AFTER_PASSWORD
        else:
            self.buffer += "\n" + self.prompt


class PssHopTests(unittest.TestCase):
    """The seeded hop onto an optical shelf, end to end."""

    def _hop(self, screen=None):
        crt_obj = FakeCrt()
        crt_obj.Screen = screen or PssLoginScreen()
        crt_obj.Dialog = ChainDialog()
        crt_obj.Session.Connected = False
        namespace = {"crt": crt_obj, "__name__": "probe"}
        exec(compile(SCRIPT.read_text(encoding="utf-8"), str(SCRIPT), "exec"), namespace)
        sys.path.insert(0, str(REPO_ROOT))
        from nokia_network_audit.chain import seed_targets

        target = seed_targets("10.9.102.176=CHEM001_1830")[0]
        # detect_prompt() rstrips, so the origin is held without its trailing
        # space -- exactly as the real caller obtains it.
        prompt = namespace["hop_to"](
            target,
            "B:ALVY002_7250#",
            "admin",
            "admin",
            hostkey=namespace["HostKeyPolicy"](namespace["HostKeyPolicy"].ACCEPT),
        )
        return crt_obj, prompt

    def test_the_shelf_is_reached_and_its_prompt_returned(self):
        crt_obj, prompt = self._hop()
        self.assertEqual(prompt.strip(), "CHEM001_1830#")

    def test_the_command_names_the_getty_account_and_the_instance(self):
        crt_obj, _ = self._hop()
        self.assertEqual(
            crt_obj.Screen.hop_commands,
            ["ssh 10.9.102.176 -l cli router management"],
        )

    def test_the_cli_identity_is_sent_not_the_getty_one(self):
        # "cli" gets the shelf to a login prompt; "admin" is who it logs in as.
        crt_obj, _ = self._hop()
        self.assertEqual(crt_obj.Screen.replies, ["yes", "admin", "admin"])

    def test_the_shelf_is_identified_as_an_1830_from_its_prompt(self):
        crt_obj, prompt = self._hop()
        namespace = {"crt": crt_obj, "__name__": "probe"}
        exec(compile(SCRIPT.read_text(encoding="utf-8"), str(SCRIPT), "exec"), namespace)
        # No "A:"/"B:" prefix, so platform detection probes the 1830 identity
        # command first rather than asking a shelf for "show system information".
        self.assertFalse(namespace["looks_like_sros_prompt"](prompt))
        self.assertEqual(namespace["hostname_from_prompt"](prompt), "CHEM001_1830")

    def test_a_shelf_that_asks_for_the_getty_password_is_answered_empty(self):
        crt_obj, prompt = self._hop(PssGettyPasswordScreen())
        self.assertEqual(prompt.strip(), "CHEM001_1830#")
        # Empty at the getty stage, then the CLI identity. The word "admin" must
        # never be sent to the ssh account: that is what closed the session.
        self.assertEqual(crt_obj.Screen.replies, ["yes", "admin", "admin"])
        blank_before_username = crt_obj.Screen.sent.index("admin\r")
        self.assertIn("\r", crt_obj.Screen.sent[:blank_before_username])

    def test_a_shelf_that_never_accepts_the_getty_password_gives_up(self):
        """The bound on the empty reply, checked by behaviour.

        A shelf that keeps asking is refusing. Without a limit the hop would
        spend its entire 60-second deadline sending blank lines, and a walk of
        six shelves would stall for minutes on end.
        """

        class NeverSatisfied(PssGettyPasswordScreen):
            def Send(self, data):
                if data == "\r" and self.stage == "getty-password":
                    self.sent.append(data)
                    self.buffer += "\n" + self.ASKS_FOR_GETTY_PASSWORD
                    return
                super().Send(data)

        crt_obj = FakeCrt()
        crt_obj.Screen = NeverSatisfied()
        crt_obj.Dialog = ChainDialog()
        crt_obj.Session.Connected = False
        namespace = {"crt": crt_obj, "__name__": "probe"}
        exec(compile(SCRIPT.read_text(encoding="utf-8"), str(SCRIPT), "exec"), namespace)
        sys.path.insert(0, str(REPO_ROOT))
        from nokia_network_audit.chain import seed_targets

        target = seed_targets("10.9.102.99")[0]
        with self.assertRaises(namespace["HopAborted"]):
            namespace["hop_to"](
                target,
                "B:ALVY002_7250#",
                "admin",
                "admin",
                hostkey=namespace["HostKeyPolicy"](
                    namespace["HostKeyPolicy"].ACCEPT
                ),
            )
        # Bounded, and in the right order: the documented no-password answer is
        # tried first, then the known password exactly once per account, then it
        # stops. Two accounts are in the sequence, so at most two -- never a loop.
        sent = crt_obj.Screen.sent
        self.assertLessEqual(sent.count("admin\r"), len(
            seed_targets("10.9.102.99")[0].login_sequence()
        ))
        self.assertLess(sent.index("\r", sent.index("yes\r")), sent.index("admin\r"))

    def test_a_shelf_that_refuses_the_getty_account_is_retried_as_the_cli_user(self):
        """The second login shape, seen on four of six shelves.

        ``ssh -l cli`` is refused outright; ``ssh -l admin`` with the password
        lands straight on the prompt with no ``Username:`` stage at all. Which
        shape a shelf uses cannot be known before connecting.
        """

        class RefusesGetty(PssLoginScreen):
            """cli is rejected; admin authenticates in one step."""

            def Send(self, data):
                self.sent.append(data)
                if data in ("\r", " "):
                    if self.stage == "cli-password":
                        self.buffer += "\n" + self.CLI_PROMPT
                    else:
                        self.buffer += "\n" + self.prompt
                    return
                text = data.rstrip("\r")
                if text.startswith("ssh "):
                    self.hop_commands.append(text)
                    self.stage = "hostkey-admin" if " -l admin " in text else "hostkey"
                    self.buffer += text + self.HOSTKEY
                    return
                self.replies.append(text)
                if self.stage == "hostkey" and text == "yes":
                    self.stage = "cli-password"
                    self.buffer += "yes\n\n" + self.CLI_PROMPT
                elif self.stage == "cli-password":
                    # Verbatim shape: the shelf asks three times before dropping
                    # the session, so the refusal arrives as a closed connection
                    # rather than as an explicit rejection.
                    self.cli_asks = getattr(self, "cli_asks", 1) + 1
                    if self.cli_asks < 3:
                        self.buffer += "\n" + self.CLI_PROMPT
                    else:
                        self.buffer += (
                            "\nMINOR: CLI Connection closed by foreign host.\n"
                        )
                        self.stage = None
                elif self.stage == "hostkey-admin" and text == "yes":
                    self.stage = "admin-password"
                    self.buffer += "yes\n\nadmin@10.9.102.106's password: "
                elif self.stage == "admin-password":
                    self.stage = None
                    self.on_far = True
                    self.buffer += self.AFTER_PASSWORD
                else:
                    self.buffer += "\n" + self.prompt

        RefusesGetty.CLI_PROMPT = "cli@10.9.102.106's password: "
        crt_obj, prompt = self._hop(RefusesGetty())
        self.assertEqual(prompt.strip(), "CHEM001_1830#")
        # Two ssh sessions, one per account -- not more guesses at one login.
        self.assertEqual(
            crt_obj.Screen.hop_commands,
            [
                "ssh 10.9.102.176 -l cli router management",
                "ssh 10.9.102.176 -l admin router management",
            ],
        )

    def test_a_failure_that_is_not_a_credential_refusal_is_not_retried(self):
        # No route, host key declined, connection refused: trying a second
        # account changes nothing and doubles the time spent failing.
        class NoRoute(PssLoginScreen):
            def Send(self, data):
                self.sent.append(data)
                if data in ("\r", " "):
                    self.buffer += "\n" + self.prompt
                    return
                text = data.rstrip("\r")
                if text.startswith("ssh "):
                    self.hop_commands.append(text)
                    self.buffer += (
                        text + "\nMINOR: CLI No route to destination.\n" + self.prompt
                    )
                    return
                self.buffer += "\n" + self.prompt

        crt_obj = FakeCrt()
        crt_obj.Screen = NoRoute()
        crt_obj.Dialog = ChainDialog()
        crt_obj.Session.Connected = False
        namespace = {"crt": crt_obj, "__name__": "probe"}
        exec(compile(SCRIPT.read_text(encoding="utf-8"), str(SCRIPT), "exec"), namespace)
        sys.path.insert(0, str(REPO_ROOT))
        from nokia_network_audit.chain import seed_targets

        with self.assertRaises(namespace["HopAborted"]):
            namespace["hop_to"](
                seed_targets("10.9.102.176")[0],
                "B:ALVY002_7250#",
                "admin",
                "admin",
                hostkey=namespace["HostKeyPolicy"](
                    namespace["HostKeyPolicy"].ACCEPT
                ),
            )
        self.assertEqual(len(crt_obj.Screen.hop_commands), 1)

    def test_the_login_banner_is_not_read_as_a_failure(self):
        # A SYSLOG line and "Alarm Status: Critical-1" arrive mid-login. Either
        # being mistaken for an error would abandon a working session.
        namespace = {"crt": FakeCrt(), "__name__": "probe"}
        namespace["crt"].Session.Connected = False
        exec(compile(SCRIPT.read_text(encoding="utf-8"), str(SCRIPT), "exec"), namespace)
        for text in (PssLoginScreen.AFTER_YES, PssLoginScreen.AFTER_PASSWORD):
            self.assertFalse(namespace["looks_like_error"](text))


class FallbackProfileTests(unittest.TestCase):
    """The built-in fallback must match the real profiles.

    A live run silently used the fallback -- the audit package had failed to
    import -- and captured a command set two releases behind the profile on
    disk, with no audit written. Drift between the two is invisible at the time
    and only shows up as a transcript that is quietly missing commands.
    """

    def setUp(self):
        namespace = {"crt": FakeCrt(), "__name__": "probe"}
        namespace["crt"].Session.Connected = False
        exec(compile(SCRIPT.read_text(encoding="utf-8"), str(SCRIPT), "exec"), namespace)
        self.fallback = namespace["_FALLBACK_PROFILES"]

    def test_every_profile_has_a_fallback(self):
        from nokia_network_audit.profiles import PROFILES

        self.assertEqual(sorted(self.fallback), sorted(PROFILES))

    def test_fallback_commands_match_the_profiles(self):
        from nokia_network_audit.profiles import PROFILES, session_commands

        for name, profile in PROFILES.items():
            with self.subTest(name):
                expected = list(session_commands(profile))
                spec = self.fallback[name]
                actual = [spec["paging_command"]] + list(spec["commands"])
                self.assertEqual(actual, expected)


class ErrorDetectionTests(unittest.TestCase):
    """Distinguishing "the device rejected that" from "that is the answer"."""

    def setUp(self):
        namespace = {"crt": FakeCrt(), "__name__": "probe"}
        namespace["crt"].Session.Connected = False
        exec(compile(SCRIPT.read_text(encoding="utf-8"), str(SCRIPT), "exec"), namespace)
        self.looks_like_error = namespace["looks_like_error"]

    def test_a_real_7705_answer_is_not_an_error(self):
        # Verbatim from a 7705 SAR-8 v2. "invalid" here is a field value, not a
        # rejection -- reading it as one made the walk skip every 7705.
        answer = (
            "\n===============================================================\n"
            "System Information\n"
            "===============================================================\n"
            "System Name            : BKLY001_7705\n"
            "System Type            : 7705 SAR-8 v2\n"
            "Microwave S/W Package  : invalid\n"
            "Management IP Addr     : 10.9.102.150/22\n"
        )
        self.assertFalse(self.looks_like_error(answer))

    def test_real_rejections_are_recognised(self):
        for output in (
            "                     ^\nError: Invalid parameter. \n",
            "MINOR: CLI ISIS instance 0 is not configured.\n",
            "MINOR: CLI BGP is not configured.\n",
            "",
            "   \n",
        ):
            with self.subTest(output[:30]):
                self.assertTrue(self.looks_like_error(output))

    def test_the_real_fixtures_are_identified(self):
        # The fixture now carries the "invalid" field the real device prints.
        from nokia_network_audit.parsers import parse_sros_transcript

        text = (FIXTURES / "sar_8.txt").read_text(encoding="utf-8")
        self.assertIn("Microwave S/W Package  : invalid", text)
        self.assertEqual(parse_sros_transcript(text).platform.value, "7705-sar-8")


class HostnameFromPromptTests(unittest.TestCase):
    """The device names itself in its prompt, before any command is sent."""

    def setUp(self):
        namespace = {"crt": FakeCrt(), "__name__": "probe"}
        # Executing the script runs main(); a disconnected session makes that a
        # no-op so the helpers can be imported without driving a capture.
        namespace["crt"].Session.Connected = False
        exec(compile(SCRIPT.read_text(encoding="utf-8"), str(SCRIPT), "exec"), namespace)
        self.hostname_from_prompt = namespace["hostname_from_prompt"]

    def test_prompt_forms(self):
        cases = {
            "A:MOPN002_7705# ": "MOPN002_7705",
            "*A:SITE-A# ": "SITE-A",
            "A:MOPN001_7250>config>router# ": "MOPN001_7250",
            "MOPN001_1830# ": "MOPN001_1830",
            "GRIZ001_1830#": "GRIZ001_1830",
        }
        for prompt, expected in cases.items():
            with self.subTest(prompt):
                self.assertEqual(self.hostname_from_prompt(prompt), expected)

    def test_unrecognised_prompt_yields_nothing(self):
        for prompt in ("", None, ">", "$ "):
            with self.subTest(repr(prompt)):
                self.assertEqual(self.hostname_from_prompt(prompt), "")


class ChainedCaptureTests(unittest.TestCase):
    def _crt(self, **kwargs):
        origin = dict(RESPONSES)
        origin["show system information"] = ORIGIN_ROUTER_INFO
        origin["show router interface"] = ORIGIN_ROUTER_IF
        origin["show router ospf neighbor"] = ORIGIN_OSPF
        far = dict(RESPONSES)
        far["show system information"] = FAR_SYSTEM_INFO

        crt_obj = FakeCrt()
        crt_obj.Screen = ChainFakeScreen("*A:SITE-A# ", origin, "*A:SITE-B# ", far)
        crt_obj.Dialog = ChainDialog(**kwargs)
        return crt_obj

    def test_neighbour_is_captured_and_the_session_returns_home(self):
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
            runs = sorted(p.name for p in Path(tmp).iterdir())
        # Origin plus the hopped neighbour, each named for the device rather
        # than whichever address reached it.
        self.assertEqual(len(runs), 2)
        self.assertTrue(any(name.startswith("SITE-A_") for name in runs), runs)
        self.assertTrue(any(name.startswith("SITE-B_") for name in runs), runs)
        # Exactly one hop, using ssh because telnet is disabled.
        self.assertEqual(crt_obj.Screen.hop_commands, ["ssh 172.16.0.2 -l admin"])
        # And it logged back out, leaving the session on the origin.
        self.assertEqual(crt_obj.Screen.logouts, 1)
        self.assertFalse(crt_obj.Screen.on_far)

    def test_the_platform_is_not_re_confirmed_for_every_device(self):
        # Detection reads the platform off the device; asking again per hop is
        # pure friction in a chained run.
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        asked = [m for m, _pw in crt_obj.Dialog.prompts if "1830-pss-8" in m]
        self.assertEqual(asked, [])

    def test_declining_the_offer_sends_no_hop(self):
        crt_obj = self._crt(accept_chain=False)
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
            self.assertEqual(len(list(Path(tmp).iterdir())), 1)
        self.assertEqual(crt_obj.Screen.hop_commands, [])
        self.assertEqual(crt_obj.Screen.logouts, 0)

    def test_default_credentials_are_used_without_prompting(self):
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        self.assertEqual(crt_obj.Screen.hop_commands, ["ssh 172.16.0.2 -l admin"])
        # No credential dialog. The walk also offers a seed field, which is a
        # different question and is allowed to appear.
        self.assertEqual(
            [m for m, _pw in crt_obj.Dialog.prompts if "Username" in m or "Password" in m],
            [],
        )

    def test_credentials_can_be_overridden_from_the_environment(self):
        crt_obj = self._crt()
        previous = {k: os.environ.get(k) for k in ("NOKIA_AUDIT_USER", "NOKIA_AUDIT_PASSWORD")}
        os.environ["NOKIA_AUDIT_USER"] = "netops"
        os.environ["NOKIA_AUDIT_PASSWORD"] = "s3cret"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                run_button(crt_obj, tmp)
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertEqual(crt_obj.Screen.hop_commands, ["ssh 172.16.0.2 -l netops"])

    def test_the_password_never_reaches_a_transcript(self):
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
            for run in Path(tmp).iterdir():
                text = (run / "transcript.txt").read_text(encoding="utf-8")
                self.assertNotIn("admin\r", text)
                self.assertNotIn("password", text.lower())

    def test_only_read_only_commands_reach_the_far_device(self):
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        for data in crt_obj.Screen.sent:
            command = data.rstrip("\r")
            if command in ("", " ", "admin", "secret", "logout"):
                continue
            if command.startswith(("ssh ", "telnet ")):
                continue
            normalized = " ".join(command.lower().split())
            self.assertTrue(
                normalized.startswith("show ") or normalized == "environment no more",
                "unexpected command sent: %r" % command,
            )

    def test_returning_home_waits_on_the_stream_not_the_keyboard(self):
        # A live run pressed Enter 43 times waiting for the origin prompt to
        # settle. Each press emits another prompt into the read stream, and an
        # unconsumed prompt is precisely what desynchronises later reads -- so
        # the requirement is not "few" keystrokes after logout but *none*.
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        sent = crt_obj.Screen.sent
        after_logout = sent[len(sent) - 1 - sent[::-1].index("logout\r") :]
        self.assertNotIn(
            "\r", after_logout, "hop_back polled with carriage returns"
        )

    def test_a_router_is_never_asked_the_1830_question(self):
        # "show general system-identification" on SR OS prints
        # "Error: Invalid parameter." into the operator's session for nothing.
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        sent = [d.rstrip("\r") for d in crt_obj.Screen.sent]
        self.assertNotIn("show general system-identification", sent)

    def test_an_optical_origin_offers_no_hops(self):
        # The 1830 has no CLI client to hop with.
        responses = {
            "show general system-identification": "\nShelf Type: PSS-8\n",
            "paging status disabled": "",
        }
        crt_obj = FakeCrt(prompt="PSS-A# ", responses=responses)
        crt_obj.Dialog = ChainDialog()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        self.assertFalse(
            any(d.rstrip("\r").startswith(("ssh ", "telnet ")) for d in crt_obj.Screen.sent)
        )


_COHERENT_PORT_DETAIL = (
    "\n"
    "===============================================================================\n"
    "Description        : QSFP28 Connector\n"
    "Interface          : 1/1/c7\n"
    "Admin State        : up\n"
    "Oper State         : up\n"
    "\n"
    "Transceiver Data\n"
    "\n"
    "Transceiver Status : operational\n"
    "Transceiver Type   : QSFP+ or later with CMIS   DCO              : Enabled\n"
    "Laser Tunability   : fully-tunable              \n"
    "Oper Freq (MHz)    : 193100000                  Max Freq (MHz)   : 196100000\n"
    "Part Number        : FTLC3351S3PL1-A5\n"
    "===============================================================================\n"
)


def _router_responses(name, system_ip, neighbours, coherent=False):
    """Enough of an SR OS baseline for the walk to discover ``neighbours``.

    ``coherent`` adds a DWDM pluggable, which is what tells the walk an optical
    shelf exists at this site even though no router can name it.
    """
    interfaces = [
        "Interface-Name                   Adm       Opr(v4/v6)  Mode    Port/SapId",
        "   IP-Address                                                  PfxState",
        "-" * 79,
        "system                           Up        Up/Down     Network system",
        "   %s/32                                                n/a" % system_ip,
    ]
    ospf = [
        "Interface-Name                   Rtr Id          State      Pri  RetxQ   TTL",
        "   Area-Id",
        "-" * 79,
    ]
    for index, peer in enumerate(neighbours, start=1):
        interfaces += [
            "to_peer%-25d Up        Up/Down     Network lag-%d" % (index, index),
            "   172.18.%d.%d/31                                             n/a"
            % (index, index),
        ]
        ospf += [
            "to_peer%-25d %-15s Full       1    0       39" % (index, peer),
            "   0.0.0.0",
        ]
    responses = {
        "show system information": (
            "\nSystem Name            : %s\n"
            "System Type            : 7250 IXR-R6\n"
            "System Version         : TiMOS-B-25.10.R2\n\n"
            "Tel/Tel6/SSH/FTP Admin : Disabled/Disabled/Enabled/Disabled\n" % name
        ),
        "show router interface": "\n" + "\n".join(interfaces) + "\n",
        "show router ospf neighbor": "\n" + "\n".join(ospf) + "\n",
    }
    if coherent:
        responses["show port detail"] = _COHERENT_PORT_DETAIL
    return responses


class WalkFakeScreen(FakeScreen):
    """A small routed network the session can move around.

    Every device is reachable from the origin, which is the premise the walk
    rests on: system addresses are advertised /32s, so it never has to nest
    sessions to get further away.
    """

    def __init__(self, network, origin, present_host_keys=False):
        self.network = network  # address -> (prompt, responses)
        self.origin = origin
        origin_prompt, origin_responses = network[origin]
        super().__init__(origin_prompt, origin_responses)
        self.current = origin
        self.awaiting_password = False
        self.awaiting_hostkey = False
        self.pending = None
        self.hop_commands = []
        self.hops_from = []
        self.logouts = 0
        # Real gear presents an unknown key on every first connection.
        self.present_host_keys = present_host_keys
        self.host_key_questions = 0

    @property
    def prompt(self):
        return self.network[self.current][0]

    @prompt.setter
    def prompt(self, value):
        pass

    @property
    def responses(self):
        return self.network[self.current][1]

    @responses.setter
    def responses(self, value):
        pass

    def Send(self, data):
        self.sent.append(data)
        if data in ("\r", " "):
            # A device asked for a password does not accept an empty line and
            # move on; it asks again. Modelling that matters, because a seeded
            # hop deliberately tries no-password first -- an optical shelf's ssh
            # account carries none -- and only then the configured password.
            if self.awaiting_password:
                self.buffer += "\nadmin@%s's password: " % self.pending
            return
        command = data.rstrip("\r")
        if self.awaiting_hostkey:
            self.awaiting_hostkey = False
            if command != "yes":
                self.pending = None
                self.buffer += "\nHost key verification failed.\n" + self.prompt
                return
            self.awaiting_password = True
            self.buffer += "\n\nadmin@%s's password: " % self.pending
            return
        if self.awaiting_password:
            self.awaiting_password = False
            self.current = self.pending
            self.buffer += "\n" + self.prompt
            return
        match = re.match(r"^ssh (\S+)", command)
        if match:
            self.hop_commands.append(command)
            self.hops_from.append(self.current)
            address = match.group(1)
            if address not in self.network:
                self.buffer += command + "\nNo route to host\n" + self.prompt
                return
            self.pending = address
            if self.present_host_keys:
                self.host_key_questions += 1
                self.awaiting_hostkey = True
                self.buffer += (
                    command
                    + "\nThe authenticity of host '%s' can't be established.\n" % address
                    + "ECDSA key fingerprint is SHA256:zZk9%02d.\n" % self.host_key_questions
                    + "Are you sure you want to continue connecting "
                    "(yes/no/[fingerprint])? "
                )
                return
            self.awaiting_password = True
            self.buffer += command + "\nPassword: "
            return
        if command == "logout":
            self.logouts += 1
            self.current = self.origin
            self.buffer += "\nConnection closed.\n" + self.prompt
            return
        output = self.responses.get(command, "\nError: unknown command\n")
        self.buffer += command + "\n" + output + "\n" + self.prompt


class AuthFailureFakeScreen(WalkFakeScreen):
    """Models a device that presents a host key and rejects the credentials.

    Reproduces a live failure: the SSH client printed an informational
    "ECDSA key fingerprint is ..." line before asking anything, then asked for
    the password three times before giving up. Replying to the wrong line, or
    replying twice, put text on the CLI where it ran as a command.
    """

    def __init__(self, network, origin, bad_hosts):
        super().__init__(network, origin)
        self.bad_hosts = set(bad_hosts)
        self.password_prompts = {}
        self.commands_run_on_cli = []

    def Send(self, data):
        if data not in ("\r", " ", chr(3)) and not self.awaiting_password:
            command = data.rstrip("\r")
            # Anything typed at a CLI prompt that is not a hop is a command.
            if not command.startswith(("ssh ", "telnet ")) and self.pending is None:
                self.commands_run_on_cli.append(command)
        self.sent.append(data)
        if data == chr(3):
            # Ctrl-C aborts the ssh client and drops back to the local CLI.
            self.pending = None
            self.awaiting_password = False
            self.buffer += "\n" + self.prompt
            return
        if data in ("\r", " "):
            return
        command = data.rstrip("\r")

        if self.pending in self.bad_hosts:
            if command == "yes":
                self.buffer += "\n\nadmin@%s's password: " % self.pending
                return
            # Any other input while authenticating is another failed attempt.
            count = self.password_prompts.get(self.pending, 0) + 1
            self.password_prompts[self.pending] = count
            if count >= 3:
                self.pending = None
                self.buffer += (
                    "\nMINOR: CLI Connection closed by foreign host.\n" + self.prompt
                )
            else:
                self.buffer += "\nadmin@%s's password: " % self.pending
            return

        if self.awaiting_password:
            self.awaiting_password = False
            self.current = self.pending
            self.pending = None
            self.buffer += "\n" + self.prompt
            return

        match = re.match(r"^ssh (\S+)", command)
        if match:
            self.hop_commands.append(command)
            self.hops_from.append(self.current)
            address = match.group(1)
            self.pending = address
            # The informational lines come before the question, as on real gear.
            self.buffer += (
                command
                + "\nThe authenticity of host '%s' can't be established.\n" % address
                + "ECDSA key fingerprint is SHA256:abc123.\n"
                + "Are you sure you want to continue connecting (yes/no/[fingerprint])? "
            )
            if address not in self.network and address not in self.bad_hosts:
                self.pending = None
                self.buffer += "\nNo route to host\n" + self.prompt
            return

        if command == "yes" and self.pending:
            self.awaiting_password = True
            self.buffer += "\n\nadmin@%s's password: " % self.pending
            return
        if command == "exit all":
            self.buffer += "\n" + self.prompt
            return
        if command == "logout":
            self.logouts += 1
            self.current = self.origin
            self.buffer += "\nConnection closed.\n" + self.prompt
            return
        output = self.responses.get(command, "\nError: unknown command\n")
        self.buffer += command + "\n" + output + "\n" + self.prompt


class HopFailureRecoveryTests(unittest.TestCase):
    """A rejected login must not leave debris on the origin's CLI."""

    NETWORK = dict(
        {
            "172.16.0.1": ("*A:SITE-A# ", _router_responses("SITE-A", "172.16.0.1", ["172.16.0.2", "172.16.0.3"])),
            "172.16.0.3": ("*A:SITE-C# ", _router_responses("SITE-C", "172.16.0.3", ["172.16.0.1"])),
        }
    )

    def _crt(self):
        crt_obj = FakeCrt()
        # .2 presents a host key and then rejects admin/admin; .3 is fine.
        crt_obj.Screen = AuthFailureFakeScreen(
            self.NETWORK, "172.16.0.1", bad_hosts={"172.16.0.2"}
        )
        crt_obj.Dialog = ChainDialog()
        return crt_obj

    def test_the_password_is_never_left_on_the_cli(self):
        # Live failure: after auth failed, "admin" was typed at the prompt and
        # executed, entering SR OS's admin context and changing the prompt.
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        stray = [c for c in crt_obj.Screen.commands_run_on_cli if c in ("admin", "secret", "yes", "no")]
        self.assertEqual(stray, [], "credential or answer text ran as a CLI command")

    def test_the_password_is_sent_at_most_once_per_hop(self):
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        # Three prompts on the real device meant three client retries; the
        # script must not feed them.
        self.assertLessEqual(crt_obj.Screen.password_prompts.get("172.16.0.2", 0), 2)

    def test_a_rejected_login_does_not_stop_the_walk(self):
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
            names = sorted(p.name.split("_")[0] for p in Path(tmp).iterdir())
        # SITE-C is still reached even though SITE-B rejected the credentials.
        self.assertIn("SITE-C", names)
        self.assertEqual(crt_obj.Screen.current, "172.16.0.1")


class HostKeyPolicyTests(unittest.TestCase):
    """One decision per walk, not one per device — with a record of it.

    SR OS cannot suppress the "authenticity of host ... can't be established"
    question (its ssh client takes only -l / router / re-exchange-* / -p), so it
    has to be answered for every unknown host. A live 40-device walk raised 36
    dialogs; on the full network that is ~180, which nobody answers carefully by
    the end.
    """

    REAL_OUTPUT = (
        "The authenticity of host '172.16.245.181' can't be established.\n"
        "ECDSA key fingerprint is SHA256:JA1klaKRonwP5IY7y89TYNeieAUg9fNSYzLK1Q7Mq8s.\n"
        "ECDSA key fingerprint is MD5:70:0d:a7:ca:0f:b2:ef:9d:49:58:fd:93:3f:0d:6c:06.\n"
        "Are you sure you want to continue connecting (yes/no/[fingerprint])? "
    )

    def setUp(self):
        namespace = {"crt": FakeCrt(), "__name__": "probe"}
        namespace["crt"].Session.Connected = False
        exec(compile(SCRIPT.read_text(encoding="utf-8"), str(SCRIPT), "exec"), namespace)
        self.ns = namespace
        self.HostKeyPolicy = namespace["HostKeyPolicy"]
        self.fingerprints = namespace["fingerprints"]

    def _target(self, address="172.16.245.181", label="GRIZ001_7250"):
        class T:
            pass

        t = T()
        t.address = address
        t.display = "%s (%s)" % (address, label)
        return t

    def test_fingerprints_are_read_from_real_output(self):
        found = self.fingerprints(self.REAL_OUTPUT)
        self.assertEqual(len(found), 2)
        self.assertTrue(found[0].startswith("SHA256:JA1kla"))
        self.assertTrue(found[1].startswith("MD5:70:0d"))

    def test_accept_mode_asks_nothing_and_records_everything(self):
        crt_obj = FakeCrt()
        self.ns["crt"] = crt_obj
        policy = self.HostKeyPolicy(self.HostKeyPolicy.ACCEPT)
        for address in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
            self.assertTrue(policy.decide(self._target(address), self.REAL_OUTPUT))
        self.assertEqual(crt_obj.Dialog.messages, [], "accept mode must not prompt")
        self.assertEqual(len(policy.accepted), 3)
        # The trail carries the fingerprint, not just the address.
        text = "\n".join(policy.summary())
        self.assertIn("10.0.0.2", text)
        self.assertIn("SHA256:JA1kla", text)

    def test_ask_mode_prompts_per_host(self):
        crt_obj = FakeCrt()
        self.ns["crt"] = crt_obj
        policy = self.HostKeyPolicy(self.HostKeyPolicy.ASK)
        policy.decide(self._target("10.0.0.1"), self.REAL_OUTPUT)
        policy.decide(self._target("10.0.0.2"), self.REAL_OUTPUT)
        self.assertEqual(len(crt_obj.Dialog.messages), 2)
        # The operator is shown the fingerprint they are accepting.
        self.assertIn("SHA256:JA1kla", crt_obj.Dialog.messages[0])

    def test_a_refusal_is_recorded_and_not_treated_as_accepted(self):
        crt_obj = FakeCrt()

        class RefusingDialog(FakeDialog):
            def MessageBox(self, message, title="", options=0):
                self.messages.append(message)
                return 7  # IDNO

        crt_obj.Dialog = RefusingDialog()
        self.ns["crt"] = crt_obj
        policy = self.HostKeyPolicy(self.HostKeyPolicy.ASK)
        self.assertFalse(policy.decide(self._target("10.0.0.9"), self.REAL_OUTPUT))
        self.assertEqual(policy.accepted, [])
        self.assertEqual(policy.refused, ["10.0.0.9"])
        self.assertIn("refused", "\n".join(policy.summary()))

    def test_missing_fingerprint_is_not_fatal(self):
        crt_obj = FakeCrt()
        self.ns["crt"] = crt_obj
        policy = self.HostKeyPolicy(self.HostKeyPolicy.ACCEPT)
        self.assertTrue(policy.decide(self._target(), "no fingerprint here"))
        self.assertEqual(policy.accepted[0][1], "unknown")


class WalkHostKeyTests(unittest.TestCase):
    """The walk asks about host keys once, before any hop."""

    def _crt(self, accept_hostkey=True):
        crt_obj = FakeCrt()
        crt_obj.Screen = WalkFakeScreen(
            NetworkWalkTests.NETWORK, "172.16.0.1", present_host_keys=True
        )
        crt_obj.Dialog = ChainDialog(accept_hostkey=accept_hostkey)
        return crt_obj

    def test_only_one_host_key_dialog_for_the_whole_walk(self):
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        # Every device presents a key...
        self.assertEqual(crt_obj.Screen.host_key_questions, 3)
        # ...but the operator is asked to decide only once. Match the question,
        # not the summary, which also mentions host keys.
        asked = [
            m
            for m in crt_obj.Dialog.messages
            if "Accept" in m and "host key" in m.lower()
        ]
        self.assertEqual(len(asked), 1, asked)
        self.assertIn("Accept them automatically for this walk", asked[0])
        # And the whole chain is still walked.
        self.assertEqual(len(crt_obj.Screen.hop_commands), 3)

    def test_the_fingerprints_accepted_are_reported(self):
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        final = crt_obj.Dialog.messages[-1]
        self.assertIn("Host keys accepted", final)
        for address in ("172.16.0.2", "172.16.0.3", "172.16.0.4"):
            self.assertIn(address, final)
        self.assertIn("SHA256:zZk9", final)

    def test_declining_means_no_device_is_reached(self):
        # Answering No to the up-front question falls back to per-host asking;
        # ChainDialog then refuses each one.
        crt_obj = FakeCrt()
        crt_obj.Screen = WalkFakeScreen(
            NetworkWalkTests.NETWORK, "172.16.0.1", present_host_keys=True
        )

        class RefuseKeys(ChainDialog):
            def MessageBox(self, message, title="", options=0):
                self.messages.append(message)
                if options & 4 and "host key" in message.lower():
                    return 7  # IDNO
                if options & 4:
                    return 6  # still accept the walk itself
                return 1

        crt_obj.Dialog = RefuseKeys()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
            names = sorted(p.name.split("_")[0] for p in Path(tmp).iterdir())
        self.assertEqual(names, ["SITE-A"])
        # The session is left where it started, not inside a half-open ssh.
        self.assertEqual(crt_obj.Screen.current, "172.16.0.1")


class NetworkWalkTests(unittest.TestCase):
    """A chain of four routers: A - B - C - D.

    Only B is a neighbour of the origin, so C and D can only be reached by
    following what each captured device reports.
    """

    NETWORK = {
        "172.16.0.1": ("*A:SITE-A# ", _router_responses("SITE-A", "172.16.0.1", ["172.16.0.2"])),
        "172.16.0.2": ("*A:SITE-B# ", _router_responses("SITE-B", "172.16.0.2", ["172.16.0.1", "172.16.0.3"])),
        "172.16.0.3": ("*A:SITE-C# ", _router_responses("SITE-C", "172.16.0.3", ["172.16.0.2", "172.16.0.4"])),
        "172.16.0.4": ("*A:SITE-D# ", _router_responses("SITE-D", "172.16.0.4", ["172.16.0.3"])),
    }

    def _crt(self):
        crt_obj = FakeCrt()
        crt_obj.Screen = WalkFakeScreen(self.NETWORK, "172.16.0.1")
        crt_obj.Dialog = ChainDialog()
        return crt_obj

    def test_the_walk_reaches_devices_beyond_the_first_neighbour(self):
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
            names = sorted(p.name.split("_")[0] for p in Path(tmp).iterdir())
        self.assertEqual(names, ["SITE-A", "SITE-B", "SITE-C", "SITE-D"])

    def test_every_hop_is_made_from_the_origin(self):
        # The session must never go deeper than one level; a depth-first walk
        # would need an unwinding stack of logouts to get home.
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        self.assertEqual(set(crt_obj.Screen.hops_from), {"172.16.0.1"})
        self.assertEqual(crt_obj.Screen.logouts, len(crt_obj.Screen.hop_commands))
        self.assertEqual(crt_obj.Screen.current, "172.16.0.1")

    def test_the_origin_is_not_revisited(self):
        # SITE-B reports SITE-A as a neighbour.
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        self.assertNotIn("ssh 172.16.0.1 -l admin", crt_obj.Screen.hop_commands)
        self.assertEqual(len(crt_obj.Screen.hop_commands), 3)

    def test_each_device_is_captured_once(self):
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        self.assertEqual(
            len(crt_obj.Screen.hop_commands), len(set(crt_obj.Screen.hop_commands))
        )

    def _optical_network(self):
        """SITE-B rides a DWDM span; SITE-E is the shelf carrying it.

        Nothing names SITE-E -- a transparent wavelength shows the far-end
        router, never the shelf -- so discovery can never reach it. The coherent
        pluggable on SITE-B is the only evidence it exists.
        """
        network = dict(self.NETWORK)
        network["172.16.0.2"] = (
            "*A:SITE-B# ",
            _router_responses(
                "SITE-B", "172.16.0.2", ["172.16.0.1", "172.16.0.3"], coherent=True
            ),
        )
        network["172.16.9.9"] = (
            "*A:SITE-E# ",
            _router_responses("SITE-E", "172.16.9.9", []),
        )
        crt_obj = FakeCrt()
        crt_obj.Screen = WalkFakeScreen(network, "172.16.0.1")
        crt_obj.Dialog = ChainDialog()
        return crt_obj

    def test_the_walk_asks_for_shelves_only_once_it_has_found_a_span(self):
        # No coherent optic anywhere in the default network, so there is nothing
        # to ask about and the operator is not interrupted.
        crt_obj = self._crt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        self.assertEqual(
            [m for m, _pw in crt_obj.Dialog.prompts if "DWDM" in m], []
        )

    def test_a_span_with_no_shelf_prompts_and_names_the_site(self):
        crt_obj = self._optical_network()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        asked = [m for m, _pw in crt_obj.Dialog.prompts if "DWDM" in m]
        self.assertEqual(len(asked), 1)
        self.assertIn("SITE", asked[0])
        self.assertIn("9310", asked[0])  # the channel to look for

    def test_a_seeded_shelf_is_walked_even_though_nothing_reports_it(self):
        crt_obj = self._optical_network()
        crt_obj.Dialog.seed_answer = "172.16.9.9"
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
            names = sorted(p.name.split("_")[0] for p in Path(tmp).iterdir())
        self.assertEqual(names, ["SITE-A", "SITE-B", "SITE-C", "SITE-D", "SITE-E"])
        # The getty account, not the CLI identity: an 1830 authenticates twice,
        # and "cli" is what ssh must present. The management routing instance is
        # required too -- the default instance has no route to it.
        self.assertIn(
            "ssh 172.16.9.9 -l cli router management", crt_obj.Screen.hop_commands
        )
        # Discovered routers are unaffected -- one ssh login, as before.
        self.assertIn("ssh 172.16.0.2 -l admin", crt_obj.Screen.hop_commands)
        # Still one level deep: a seed is hopped to from the origin like any
        # other target, and returned from before the next.
        self.assertEqual(set(crt_obj.Screen.hops_from), {"172.16.0.1"})
        self.assertEqual(crt_obj.Screen.current, "172.16.0.1")

    def test_the_shelf_question_is_asked_once_not_after_every_drain(self):
        crt_obj = self._optical_network()
        crt_obj.Dialog.seed_answer = "172.16.9.9"
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        # SITE-E is itself at a site with no shelf, so a second pass would ask
        # again and again -- the walk must settle instead.
        self.assertEqual(
            len([m for m, _pw in crt_obj.Dialog.prompts if "DWDM" in m]), 1
        )

    def test_a_seed_already_reached_by_discovery_is_not_visited_twice(self):
        crt_obj = self._optical_network()
        crt_obj.Dialog.seed_answer = "172.16.0.3"
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        self.assertEqual(
            len(crt_obj.Screen.hop_commands), len(set(crt_obj.Screen.hop_commands))
        )

    def test_a_mistyped_seed_is_refused_without_losing_the_walk(self):
        # Refused rather than dropped: a silently skipped seed looks exactly
        # like a device that was never found. The walk itself already happened,
        # so nothing captured is lost.
        crt_obj = self._optical_network()
        crt_obj.Dialog.seed_answer = "172.16.9.999"
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
            names = sorted(p.name.split("_")[0] for p in Path(tmp).iterdir())
        self.assertEqual(names, ["SITE-A", "SITE-B", "SITE-C", "SITE-D"])
        self.assertNotIn("ssh 172.16.9.999 -l admin", crt_obj.Screen.hop_commands)
        self.assertTrue(
            any("not a valid IPv4" in m or "not an IPv4" in m
                for m in crt_obj.Dialog.messages)
        )

    def test_an_unrecognised_platform_is_skipped_without_asking(self):
        # A 180-device network will contain models this tool has no profile for.
        # Raising a dialog on each one would stall an unattended walk.
        network = dict(self.NETWORK)
        network["172.16.0.3"] = (
            "*A:SITE-C# ",
            {"show system information": "\nSystem Name : SITE-C\nSystem Type : 7999 MYSTERY\n"},
        )
        crt_obj = FakeCrt()
        crt_obj.Screen = WalkFakeScreen(network, "172.16.0.1")
        crt_obj.Dialog = ChainDialog()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
            names = sorted(p.name.split("_")[0] for p in Path(tmp).iterdir())
        # C is skipped, and because nothing was parsed from it, D behind it is
        # not discovered -- but the walk finishes cleanly and says so.
        self.assertEqual(names, ["SITE-A", "SITE-B"])
        self.assertEqual(crt_obj.Screen.current, "172.16.0.1")
        self.assertTrue(
            any("platform not recognised" in m for m in crt_obj.Dialog.messages)
        )
        # No dialog offered a manual platform choice.
        # Nothing was asked about the platform; the seed field is unrelated.
        self.assertEqual(
            [m for m, _pw in crt_obj.Dialog.prompts if "7999" in m or "profile" in m.lower()],
            [],
        )

    def test_an_unreachable_device_does_not_stop_the_walk(self):
        network = dict(self.NETWORK)
        # SITE-B also claims a neighbour that cannot be reached.
        network["172.16.0.2"] = (
            "*A:SITE-B# ",
            _router_responses("SITE-B", "172.16.0.2", ["172.16.0.1", "172.16.0.3", "172.16.0.99"]),
        )
        crt_obj = FakeCrt()
        crt_obj.Screen = WalkFakeScreen(network, "172.16.0.1")
        crt_obj.Dialog = ChainDialog()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
            names = sorted(p.name.split("_")[0] for p in Path(tmp).iterdir())
        # The dead end is skipped and the rest still gets walked.
        self.assertEqual(names, ["SITE-A", "SITE-B", "SITE-C", "SITE-D"])
        self.assertEqual(crt_obj.Screen.current, "172.16.0.1")


class SecureCrtButtonTests(unittest.TestCase):
    def test_button_captures_transcript_and_writes_audit(self):
        crt_obj = FakeCrt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
            runs = list(Path(tmp).iterdir())
            self.assertEqual(len(runs), 1, "expected exactly one run directory")
            run_dir = runs[0]
            self.assertIn("7705-sar-8", run_dir.name)

            transcript = (run_dir / "transcript.txt").read_text(encoding="utf-8")
            self.assertIn("# Profile: 7705-sar-8", transcript)
            self.assertIn("# COMMAND: show port detail", transcript)
            # The prompt+echo line must survive so the transcript splits the
            # same way a plain terminal log does.
            self.assertIn(PROMPT + "show port detail", transcript)

            audit = json.loads((run_dir / "audit.json").read_text(encoding="utf-8"))
            self.assertEqual(audit["devices"]["SITE-A"]["platform"], "7705-sar-8")
            self.assertTrue((run_dir / "audit.md").exists())

    def test_only_read_only_commands_reach_the_device(self):
        crt_obj = FakeCrt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        sent = [d.rstrip("\r") for d in crt_obj.Screen.sent if d not in ("\r", " ")]
        self.assertTrue(sent, "no commands were sent")
        for command in sent:
            normalized = " ".join(command.lower().split())
            self.assertTrue(
                normalized.startswith("show ") or normalized == "environment no more",
                f"non-read-only command reached the device: {command!r}",
            )

    def test_paging_is_disabled_before_any_show_command(self):
        crt_obj = FakeCrt()
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
        sent = [d.rstrip("\r") for d in crt_obj.Screen.sent if d not in ("\r", " ")]
        # Detection probes run first; the profile itself must lead with paging.
        start = sent.index("environment no more")
        self.assertNotIn("show port detail", sent[:start])

    def test_disconnected_session_does_nothing(self):
        crt_obj = FakeCrt()
        crt_obj.Session = FakeSession()
        crt_obj.Session.Connected = False
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
            self.assertEqual(list(Path(tmp).iterdir()), [])
        self.assertEqual(crt_obj.Screen.sent, [])

    def test_output_stays_with_its_own_command_despite_a_stale_prompt(self):
        # Regression: learning the prompt costs a bare "\r", and the prompt the
        # device sends back sat unconsumed in the read stream. It then satisfied
        # the next command's read immediately, so every section held the
        # previous command's output and drifted a character further each time --
        # on real hardware "show system information" landed inside the
        # "environment no more" section and nothing parsed.
        crt_obj = FakeCrt(stale_prompt=True)
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
            run_dir = next(Path(tmp).iterdir())
            transcript = (run_dir / "transcript.txt").read_text(encoding="utf-8")

        sections = _sections(transcript)
        # The output must sit under the command that produced it.
        self.assertIn("System Type            : 7705 SAR-8", sections["show system information"])
        self.assertIn("Interface          : 1/1/1", sections["show port detail"])
        # ...and must not have leaked into the preceding command's section.
        self.assertNotIn("System Type", sections["environment no more"])
        self.assertNotIn("Interface          :", sections["show port"])

    def test_transcript_sections_are_not_truncated_at_the_front(self):
        # The drift showed up as progressively-lost leading characters
        # ("nvironment no more", "how chassis detail", "ow mda").
        crt_obj = FakeCrt(stale_prompt=True)
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
            run_dir = next(Path(tmp).iterdir())
            transcript = (run_dir / "transcript.txt").read_text(encoding="utf-8")
        for fragment in ("nvironment no more", "how system information", "ow port detail"):
            self.assertNotIn("\n " + fragment, transcript)

    def test_pss_session_selects_the_optical_profile(self):
        responses = {
            "show general system-identification": "\nShelf Type: PSS-8\nSerial: ABC123\n",
            "paging status disabled": "",
        }
        crt_obj = FakeCrt(prompt="PSS-A# ", responses=responses)
        with tempfile.TemporaryDirectory() as tmp:
            run_button(crt_obj, tmp)
            run_dir = next(Path(tmp).iterdir())
            self.assertIn("1830-pss-8", run_dir.name)
        sent = [d.rstrip("\r") for d in crt_obj.Screen.sent if d not in ("\r", " ")]
        self.assertIn("paging status disabled", sent)
        self.assertIn("show card sfdc8b *", sent)
        self.assertNotIn("environment no more", sent)


if __name__ == "__main__":
    unittest.main()
