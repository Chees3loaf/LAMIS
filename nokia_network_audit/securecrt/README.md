# SecureCRT button — audit the device you are already logged into

`nokia_audit_button.py` drives the **existing** SecureCRT session rather than
opening its own connection. Whatever got you to the device — jump host, telnet,
serial console, saved credentials, MFA — the button inherits it. It never
prompts for or stores a password.

Verified against SecureCRT **9.6.4** on Windows. SecureCRT 9.x runs scripts
through `PythonNNN-shim.dll` against your **system** Python 3.10–3.13, so the
script imports `nokia_network_audit` directly. There is no third-party
dependency and no subprocess.

## Prerequisite: a Python version SecureCRT can load

SecureCRT does not bundle Python. It loads your **system** interpreter through
`PythonNNN-shim.dll`, and 9.6.4 ships shims for **3.10, 3.11, 3.12, and 3.13
only**. Pressing the button with anything else installed gives:

> Unable to load the Python scripting engine. Please download and install the
> latest Python 3.13, 3.12, 3.11 or 3.10 release for your platform

Two things cause this even when a supported Python *is* installed:

- **A newer Python (3.14+) is also present.** There is no shim for it.
- **The supported Python is a per-user install and its folder is not on
  `PATH`.** The shim resolves `python312.dll` through the normal DLL search, and
  a per-user install registers under `HKCU` where a 64-bit host may not look.

Fix by putting the supported interpreter's directory on your user `PATH` — the
folder containing `python312.dll`, e.g.
`%LOCALAPPDATA%\Programs\Python\Python312` — then **fully quit and reopen
SecureCRT**. A running instance keeps the environment it started with, so
closing tabs is not enough.

Check what you have with `py --list`.

## Install the button

1. SecureCRT → **View → Button Bar**, so the bar is showing. With no buttons
   defined it is just a blank strip along the edge of the window — there is no
   visible slot to aim at, which makes the next step confusing.
2. **Right-click anywhere on that blank strip** → **New Button…**
3. In the dialog, set **Function** to `Run Script`.
4. Browse to `<repo>\nokia_network_audit\securecrt\nokia_audit_button.py`.
5. Set **Label** to something like `Nokia Audit`, then **OK**.

The button now appears on the bar. Connect to a device, sit at an idle CLI
prompt, and press it.

Already-configured buttons live in `%APPDATA%\VanDyke\Config\ButtonBarV5.ini`;
one line per button, so you can confirm the script path there without reopening
the dialog.

### If a run writes only `transcript.txt`

No `audit.json`/`audit.md`, and no offer to walk, means the audit package did not
load. The button then falls back to a command list built into the script itself,
which is enough to capture but nothing else. The summary now says so explicitly
and prints the reason.

SecureCRT keeps one Python interpreter alive across button presses, so an
imported module stays cached. The script drops its own package from
`sys.modules` on every press so edits to the repo take effect immediately — but
if you see a stale-looking run, restarting SecureCRT is the sure fix.

### If you copy the script out of the repo

The script finds the audit package by walking up from its own location
(`crt.ScriptFullName`). If you move it into SecureCRT's script directory, set an
environment variable so it can still find the package:

```powershell
setx NOKIA_AUDIT_REPO "C:\Users\<you>\Downloads\ATLAS"
```

Without it the button still captures the transcript — it just skips the audit
step and tells you so.

## What happens when you press it

| Step | Detail |
| --- | --- |
| 1 | Reads the current prompt off the screen, and takes the **device name from it** — `A:MOPN002_7705#` → `MOPN002_7705`. |
| 2 | Identifies the platform from the device: `show system information` on SR OS, `show general system-identification` on the 1830. The prompt shape decides which to try first, so a router is never asked the 1830 question. |
| 3 | Shows the **full list of commands** it is about to send, for confirmation. It only asks you to pick a platform if detection came back empty. |
| 4 | Disables pagination for this CLI session only. |
| 5 | Sends the profile's `show` commands, one at a time, reading to the prompt. |
| 6 | Writes `transcript.txt`, then `audit.json` and `audit.md`. |

Output goes to
`%USERPROFILE%\Documents\NokiaNetworkAudit\<device>_<profile>_<UTC stamp>\`.
Override the base directory with the `NOKIA_AUDIT_OUTPUT` environment variable.

The directory is named for the **device**, not the address used to reach it. A
chained hop arrives by system address while a direct session uses the management
address, so naming by address made one device look like two.

Per-command timeout is 120 s. A command that times out is recorded in the
transcript as `# ERROR: command timed out` and named in the summary dialog; the
run continues.

## Network walk (SR OS routers only)

After auditing the device you are on, if it is an SR OS router the button offers
to **walk the topology** — capture its routed neighbours, then whatever *they*
report, outward until nothing new is found. It shows what it knows so far and
does nothing without a Yes:

```text
SITE-A reports 3 routed neighbour(s).

  172.16.245.201 (BKLY001_7250) (via 1/1/c7/1)
      ssh 172.16.245.201 -l admin
  ...
Only these exact commands will be sent to open a session.
```

Targets come from **OSPF adjacency**, so they are addresses the device is
actually routing to — not names read off an interface description. Already
visited devices are skipped, so a mesh cannot loop.

The transport is read from the device: `Tel/Tel6/SSH/FTP Admin`. These routers
ship **telnet disabled and SSH enabled**, so it uses `ssh`; a telnet hop would
simply fail.

### Every hop is made from the origin

The walk goes anywhere in the network, but the **session never nests**. Each
hop is `origin → device → logout → origin`, even for a device four hops away in
the topology.

That works because within one routing domain every system address is an
advertised `/32`, so the origin can already reach the whole network — there is
no need to tunnel through intermediates. The alternative, walking depth-first,
would need an unwinding stack of `logout`s, and losing count of that stack is
exactly how an operator's session ends up somewhere they did not ask to be.

A device that cannot be reached is recorded and skipped; the walk carries on.

### Host keys

Every device the origin has not reached before presents an unrecognised host
key, and **SR OS has no way to suppress the question** — its ssh client accepts
only `-l`, `router`, `re-exchange-*` and `-p`. So it has to be answered for each
new host.

Answering per host does not scale: a 40-device walk raised 36 dialogs, and the
full network would raise ~180 — which nobody reads carefully by the end. So the
walk asks **once, before the first hop**:

- **Yes** — accept every key for this walk, and list each one with its
  fingerprint in the summary.
- **No** — ask about each device individually, as before.

Either way the accepted keys are reported, so the run leaves a record:

```text
Host keys accepted (no prompt, chosen once for this walk):
  172.16.245.181  SHA256:JA1klaKRonwP5IY7y89TYNeieAUg9fNSYzLK1Q7Mq8s
  172.16.245.201  SHA256:/tANxAxTEASc+aztwO4evV3B9R/eQuOqegra+YRixUA
```

This is a real trade: accepting keys in bulk means a machine-in-the-middle on
the management network would not be noticed at the moment of connection. What it
buys is that the decision is made once, deliberately, with the fingerprints
written down — rather than a hundred-and-eightieth dialog answered on autopilot.
The fingerprints are also in the SecureCRT session log, so they can be checked
after the fact.

### When it stops

- nothing new left to visit, or
- the device cap is hit — it says how many were still queued. Default 40; raise
  it with `NOKIA_AUDIT_MAX_DEVICES`. The default is a bound on one run, not a
  claim about network size.

At the end it reports **LAGs whose far end was never reached**. That is the real
completeness test: a LAG always looks healthy from one side, so it is only
properly checked once the device on the other end has been captured too.

Note that LAG-completeness and topology-completeness are different conditions.
A pod's LAGs can all be paired while the walk still has devices queued, because
not every link is a LAG.

### What the walk will *not* reach

| Gap | Effect |
| --- | --- |
| **IS-IS or LDP-only neighbours** | Only OSPF adjacency is parsed. `show router isis adjacency` and `show router ldp session` are captured but not interpreted, so the walk stops at any IS-IS boundary. |
| **Models with no profile** | Only 7705 SAR-8, 7250 IXR-R6/R6d/R6dl and 1830 PSS-8 exist. Others are recorded as "platform not recognised, skipped" and — because nothing is parsed from them — anything reachable only *through* them stays undiscovered. |
| **1830 PSS** | No CLI client to hop with; the walk never targets one. |
| **Different credentials** | A device that rejects the configured login ends that hop and is skipped. |
| **Separate routing domains** | Every hop is made from the origin, so a device is only reachable if the origin has a route to it. True within one IGP domain; not across VRFs or disconnected domains. |

There is also no resume: if a long walk is interrupted, the queue is lost and it
restarts from the origin. Already-captured devices are re-captured.

Guard rails, in the order they matter:

| Guard | What it does |
| --- | --- |
| Command allowlist | `chain.assert_hop_command()` re-validates immediately before typing: a bare `ssh`/`telnet` to the **approved literal IPv4 address** and nothing else. A second command, a pipe, a metacharacter, a hostname, or a different address is refused. |
| Host keys | Decided **once per walk**, not once per host — see below. Declining a key answers `no` and skips that target. |
| Return check | `logout` is only sent once the prompt has actually changed, so it can never drop your own session. If the origin prompt does not come back, the walk **stops** and tells you where the session is rather than typing into an unknown context. |
| Walk cap | `chain.MAX_WALK_DEVICES` (40) bounds a run on a network larger than expected. |
| Read-only | The far device gets the same `show`-only profile. Nothing else is sent. |
| Credentials | Defaults to `admin`/`admin`, the lab convention — no prompt. Override with `NOKIA_AUDIT_USER` / `NOKIA_AUDIT_PASSWORD`. Held in memory for the run only; never written to a transcript, a report, or disk. A device that rejects them ends that hop rather than retrying, so a wrong value cannot lock an account out. |

Depth is capped at `chain.MAX_DEPTH`. `telnet`/`ssh` are **not** read-only, so
neither is in any capture profile — there is a test asserting that — and the
button only ever uses them to open a session, never as an audit command.

## Safety

Commands come from `nokia_network_audit/profiles.py` and are re-checked
**in this process, immediately before each is sent**, against the same
allowlist. A command must either begin with `show` or be the platform's
documented pagination setting:

- SR OS classic — `environment no more`
  (7705 SAR Basic System Configuration Guide 25.10.R1, CLI environment commands)
- 1830 PSS — `paging status disabled`
  (1830 PSS R24.12 CLI Guide §2.16 *paging*, p207 — Observer level,
  "Command Access Level Impact: None"; note the value is `disabled`,
  not `disable`)

Anything else aborts the run before a single keystroke reaches the device.

Note that read-only is not the same as free. Some `detail` commands produce
substantial CPM output on a large chassis. Start with one device per platform
in an observation window before making this routine.

## Testing without hardware

`tests_network_audit/test_securecrt_button.py` fakes the `crt` object and runs
the whole button flow — prompt discovery, platform detection, the read-only
guard, capture, transcript layout, and the audit hand-off:

```powershell
py -3 -m unittest tests_network_audit.test_securecrt_button -v
```
