import logging
import os
import subprocess
import sys
from typing import Optional, Tuple, List

# Suppress console windows when running as a frozen GUI app on Windows.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

class Updater:
    """
    Secure update manager with user confirmation, change preview, and source validation.

    Implements:
    - Branch/tag validation (only pulls from main/master)
    - Commit signature verification (REQUIRED by default; failures abort the pull)
    - Diff preview (shows changes before applying)
    - User confirmation dialog (explicit approval required)
    - No auto-restart (user decides when to restart)

    Signature enforcement:
        Updates are refused unless every incoming commit carries a good (G) or
        unknown-but-trustworthy (U) GPG signature. Operators who run in
        environments that cannot sign (mirrored forks, internal builds) may
        opt out by either passing ``enforce_signatures=False`` to the
        constructor or by setting the ``LAMIS_ALLOW_UNSIGNED_UPDATES=1``
        environment variable. Both produce a loud WARNING in the audit log so
        the bypass is visible.
    """

    # Allowed branches for automatic updates (supply chain safety)
    ALLOWED_UPDATE_BRANCHES = ["main", "master"]

    # GPG status codes returned by `git log --format=%G?`:
    #   G = good (valid) signature
    #   U = good signature with unknown validity (signed but signer not in our keyring)
    #   B = BAD signature
    #   X = good but expired signature
    #   Y = good signature made by an expired key
    #   R = good signature made by a revoked key
    #   E = signature cannot be checked (missing key)
    #   N = no signature
    _GPG_GOOD_STATUSES = ("G", "U")
    _GPG_BAD_STATUSES = ("B", "X", "Y", "R", "E", "N")

    def __init__(
        self,
        repo_path: Optional[str] = None,
        enforce_signatures: bool = True,
    ):
        self.repo_path = repo_path or "https://github.com/Chees3loaf/Network-Inventory-Update"
        self.confirmation_callback = None  # For GUI integration

        # Resolve the env-var opt-out at construction so the policy is fixed
        # for the life of this Updater instance.
        env_opt_out = os.environ.get("LAMIS_ALLOW_UNSIGNED_UPDATES", "").strip() in (
            "1", "true", "yes",
        )
        self.enforce_signatures = enforce_signatures and not env_opt_out
        if not self.enforce_signatures:
            logging.warning(
                "[UPDATE] GPG signature enforcement DISABLED — updates may be "
                "applied from unsigned/untrusted commits. Set "
                "LAMIS_ALLOW_UNSIGNED_UPDATES=0 (or unset it) and pass "
                "enforce_signatures=True to re-enable."
            )

        # Ensure the repository is properly set up
        if not os.path.exists(os.path.join(self.repo_path, ".git")):
            logging.error(f"Repository not found at {self.repo_path}. Please check the path or re-clone it.")
            raise FileNotFoundError(f"Repository not found at {self.repo_path}")

    def set_confirmation_callback(self, callback):
        """Set callback function for user confirmation dialog (for GUI integration)."""
        self.confirmation_callback = callback

    def _get_current_branch(self) -> Optional[str]:
        """Get the current git branch."""
        try:
            result = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True,
                creationflags=_NO_WINDOW,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None

    def _validate_branch(self) -> Tuple[bool, str]:
        """Validate that we're on an allowed branch for updates."""
        current_branch = self._get_current_branch()
        if not current_branch:
            return False, "Could not determine current branch"
        
        if current_branch not in self.ALLOWED_UPDATE_BRANCHES:
            return False, f"Updates only allowed on branches: {', '.join(self.ALLOWED_UPDATE_BRANCHES)}. Current branch: {current_branch}"
        
        return True, f"On allowed branch: {current_branch}"

    def _verify_commit_signatures(self, commit_range: str) -> Tuple[bool, List[str]]:
        """
        Verify GPG signatures on commits to be pulled.

        A commit is acceptable only if its ``%G?`` status is ``G`` (good) or
        ``U`` (good but signer not in the local keyring — still
        cryptographically valid). All other statuses — bad/expired/revoked
        signatures, missing keys, and unsigned commits — are treated as
        verification failures.

        Returns:
            ``(all_signed, messages)`` — ``all_signed`` is True only when
            every commit in the range has an acceptable signature. ``messages``
            contains one entry per problem commit (or a single entry
            describing why the check could not run).
        """
        try:
            result = subprocess.run(
                ['git', 'log', '--format=%H %G?', commit_range],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=False,
                creationflags=_NO_WINDOW,
            )

            if result.returncode != 0:
                err = result.stderr.strip() or "git log returned non-zero"
                logging.warning(f"[UPDATE] Could not list commits for signature check: {err}")
                return False, [
                    f"Could not enumerate incoming commits to verify signatures: {err}"
                ]

            stdout = result.stdout.strip()
            if not stdout:
                # No commits to verify (already up to date) — treat as pass.
                return True, []

            messages: List[str] = []
            all_good = True

            for line in stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                commit = parts[0][:8]
                status = parts[-1] if len(parts) > 1 else '?'

                if status in self._GPG_GOOD_STATUSES:
                    continue
                all_good = False
                if status == 'N':
                    messages.append(f"Commit {commit}: UNSIGNED")
                elif status == 'B':
                    messages.append(f"Commit {commit}: BAD signature")
                elif status == 'X':
                    messages.append(f"Commit {commit}: signature EXPIRED")
                elif status == 'Y':
                    messages.append(f"Commit {commit}: signing key EXPIRED")
                elif status == 'R':
                    messages.append(f"Commit {commit}: signing key REVOKED")
                elif status == 'E':
                    messages.append(f"Commit {commit}: signature could not be checked (missing key)")
                else:
                    messages.append(f"Commit {commit}: unknown signature status '{status}'")

            return all_good, messages

        except FileNotFoundError:
            logging.error("[UPDATE] git executable not found")
            return False, ["git executable not found on PATH"]
        except Exception as e:
            logging.warning(f"[UPDATE] Signature verification failed: {e}")
            return False, [f"Signature verification error: {e}"]

    def _get_diff_summary(self) -> str:
        """Get a summary of changes that would be applied."""
        try:
            # Show summary: files changed, insertions/deletions
            result = subprocess.run(
                ['git', 'diff', '--stat', 'HEAD...@{u}'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=False,
                creationflags=_NO_WINDOW,
            )
            
            if result.stdout:
                return "Files to be changed:\n" + result.stdout[:500]  # Limit to 500 chars
            return "No file changes detected"
        except Exception as e:
            logging.debug(f"Could not generate diff summary: {e}")
            return "Could not generate change summary"

    def check_for_updates(self) -> bool:
        """Check if updates are available by fetching the latest changes from the repository."""
        logging.info("Checking for updates...")
        try:
            result = subprocess.run(
                ['git', 'fetch'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True,
                creationflags=_NO_WINDOW,
            )
            logging.debug(f"Git fetch output: {result.stdout}")
            
            result = subprocess.run(
                ['git', 'status'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True,
                creationflags=_NO_WINDOW,
            )
            logging.debug(f"Git status output: {result.stdout}")
            
            return 'Your branch is behind' in result.stdout or 'can be fast-forwarded' in result.stdout
        except subprocess.CalledProcessError as e:
            logging.error(f"Git command failed: {e.stderr}")
            return False
        except Exception as e:
            logging.error(f"Error while checking for updates: {e}")
            return False

    def apply_update(self) -> Tuple[bool, str]:
        """
        Apply updates with full security checks and user confirmation.
        
        Returns:
            (success, message)
        """
        logging.info("Preparing to apply updates...")
        
        # 1. Validate branch
        branch_valid, branch_msg = self._validate_branch()
        if not branch_valid:
            logging.error(f"Branch validation failed: {branch_msg}")
            return False, f"❌ {branch_msg}"
        
        logging.info(f"✓ {branch_msg}")
        
        # 2. Verify commit signatures.
        is_signed, sig_messages = self._verify_commit_signatures('HEAD...@{u}')
        for msg in sig_messages:
            logging.warning(f"[UPDATE] Signature issue: {msg}")

        if not is_signed and self.enforce_signatures:
            joined = "\n  - ".join(sig_messages) if sig_messages else "(no details)"
            err = (
                "Update aborted: commit signature verification failed.\n"
                f"  - {joined}\n"
                "Resolve by importing the maintainer's GPG public key, or set "
                "LAMIS_ALLOW_UNSIGNED_UPDATES=1 to override (NOT recommended)."
            )
            logging.error(f"[UPDATE] {err}")
            return False, f"❌ {err}"

        # 3. Get diff summary
        diff_summary = self._get_diff_summary()

        # 4. Build confirmation message
        if is_signed:
            sig_label = "✓ All commits signed and verified"
        elif self.enforce_signatures:
            # Should never reach here — we returned above. Guard anyway.
            sig_label = "❌ Signature verification failed"
        else:
            sig_label = "⚠️ Signature enforcement DISABLED (operator override)"

        confirmation_message = (
            "⚠️ UPDATE CONFIRMATION REQUIRED\n\n"
            f"Branch: {self._get_current_branch()}\n"
            f"Signature Status: {sig_label}\n\n"
            f"{diff_summary}\n\n"
        )

        if sig_messages:
            confirmation_message += "⚠️ Signature notes:\n"
            for w in sig_messages:
                confirmation_message += f"  - {w}\n"
            confirmation_message += "\n"
        
        confirmation_message += "Do you want to apply these changes and restart ATLAS?"
        
        # 5. Request user confirmation (can be overridden for testing)
        if self.confirmation_callback:
            approved = self.confirmation_callback(confirmation_message)
        else:
            # Fallback for CLI usage (non-interactive)
            print(confirmation_message)
            user_input = input("Apply update? (yes/no): ").strip().lower()
            approved = user_input in ('yes', 'y')
        
        if not approved:
            logging.info("Update cancelled by user")
            return False, "Update cancelled"
        
        # 6. Apply the update
        logging.info("Applying updates...")
        try:
            result = subprocess.run(
                ['git', 'pull'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True,
                creationflags=_NO_WINDOW,
            )
            logging.info(f"Updates applied: {result.stdout}")
            return True, "✓ Updates applied successfully. Restart ATLAS to complete."
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to apply updates: {e.stderr}")
            return False, f"❌ Failed to apply updates: {e.stderr}"
        except Exception as e:
            logging.error(f"Error while applying updates: {e}")
            return False, f"❌ Update error: {e}"

    @staticmethod
    def _safe_restart_argv() -> list:
        """Return a sanitized argv for re-exec.

        F016 hardening: ``sys.argv`` may contain credentials or attacker-controlled
        flags (e.g. ``--password=...`` from a launcher). Re-executing with the
        original argv would echo those values into the new process and into any
        process listing. We keep only ``sys.argv[0]`` (the script path) and drop
        all user-supplied arguments. Callers needing arguments preserved must
        explicitly opt in via the ``LAMIS_RESTART_ARGS`` environment variable.
        """
        script = sys.argv[0] if sys.argv else ""
        extra = os.environ.get("LAMIS_RESTART_ARGS", "").strip()
        argv = [script] if script else []
        if extra:
            # Only allow simple, non-sensitive tokens (alnum + a few safe chars).
            safe = []
            for tok in extra.split():
                if all(c.isalnum() or c in "-_./=" for c in tok) and len(tok) <= 64:
                    safe.append(tok)
            argv.extend(safe)
        return argv

    def restart_program(self) -> None:
        """Restart the program after updates are applied (F016: sanitized argv)."""
        argv = self._safe_restart_argv()
        logging.info("Restarting ATLAS (argv0=%s, extra_args=%d)",
                     os.path.basename(argv[0]) if argv else "<none>",
                     max(0, len(argv) - 1))
        try:
            os.execl(sys.executable, sys.executable, *argv)
        except Exception as e:
            logging.error(f"Error while restarting the program: {e}")


if __name__ == "__main__":
    updater = Updater()
    if updater.check_for_updates():
        success, message = updater.apply_update()
        print(message)
        if success:
            input("Press Enter to restart ATLAS...")
            updater.restart_program()
    else:
        logging.info("No updates available.")
