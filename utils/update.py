import logging
import os
import subprocess

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class Updater:
    def __init__(self, repo_path=None):
        self.repo_path = repo_path or "C:/Users/ZackerySimino/OneDrive - LightRiver Technologies Inc/Git/Git Repo"

        # Ensure the repository is properly set up
        if not os.path.exists(os.path.join(self.repo_path, ".git")):
            logging.error(f"Repository not found at {self.repo_path}. Please check the path or re-clone it.")
            raise FileNotFoundError(f"Repository not found at {self.repo_path}")


    def check_for_updates(self):
        """Checks if updates are available by fetching the latest changes from the repository."""
        logging.info("Checking for updates...")
        try:
            result = subprocess.run(['git', 'fetch'], cwd=self.repo_path, capture_output=True, text=True, check=True)
            logging.debug(f"Git fetch output: {result.stdout}")
            
            result = subprocess.run(['git', 'status'], cwd=self.repo_path, capture_output=True, text=True, check=True)
            logging.debug(f"Git status output: {result.stdout}")
            
            return 'Your branch is behind' in result.stdout or 'can be fast-forwarded' in result.stdout
        except subprocess.CalledProcessError as e:
            logging.error(f"Git command failed: {e.stderr}")
            return False
        except Exception as e:
            logging.error(f"Error while checking for updates: {e}")
            return False

    def apply_update(self):
        """Applies the update by pulling the latest changes from the repository."""
        logging.info("Applying updates...")
        try:
            result = subprocess.run(['git', 'pull'], cwd=self.repo_path, capture_output=True, text=True, check=True)
            logging.info(f"Updates applied: {result.stdout}")
            self.restart_program()
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to apply updates: {e.stderr}")
        except Exception as e:
            logging.error(f"Error while applying updates: {e}")

    def restart_program(self):
        """Restarts the program after applying updates."""
        logging.info("Restarting the program...")
        try:
            os.execl(os.sys.executable, os.sys.executable, *os.sys.argv)
        except Exception as e:
            logging.error(f"Error while restarting the program: {e}")

if __name__ == "__main__":
    updater = Updater()
    if updater.check_for_updates():
        updater.apply_update()
    else:
        logging.info("No updates available.")
