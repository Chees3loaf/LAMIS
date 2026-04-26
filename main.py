import logging
import os
from datetime import datetime
from tkinter import Tk, Label
from PIL import Image, ImageTk
from gui.gui4_0 import InventoryGUI
import script_interface
from utils.update import Updater
from script_interface import CommandTracker
import config
from utils.helpers import get_database_path

# Configure logging — write to console AND a timestamped log file
_log_dir = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(_log_dir, exist_ok=True)
_log_file = os.path.join(_log_dir, datetime.now().strftime("LAMIS_%Y-%m-%d_%H-%M-%S.log"))

_root_logger = logging.getLogger()
_root_logger.setLevel(config.LOG_LEVEL)
_fmt = logging.Formatter(config.LOG_FORMAT)

_console_handler = logging.StreamHandler()
_console_handler.setFormatter(_fmt)
_root_logger.addHandler(_console_handler)

_file_handler = logging.FileHandler(_log_file, encoding="utf-8")
_file_handler.setFormatter(_fmt)
_root_logger.addHandler(_file_handler)

# Suppress PIL debug logs
logging.getLogger("PIL").setLevel(config.PIL_LOG_LEVEL)

# Suppress paramiko internal debug logs (kex handshake, cipher negotiation, etc.)
logging.getLogger("paramiko").setLevel(logging.WARNING)

class LoadingScreen:
    def __init__(self, root):
        self.root = root
        self.root.title("Loading LAMIS")
        self.root.geometry("800x600")
        self.root.overrideredirect(True)  # Remove window decorations

        # Center the window
        x = (self.root.winfo_screenwidth() / 2) - 400
        y = (self.root.winfo_screenheight() / 2) - 300
        self.root.geometry(f'+{int(x)}+{int(y)}')

        try:
            logo_path = os.path.join(os.path.dirname(__file__), "L.A.M.I.S Logo.png")
            logo = Image.open(logo_path).resize((800, 600), Image.LANCZOS)
            self.logo = ImageTk.PhotoImage(logo)
            self.logo_label = Label(self.root, image=self.logo)
            self.logo_label.pack(pady=20)
        except Exception as e:
            logging.error(f"Failed to load logo: {e}")
            Label(self.root, text="LightRiver Automated MultiVendor Inventory System (LAMIS)", font=("Arial", 16)).pack(pady=20)

        self.status_label = Label(self.root, text="Loading...", font=("Arial", 12))
        self.status_label.pack(pady=10)
        self.root.update_idletasks()

    def update_status(self, message):
        self.status_label.config(text=message)
        self.root.update_idletasks()

    def close(self):
        self.root.quit()
        self.root.destroy()


def show_loading_screen():
    loading_root = Tk()
    return LoadingScreen(loading_root), loading_root


def check_updates(loading_screen):
    updater = Updater(os.path.dirname(__file__))
    update_available = updater.check_for_updates()
    loading_screen.update_status("Update Available" if update_available else "No Updates")
    loading_screen.close()
    start_gui(update_available)


def start_gui(update_available):
    root = Tk()
    command_tracker = CommandTracker()
    db_cache = script_interface.DatabaseCache(str(get_database_path()))

    InventoryGUI(root, update_available, command_tracker, db_cache)
    root.mainloop()


def main():
    logging.info("Starting LightRiver Automated MultiVendor Inventory System (LAMIS)")
    logging.info(f"Log file: {_log_file}")
    loading_screen, loading_root = show_loading_screen()
    loading_root.after(100, lambda: check_updates(loading_screen))
    loading_root.mainloop()


if __name__ == "__main__":
    main()
