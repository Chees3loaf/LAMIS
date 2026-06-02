"""
Configuration constants for ATLAS (Automated Toolkit for Lightriver Asset & Systems).

Centralized location for all configuration values to make the system more maintainable
and easier to customize across different environments.
"""

# ============================================================================
# APPLICATION / UPDATE
# ============================================================================

# Keep this in lockstep with ATLAS.nsi `ProductVersion` so the installer and
# the running app agree on what's currently installed. The updater compares
# this against the latest GitHub release tag.
APP_VERSION = "2.0.7.1"

# GitHub release feed used by utils.update.Updater when running as an
# installed (frozen) build. Overridable via the LAMIS_UPDATE_REPO env var.
# The repo named here only needs to host the GitHub Releases — it doesn't
# have to be the source repo. Releases live in a dedicated public
# "Network-Inventory-Update" repo so source can stay wherever it lives
# while update distribution gets its own home.
GITHUB_OWNER = "Chees3loaf"
GITHUB_REPO = "Network-Inventory-Update"

# Filename of the installer asset attached to each release.
INSTALLER_ASSET_NAME = "ATLAS_Setup.exe"

# How long to wait on the GitHub API / asset download before giving up.
UPDATE_HTTP_TIMEOUT_S = 15

# ============================================================================
# NETWORK CONFIGURATION
# ============================================================================

# Pod/Network settings
POD_NETWORK_PREFIX = "10.9"          # IP network prefix (e.g., "10.9.{pod}.{host}")
POD_MIN = 100                         # Minimum pod number
POD_MAX = 112                         # Maximum pod number
POD_COUNT = 13                        # Number of pod options (POD_MAX - POD_MIN + 1)

# Default SSH/Telnet ports (standard, unlikely to change)
SSH_PORT = 22
TELNET_PORT = 23

# ============================================================================
# AUTHENTICATION
# ============================================================================

# Credentials: ATLAS no longer persists user-entered credentials. The
# only stored creds are the Fernet-encrypted seed list (see
# _BUILTIN_DEFAULT_SEED in utils/credentials.py) which the auth-failure
# rotation cycles through on each device.

# SSH host-key trust policy.
# ATLAS is intended for unattended bulk operations across 100+ devices,
# where prompting the operator to accept each new SSH host key defeats
# the automation. By default we Trust-On-First-Use (TOFU): any unknown
# host key is silently recorded in the LAMIS known_hosts file the first
# time we see it, and enforced strictly thereafter (a *changed* key on a
# subsequent connection still raises and aborts — protecting against
# spoofing once the device is known).
#
# To restore interactive prompting, set env var LAMIS_PROMPT_HOSTKEYS=1
# or flip SSH_AUTO_ACCEPT_HOST_KEYS to False below.
SSH_AUTO_ACCEPT_HOST_KEYS = True

# ============================================================================
# TIMEOUT SETTINGS (in seconds)
# ============================================================================

# Connection timeouts
SSH_CONNECT_TIMEOUT = 10            # SSH connection timeout
TELNET_CONNECT_TIMEOUT = 10         # Telnet connection timeout
TELNET_READ_TIMEOUT = 5             # Telnet read operation timeout
SSH_READ_TIMEOUT = 5                # SSH read operation timeout

# Command execution timeouts
TDS_TIMEOUT = 1800                  # TDS diagnostics timeout (30 minutes)

# ============================================================================
# GUI SETTINGS
# ============================================================================

# Queue polling interval (milliseconds)
QUEUE_POLL_INTERVAL_MS = 100

# Loading screen dimensions
LOADING_SCREEN_WIDTH = 800
LOADING_SCREEN_HEIGHT = 600

# Main window dimensions
MAIN_WINDOW_WIDTH = 900
MAIN_WINDOW_HEIGHT = 750

# ============================================================================
# EXCEL/EXPORT SETTINGS
# ============================================================================

# Template paths (relative to project root)
DEVICE_REPORT_TEMPLATE = "data/Device_Report_Template.xlsx"
PACKING_SLIP_TEMPLATE = "data/ATLAS_Packing_Slip.xlsx"

# Excel column settings
EXCEL_MIN_COLUMN_WIDTH = 10
EXCEL_MAX_COLUMN_WIDTH = 60

# Summary sheet styling
CAPTURE_TIME_FONT_COLOR = "00FF00"      # Green font
CAPTURE_TIME_BG_COLOR = "000000"        # Black background
CAPTURE_TIME_BOLD = True

# Summary sheet starting row for device data
SUMMARY_DATA_START_ROW = 10

# Device sheet starting row for inventory data
DEVICE_DATA_START_ROW = 15

# ============================================================================
# DATABASE SETTINGS
# ============================================================================

# Database file location (relative to project root)
INVENTORY_DB_FILE = "data/network_inventory.db"

# Part number search settings
PART_NUMBER_PREFIX_LENGTH = 10      # Use first N characters of part number for DB lookup

# ============================================================================
# LOGGING SETTINGS
# ============================================================================

# Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
# Default INFO; set to DEBUG only for troubleshooting (may contain device output).
LOG_LEVEL = "INFO"

# Log format
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

# Suppress verbose library logs
PIL_LOG_LEVEL = "WARNING"

# Rotating log handler — bound on-disk footprint.
LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB per file
LOG_BACKUP_COUNT = 5             # Keep the latest 5 rotated files
