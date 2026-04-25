"""
Common helper functions for LAMIS.
"""

import os
import re
from typing import Tuple, Union
from pathlib import Path


def get_project_root() -> Path:
    """
    Get the LAMIS project root directory.
    
    The project root is identified by the presence of main.py and config.py.
    Searches upward from the utils directory until found.
    
    Returns:
        Path to project root
        
    Raises:
        FileNotFoundError: If project root cannot be determined
    """
    # Start from utils directory and go up
    utils_dir = Path(__file__).parent
    current = utils_dir.parent
    
    # Look for config.py and main.py as markers
    while current != current.parent:  # Stop at filesystem root
        if (current / "config.py").exists() and (current / "main.py").exists():
            return current
        current = current.parent
    
    raise FileNotFoundError(
        "Could not determine LAMIS project root. "
        "Ensure main.py and config.py exist in the project root."
    )


def get_database_path() -> Path:
    """
    Get the path to the LAMIS inventory database file.
    
    Resolves the database path relative to the project root, ensuring
    consistency across all modules.
    
    Returns:
        Path to network_inventory.db (may not exist, but path is resolved)
        
    Example:
        >>> db_path = get_database_path()
        >>> db_path.name
        'network_inventory.db'
    """
    project_root = get_project_root()
    db_path = project_root / "data" / "network_inventory.db"
    return db_path.resolve()


def extract_ip_sort_key(value: Union[str, None]) -> Tuple:
    """
    Extract IP address from a value and return a sortable tuple.
    
    Enables IP-based sorting by parsing the IP octets numerically.
    Non-IP values sort after valid IPs.
    
    Args:
        value: String that may contain an IP address
        
    Returns:
        Tuple for sorting:
        - (0, octet1, octet2, octet3, octet4, lowercase_string) for valid IPs
        - (1, lowercase_string) for non-IP values
        
    Example:
        >>> extract_ip_sort_key("10.9.100.5")
        (0, 10, 9, 100, 5, "10.9.100.5")
        >>> extract_ip_sort_key("device_name")
        (1, "device_name")
    """
    s = str(value or "").strip()
    match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", s)
    if not match:
        return (1, s.lower())

    ip = match.group(1)
    try:
        octets = [int(x) for x in ip.split(".")]
    except ValueError:
        return (1, s.lower())

    if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
        return (1, s.lower())

    return (0, octets[0], octets[1], octets[2], octets[3], s.lower())
