"""Part-number lookup without GUI dependencies."""
from __future__ import annotations
import re
import sqlite3
from pathlib import Path
from typing import Optional

_VENDOR_PREFIX_RE = re.compile(r"^(?:1P|P)", re.IGNORECASE)


def lookup_part(db_path: str | Path, query: str, max_suggestions: int = 10) -> tuple[Optional[str], list[tuple[str, str]]]:
    normalized = _VENDOR_PREFIX_RE.sub("", (query or "").strip()).upper()
    if not normalized: return None, []
    with sqlite3.connect(str(db_path)) as connection:
        row = connection.execute("SELECT description FROM parts WHERE UPPER(part_number) = ?", (normalized,)).fetchone()
        rows = connection.execute("SELECT part_number, description FROM parts WHERE UPPER(part_number) LIKE ? ORDER BY part_number LIMIT ?", (normalized + "%", max_suggestions + 1)).fetchall()
    exact = row[0] if row else None
    suggestions = [(part, description) for part, description in rows if part.upper() != normalized][:max_suggestions]
    return exact, suggestions
