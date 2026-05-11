import sqlite3
from pathlib import Path

runtime_db = Path.home() / "AppData" / "Roaming" / "ATLAS" / "network_inventory.db"
workspace_db = Path(r"c:\Users\ZackerySimino\Downloads\LAMIS\data\network_inventory.db")

def upsert(db_path: Path, part_number: str, description: str) -> None:
    if not db_path.exists():
        print(f"SKIP (missing): {db_path}")
        return
    con = sqlite3.connect(str(db_path))
    cur = con.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO parts (part_number, description) VALUES (?, ?)",
        (part_number, description),
    )
    con.commit()
    cur.execute("SELECT part_number, description FROM parts WHERE part_number = ?", (part_number,))
    row = cur.fetchone()
    con.close()
    print(f"UPDATED {db_path}: {row}")

part = "3HE06792AA"
desc = "Fan Module (SAR-8 Shelf V2) Ext Temp"

upsert(runtime_db, part, desc)
upsert(runtime_db, "3HE06792AAAB0304", desc)

# Keep workspace DB in sync as well
upsert(workspace_db, part, desc)
upsert(workspace_db, "3HE06792AAAB0304", desc)
