"""One-time import: db.json (old atomic store) -> SQLAlchemy (SQLite/Postgres).

Usage:
  cd backend
  py -3 migrate_json_to_sql.py
  # reads MONO_DB_PATH (default db.json), writes to DATABASE_URL (default mono.db)
"""
import json
import os
import time
from pathlib import Path

from db import SessionLocal, User, Resume, init_db

SRC = Path(os.getenv("MONO_DB_PATH", str(Path(__file__).parent / "db.json")))

def main():
    init_db()
    if not SRC.exists():
        print(f"No {SRC.name} found — nothing to import.")
        return
    try:
        raw = json.loads(SRC.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Could not read {SRC}: {e}")
        return
    db = SessionLocal()
    try:
        n_u = n_r = 0
        for u in raw.get("users", []):
            if not db.query(User).filter(User.id == u.get("id")).first():
                db.add(User(id=u["id"], name=u.get("name", ""), email=u.get("email", ""),
                            pw=u.get("pw", ""), created_at=u.get("createdAt", int(time.time()*1000))))
                n_u += 1
        for r in raw.get("resumes", []):
            if not db.query(Resume).filter(Resume.id == r.get("id")).first():
                db.add(Resume(id=r.get("id"), owner_id=r.get("ownerId", ""),
                              data=r, created_at=r.get("createdAt", 0), updated_at=r.get("updatedAt", 0)))
                n_r += 1
        db.commit()
        print(f"Imported {n_u} users, {n_r} resumes.")
        print("Keep db.json as backup; app now reads from SQL database.")
    finally:
        db.close()

if __name__ == "__main__":
    main()
