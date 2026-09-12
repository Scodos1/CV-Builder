"""Backup: dump users (without password hashes) + resumes to a timestamped JSON file.

Usage:
  cd backend
  py -3 backup.py                    # -> backups/mono-backup-<ts>.json
  py -3 backup.py --restore <file>   # restore into current DATABASE_URL (merges by id)

Restore never overwrites existing rows with the same id; it only adds missing ones.
Keep backups encrypted at rest in production (e.g. age/sops or provider snapshots).
"""
import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from db import SessionLocal, User, Resume, init_db  # noqa: E402


def backup(out_dir: Path) -> Path:
    init_db()
    db = SessionLocal()
    try:
        users = [{"id": u.id, "name": u.name, "email": u.email, "created_at": u.created_at}
                 for u in db.query(User).all()]
        resumes = [{"id": r.id, "owner_id": r.owner_id, "data": r.data,
                    "created_at": r.created_at, "updated_at": r.updated_at}
                   for r in db.query(Resume).all()]
    finally:
        db.close()
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out_dir / f"mono-backup-{ts}.json"
    path.write_text(json.dumps({"exported_at": ts, "users": users, "resumes": resumes}, indent=2), encoding="utf-8")
    print(f"Wrote {path} ({len(users)} users, {len(resumes)} resumes). Password hashes excluded by design.")
    return path


def restore(path: Path):
    init_db()
    raw = json.loads(path.read_text(encoding="utf-8"))
    db = SessionLocal()
    try:
        n_u = n_r = 0
        for u in raw.get("users", []):
            if not db.query(User).filter(User.id == u.get("id")).first():
                # No password hash in backups: force password reset for restored logins.
                db.add(User(id=u["id"], name=u.get("name", ""), email=u.get("email", ""),
                            pw="pbkdf2$200000$" + "0" * 32 + "$" + "0" * 64,
                            created_at=u.get("created_at", int(time.time() * 1000))))
                n_u += 1
        for r in raw.get("resumes", []):
            if not db.query(Resume).filter(Resume.id == r.get("id")).first():
                db.add(Resume(id=r["id"], owner_id=r.get("owner_id", ""), data=r.get("data", {}),
                              created_at=r.get("created_at", 0), updated_at=r.get("updated_at", 0)))
                n_r += 1
        db.commit()
        print(f"Restored {n_u} users (password reset required), {n_r} resumes from {path.name}.")
    finally:
        db.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--restore", default="", help="backup JSON file to merge-restore")
    ap.add_argument("--out", default="backups", help="backup output dir")
    args = ap.parse_args()
    if args.restore:
        restore(Path(args.restore))
    else:
        backup(Path(args.out))
