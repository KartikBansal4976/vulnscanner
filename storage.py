"""Simple SQLite-backed storage for scan jobs.

Stores jobs with JSON-encoded results to survive restarts.
"""
import sqlite3
import json
from pathlib import Path
from typing import Optional, Dict, List


def init_db(path: str | Path):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            target TEXT,
            depth INTEGER,
            created_at REAL,
            status TEXT,
            user TEXT,
            report TEXT,
            results TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def _connect(path: str | Path):
    return sqlite3.connect(str(path), check_same_thread=False)


def create_job(db_path: str | Path, job: Dict):
    conn = _connect(db_path)
    cur = conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO jobs (id,target,depth,created_at,status,user,report,results) VALUES (?,?,?,?,?,?,?,?)",
        (
            job.get("id"),
            job.get("target"),
            job.get("depth"),
            job.get("created_at"),
            job.get("status"),
            job.get("user"),
            job.get("report"),
            json.dumps(job.get("results") or {}),
        ),
    )
    conn.commit()
    conn.close()


def update_job(db_path: str | Path, job_id: str, fields: Dict):
    conn = _connect(db_path)
    cur = conn.cursor()
    # build set clause
    sets = []
    vals = []
    for k, v in fields.items():
        if k == "results":
            sets.append("results = ?")
            vals.append(json.dumps(v or {}))
        else:
            sets.append(f"{k} = ?")
            vals.append(v)
    vals.append(job_id)
    cur.execute(f"UPDATE jobs SET {', '.join(sets)} WHERE id = ?", vals)
    conn.commit()
    conn.close()


def get_job(db_path: str | Path, job_id: str) -> Optional[Dict]:
    conn = _connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id,target,depth,created_at,status,user,report,results FROM jobs WHERE id = ?", (job_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    id, target, depth, created_at, status, user, report, results = row
    try:
        results_obj = json.loads(results) if results else {}
    except Exception:
        results_obj = {}
    return {
        "id": id,
        "target": target,
        "depth": depth,
        "created_at": created_at,
        "status": status,
        "user": user,
        "report": report,
        "results": results_obj,
    }


def get_jobs(db_path: str | Path) -> List[Dict]:
    conn = _connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id,target,depth,created_at,status,user,report,results FROM jobs ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    out = []
    for row in rows:
        id, target, depth, created_at, status, user, report, results = row
        try:
            results_obj = json.loads(results) if results else {}
        except Exception:
            results_obj = {}
        out.append({
            "id": id,
            "target": target,
            "depth": depth,
            "created_at": created_at,
            "status": status,
            "user": user,
            "report": report,
            "results": results_obj,
        })
    return out
