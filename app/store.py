from __future__ import annotations

import json, os, sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.getenv('EVENTWEAVE_DB','/tmp/eventweave.sqlite3'))

def conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute('''CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at TEXT NOT NULL,
      action TEXT NOT NULL,
      subject TEXT NOT NULL,
      detail TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS cases (
      case_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      payload TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )''')
    return c

def audit(action: str, subject: str, detail: str):
    with conn() as c:
        c.execute('INSERT INTO audit(created_at,action,subject,detail) VALUES(?,?,?,?)',
                  (datetime.now(timezone.utc).isoformat(), action, subject, detail))

def list_audit(limit=50):
    with conn() as c:
        rows = c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
        return [dict(r) for r in rows]

def save_case(case_id: str, name: str, payload: dict):
    with conn() as c:
        c.execute('INSERT OR REPLACE INTO cases(case_id,name,payload,updated_at) VALUES(?,?,?,?)',
                  (case_id, name, json.dumps(payload), datetime.now(timezone.utc).isoformat()))

def load_case(case_id: str):
    with conn() as c:
        row = c.execute('SELECT payload FROM cases WHERE case_id=?',(case_id,)).fetchone()
        return json.loads(row['payload']) if row else None
