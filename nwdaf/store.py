"""
nwdaf/store.py -- SQLite persistence for alerts and mitigation records.

Alert history and the mitigation log survive NWDAF restarts. Plain stdlib sqlite3,
one connection guarded by a lock, WAL mode, bounded retention.
"""
import json
import os
import sqlite3
import threading
from typing import List

KEEP = 5000


class Store:
    def __init__(self, path: str = None):
        path = path or os.environ.get("IDRS_DB", "/data/idrs.db")
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS alerts(
                threat_id TEXT PRIMARY KEY, detected_at REAL, rule_id TEXT, severity TEXT,
                forwarded INTEGER, body TEXT);
            CREATE TABLE IF NOT EXISTS mitigations(
                mitigation_id TEXT PRIMARY KEY, executed_at REAL, rule_id TEXT, status TEXT, body TEXT);
            CREATE TABLE IF NOT EXISTS state(kind TEXT, key TEXT, ts REAL, PRIMARY KEY(kind, key));
            CREATE INDEX IF NOT EXISTS ix_alerts_t ON alerts(detected_at);
            CREATE INDEX IF NOT EXISTS ix_mit_t ON mitigations(executed_at);
        """)
        self._db.commit()
        self._n = 0

    def save_alert(self, d: dict):
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?)",
                             (d["threat_id"], d["detected_at"], d["rule_id"], d["severity"],
                              int(bool(d.get("forwarded"))), json.dumps(d, default=str)))
            self._commit_and_prune()

    def save_mitigation(self, d: dict):
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO mitigations VALUES (?,?,?,?,?)",
                             (d["mitigation_id"], d["executed_at"], d["rule_id"], d["status"],
                              json.dumps(d, default=str)))
            self._commit_and_prune()

    def save_state(self, kind: str, key: str, ts: float):
        """Engine learned state (PFCP SEIDs, UL TEIDs, smContextRefs, policy ids, first-seen time)."""
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO state VALUES (?,?,?)", (kind, key, ts))
            self._db.commit()

    def load_state(self, max_age: float = 7 * 86400):
        import time
        with self._lock:
            self._db.execute("DELETE FROM state WHERE kind != 'meta' AND ts < ?", (time.time() - max_age,))
            self._db.commit()
            return self._db.execute("SELECT kind, key, ts FROM state").fetchall()

    def load_alerts(self, limit: int = 1000) -> List[dict]:
        with self._lock:
            rows = self._db.execute("SELECT body FROM alerts ORDER BY detected_at DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(r[0]) for r in reversed(rows)]

    def load_mitigations(self, limit: int = 500) -> List[dict]:
        with self._lock:
            rows = self._db.execute("SELECT body FROM mitigations ORDER BY executed_at DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(r[0]) for r in reversed(rows)]

    def _commit_and_prune(self):
        self._db.commit()
        self._n += 1
        if self._n % 200 == 0:
            for t, col in (("alerts", "detected_at"), ("mitigations", "executed_at")):
                self._db.execute(f"DELETE FROM {t} WHERE {col} < (SELECT MIN({col}) FROM "
                                 f"(SELECT {col} FROM {t} ORDER BY {col} DESC LIMIT {KEEP}))")
            self._db.commit()
