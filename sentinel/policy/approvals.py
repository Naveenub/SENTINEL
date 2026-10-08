"""Human-approval records, persisted in SQLite so a restart does not drop pending requests or approvals
that a human already granted.

Lifecycle: pending -> approved | denied -> consumed (row deleted, single use).
  - Expiry: a pending row expires `ttl` seconds after creation; a decided row expires `ttl` seconds after
    the decision. Expired rows are pruned and behave as if they never existed (the re-submitted call is
    denied). Wall-clock time is used on purpose: monotonic clocks do not survive a restart.
  - Cap: at most `max_pending` pending rows, so an agent cannot grow the table without bound.
  - Arguments are stored only while pending (the approver needs to see them). They are cleared on the
    decision; afterwards only the fingerprint that binds the approval to the exact call remains.
"""
import json
import sqlite3
import threading
import time


class ApprovalStore:
    def __init__(self, path: str = ":memory:", ttl: float = 86400.0, max_pending: int = 1000):
        self.ttl, self.max_pending = ttl, max_pending
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS approvals(
                id TEXT PRIMARY KEY, fp TEXT NOT NULL, agent TEXT NOT NULL, tool TEXT NOT NULL,
                args TEXT, state TEXT NOT NULL, ts REAL NOT NULL);
            """
        )

    def _prune(self, now: float) -> None:  # caller holds the lock
        self.db.execute("DELETE FROM approvals WHERE ts < ?", (now - self.ttl,))
        self.db.commit()

    def create(self, aid: str, fp: str, agent: str, tool: str, args: dict, now: float | None = None) -> bool:
        """False when the pending cap is reached (nothing is stored)."""
        now = time.time() if now is None else now
        with self._lock:
            self._prune(now)
            n = self.db.execute("SELECT COUNT(*) FROM approvals WHERE state='pending'").fetchone()[0]
            if n >= self.max_pending:
                return False
            self.db.execute("INSERT INTO approvals VALUES(?,?,?,?,?,'pending',?)",
                            (aid, fp, agent, tool, json.dumps(args, sort_keys=True, default=str), now))
            self.db.commit()
            return True

    def get(self, aid: str, now: float | None = None) -> dict | None:
        now = time.time() if now is None else now
        with self._lock:
            self._prune(now)
            row = self.db.execute("SELECT fp, state FROM approvals WHERE id=?", (aid,)).fetchone()
        return {"fp": row[0], "state": row[1]} if row else None

    def resolve(self, aid: str, approve: bool, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            self._prune(now)
            cur = self.db.execute("UPDATE approvals SET state=?, args=NULL, ts=? WHERE id=? AND state='pending'",
                                  ("approved" if approve else "denied", now, aid))
            self.db.commit()
            return cur.rowcount == 1

    def consume(self, aid: str) -> str | None:
        """Atomically take a decided approval (single use). Returns its state, or None if it is gone,
        still pending, or was already consumed."""
        with self._lock:
            row = self.db.execute("SELECT state FROM approvals WHERE id=? AND state!='pending'", (aid,)).fetchone()
            if not row:
                return None
            cur = self.db.execute("DELETE FROM approvals WHERE id=? AND state!='pending'", (aid,))
            self.db.commit()
            return row[0] if cur.rowcount == 1 else None

    def pending(self, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        with self._lock:
            self._prune(now)
            rows = self.db.execute("SELECT id, agent, tool, args FROM approvals WHERE state='pending' ORDER BY ts").fetchall()
        return [{"approval_id": i, "agent": a, "tool": t, "args": json.loads(args or "{}")} for i, a, t, args in rows]
