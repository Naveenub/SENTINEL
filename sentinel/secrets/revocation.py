"""Token revocation: a persistent denylist checked on every verify().

Two kinds of entries, both in SQLite so they survive restarts:
  - jti:   one token. Kept until the token could no longer be valid anyway (now + MAX_TTL), then pruned.
  - agent: kill switch. Every token for that agent issued at or before the cutoff is dead; tokens
           issued afterwards are fine. Pruned once every token before the cutoff has expired.
"""
import sqlite3
import threading
import time

MAX_TTL = 300  # keep in sync with broker.MAX_TTL


class RevocationStore:
    def __init__(self, path: str = ":memory:"):
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS revoked_jti(jti TEXT PRIMARY KEY, until REAL NOT NULL, ts REAL NOT NULL, reason TEXT);
            CREATE TABLE IF NOT EXISTS revoked_agent(agent TEXT PRIMARY KEY, cutoff REAL NOT NULL);
            """
        )

    def revoke_jti(self, jti: str, reason: str = "", now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._lock:
            self.db.execute("INSERT OR REPLACE INTO revoked_jti VALUES(?,?,?,?)", (jti, now + MAX_TTL + 1, now, reason))
            self.db.commit()
            self._prune(now)

    def revoke_agent(self, agent: str, now: float | None = None) -> float:
        now = time.time() if now is None else now
        with self._lock:
            self.db.execute("INSERT OR REPLACE INTO revoked_agent VALUES(?,?)", (agent, now))
            self.db.commit()
            self._prune(now)
        return now

    def is_revoked(self, jti: str, agent: str, iat: float) -> bool:
        with self._lock:
            if self.db.execute("SELECT 1 FROM revoked_jti WHERE jti=?", (jti,)).fetchone():
                return True
            row = self.db.execute("SELECT cutoff FROM revoked_agent WHERE agent=?", (agent,)).fetchone()
        return row is not None and iat <= row[0]

    def _prune(self, now: float) -> None:  # caller holds the lock
        self.db.execute("DELETE FROM revoked_jti WHERE until < ?", (now,))
        self.db.execute("DELETE FROM revoked_agent WHERE cutoff < ?", (now - MAX_TTL - 1,))
        self.db.commit()
