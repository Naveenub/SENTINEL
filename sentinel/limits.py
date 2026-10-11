"""Durable rate-limit counters and auth lockout, persisted in SQLite so a restart does not reset them.

Wall-clock time on purpose: monotonic clocks do not survive a restart. Rows are pruned on every call, so
the tables stay bounded by (limit x keys) and (max_failures x clients).
"""
import sqlite3
import threading


class LimitStore:
    def __init__(self, path: str = ":memory:"):
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS rate_hits(k TEXT NOT NULL, ts REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS rate_hits_k ON rate_hits(k, ts);
            CREATE TABLE IF NOT EXISTS auth_fails(client TEXT NOT NULL, ts REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS auth_fails_c ON auth_fails(client, ts);
            CREATE TABLE IF NOT EXISTS lockouts(client TEXT PRIMARY KEY, until REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS quarantine(agent TEXT PRIMARY KEY, until REAL NOT NULL, rule TEXT NOT NULL);
            """
        )

    def rate_hit(self, key: str, limit: int, window: float, now: float) -> bool:
        """Record one call unless `limit` calls already happened in the last `window` seconds."""
        with self._lock:
            self.db.execute("DELETE FROM rate_hits WHERE k=? AND ts<=?", (key, now - window))
            n = self.db.execute("SELECT COUNT(*) FROM rate_hits WHERE k=?", (key,)).fetchone()[0]
            if n >= limit:
                self.db.commit()
                return False
            self.db.execute("INSERT INTO rate_hits VALUES(?,?)", (key, now))
            self.db.commit()
            return True

    def locked_until(self, client: str, now: float) -> float:
        """Lockout expiry (wall clock), or 0.0 when the client is not locked out."""
        with self._lock:
            row = self.db.execute("SELECT until FROM lockouts WHERE client=?", (client,)).fetchone()
            if row and row[0] <= now:
                self.db.execute("DELETE FROM lockouts WHERE client=?", (client,))
                self.db.commit()
                return 0.0
        return row[0] if row else 0.0

    def record_failure(self, client: str, max_failures: int, window: float, lockout: float, now: float) -> bool:
        """Count one invalid token. True when this failure started a lockout."""
        with self._lock:
            self.db.execute("DELETE FROM auth_fails WHERE ts<=?", (now - window,))
            self.db.execute("DELETE FROM lockouts WHERE until<=?", (now,))
            self.db.execute("INSERT INTO auth_fails VALUES(?,?)", (client, now))
            n = self.db.execute("SELECT COUNT(*) FROM auth_fails WHERE client=?", (client,)).fetchone()[0]
            locked = n >= max_failures
            if locked:
                self.db.execute("INSERT OR REPLACE INTO lockouts VALUES(?,?)", (client, now + lockout))
                self.db.execute("DELETE FROM auth_fails WHERE client=?", (client,))
            self.db.commit()
            return locked

    # ---- agent quarantine (alert -> block)

    def quarantine(self, agent: str, rule: str, seconds: float, now: float) -> bool:
        """Quarantine an agent. No-op (False) while one is already active, so denials caused by the
        quarantine itself can never extend it."""
        with self._lock:
            self.db.execute("DELETE FROM quarantine WHERE until<=?", (now,))
            cur = self.db.execute("INSERT OR IGNORE INTO quarantine VALUES(?,?,?)", (agent, now + seconds, rule))
            self.db.commit()
            return cur.rowcount == 1

    def quarantined(self, agent: str, now: float) -> str | None:
        """The rule that quarantined this agent, or None."""
        with self._lock:
            row = self.db.execute("SELECT rule, until FROM quarantine WHERE agent=?", (agent,)).fetchone()
        return row[0] if row and row[1] > now else None

    def release(self, agent: str) -> bool:
        with self._lock:
            cur = self.db.execute("DELETE FROM quarantine WHERE agent=?", (agent,))
            self.db.commit()
            return cur.rowcount == 1

    def quarantine_list(self, now: float) -> list[dict]:
        with self._lock:
            rows = self.db.execute("SELECT agent, rule, until FROM quarantine WHERE until>? ORDER BY agent", (now,)).fetchall()
        return [{"agent": a, "rule": r, "until": u} for a, r, u in rows]
